# In-memory file processing

`backend/metaguard_api/file_processing.py` exposes a small HTTP-independent processor for JPEG, PNG, and PDF bytes. It checks the declared MIME type against the file signature, applies fixed demo limits, returns a sanitized copy, and reparses that copy before marking it verified. Unsupported or unverifiable inputs raise `FileProcessingError`; there is no partial-output result.

## Quick path

```python
from metaguard_api.file_processing import process_file

result = process_file(upload_bytes, "image/jpeg")
clean_bytes = result.cleaned_bytes
report = result.report
```

Pass bytes and one of `image/jpeg`, `image/png`, or `application/pdf`. Do not call this parser from the HTTP API; worker isolation and API-to-worker transfer are separate work.

## Processing behavior

| Input | Sanitization | Verification |
|---|---|---|
| JPEG | Apply EXIF orientation, convert to RGB, and re-encode with fixed JPEG options; no EXIF, XMP, IPTC, thumbnails, or embedded profile is forwarded. | Reopen, decode, check format/frame count, and require no EXIF or known metadata blocks. JPEG pixels are lossy. |
| PNG | Re-encode without input metadata, text, or embedded ICC profile. Preserve supported PNG pixel modes and sample depth, including 16-bit grayscale; convert RGB `tRNS` color-key transparency to alpha before clearing metadata. | Verify the input structure and warnings, then reopen and decode the sanitized output; require no EXIF or known metadata blocks while preserving transparent and visible pixels. |
| PDF | Clear document Info, XMP, trailer ID, page thumbnails, annotations, embedded files, forms, external-file references, and known active actions, including `/GoToE` in compressed/indirect objects. URI actions are counted without returning their values or making requests. | Reopen without parser recovery, check page count and warnings after traversal, decode every page-content stream within a 25 MiB aggregate bound, and scan output for metadata, file references, active-action keys, and URI actions. Accept classic xref tables and xref/object streams. |

The report contains minimized metadata categories, dimensions or page count, removed URI-action count, and verification status; it never returns metadata values. A successful verification means only that these processor checks passed. It is not an independent ExifTool/qpdf verification and does not prove visual content is anonymous.

## Fixed input limits

- 25 MiB maximum input and sanitized output.
- Images: 8,000 pixels maximum on either side and 40 megapixels total; animated/multi-frame images are rejected.
- PDFs: 1–100 pages; encrypted, malformed, warned, or structurally over-complex PDFs fail closed.

The current limit values are demo settings from `docs/limites.md`, not production capacity claims. The caller must still enforce isolation, CPU/memory/wall-time limits, request quotas, and scratch cleanup.

Page-content verification accepts unfiltered streams and `FlateDecode` streams without non-empty decode parameters. Unsupported filters/parameters and malformed or over-limit streams fail closed rather than being silently accepted.

## Verification and remaining gap

`backend/tests/test_file_processing.py` builds synthetic JPEG, PNG, and PDF inputs in memory. It checks ICC removal, RGB `tRNS` transparency preservation, 16-bit PNG sample preservation, nested EXIF reporting, malformed-image rejection, PDF thumbnail/action/file-reference removal, bounded page-content decoding, lazy parser-warning rejection, trailer-ID removal in classic and xref-stream PDFs, compressed JavaScript sanitization, deterministic output, MIME/signature validation, size/dimension/page limits, encryption rejection, output reparsing, and the absence of plaintext-file writes by the processor.

The proposal's seeded corpus (20 files for metadata removal and 10 active-content PDFs) has not been verified, so its 100% corpus target is **not** claimed. ExifTool and qpdf are not dependencies of the processor; the internal output checks use the same pinned Pillow and pikepdf libraries as cleaning. Independent verification of the target corpus, resource behavior on extreme inputs, and production cleanup remain open.

## Supervisor runtime configuration

The private `ProcessingSupervisor` now requires a `DockerRuntimeConfig` supplied by trusted host code: absolute Linux executable, local Unix socket path, absolute Docker configuration directory, and SHA-256-pinned image reference. No runtime value comes from an upload. The launch and cleanup processes receive only the configured Docker endpoint and configuration directory, not the inherited environment. This replaces the previous implicit executable and mutable image tag; callers must configure the runtime explicitly.

Path and digest syntax do not verify ownership, executable integrity, Docker socket identity, Docker configuration contents, or image provenance. Those are deployment responsibilities. The Linux runtime uses a separately configured private socket, not native Windows. The [recorded WSL2 exercise](validacion-staging.md#estado-observado) used a local, unpublished image pinned by digest to clean synthetic JPG, PNG and PDF inputs in Docker with network disabled, a read-only root and a non-root user. This does not establish staging operation or recovery after uncertain container cleanup.

## API–supervisor frame codec

`processing_ipc_frame` defines a codec for exactly one version-1 frame: a 12-byte network-order header (`MGIP` magic, version, kind, zero reserved bits, unsigned payload length) and its payload. Request and success payloads must be nonempty and fit the existing worker request and response limits; error payloads are empty. The codec rejects invalid headers, lengths, truncation and trailing frames, and `decode_header` permits length validation before a transport reads a body.

`processing_ipc_transport` adds Linux-only transfer over a caller-provided Unix stream: it checks the expected peer UID, applies an absolute operation deadline, rejects ancillary data and truncated control messages, closes received file descriptors, bounds frame reads, and requires EOF after the frame. The sender half-closes after one frame. Callers own socket closure on all outcomes. Shared protocol limits now live in a parser-free module, so importing the codec or transport does not load Pillow or pikepdf.

`ProcessingRequestHandler` connects a caller-provided stream to the supervisor after transport authentication and the worker's strict request-schema validation. It returns a validated result or a generic empty error and closes the connection. One shared handler admits one job at a time and disables itself if container cleanup is uncertain.

`ProcessingClient` prepares a bounded request for a trusted, configured Linux Unix socket, checks the expected server UID through the private transport, and validates the returned schema with the same parser-free validator used by the supervisor. The client does not import Pillow or pikepdf. A fragmented client-to-handler exchange has been tested on simulated streams; file routes require an injected file runtime.

## Run the private listener on Linux

The listener serves one connection at a time, requests a fixed kernel backlog of 1, and checks the configured API UID before reading a request. It does not listen on TCP, build or pull images, or give the API Docker access. It is intended for a dedicated foreground process on Linux, not for native Windows.

1. Provision separate, non-root accounts for the worker and API. Use a dedicated IPC group with the API as a member. Only the worker should have access to the approved local Docker runtime. Provision an empty directory such as `/run/metaguard-ipc` owned by the worker and the IPC group with mode `2750`; use no permissive ACLs. Its ancestors must be real directories owned by root or the worker and not writable by group or others. Use the actual path rather than a symlink such as `/var/run`.
2. Make the already-prepared digest-pinned image available in that Docker runtime. From the prepared backend environment, run the CLI **as the worker user**, substituting the API UID, IPC group ID, approved Docker paths and actual digest:

   ```bash
   python -m metaguard_api.processing_service \
     --socket /run/metaguard-ipc/processor.sock \
     --api-uid 2000 --api-gid 3000 \
     --docker-executable /usr/bin/docker \
     --docker-socket /run/docker.sock \
     --docker-config-dir /etc/metaguard/docker \
     --worker-image "metaguard-processor@sha256:${WORKER_IMAGE_DIGEST:?set the approved 64-character digest}"
   ```

3. Configure the API-side `ProcessingClientConfig` with the **same socket path**, the worker's effective UID as `server_uid`, and a timeout long enough for supervised processing and cleanup (up to 120 seconds). Run the API and worker in a namespace configuration where the peer UID checks see the intended identities. UID checks authenticate processes, not end users.

The newly bound socket is accessible only to its owner and configured group (mode `0660`). The listener refuses all pre-existing entries and removes only its own socket entry on orderly shutdown. SIGTERM and SIGINT stop accepting work and wait for the active handler, including its cleanup attempt. Avoid signaling the entire process group for an orderly stop, since that may also interrupt Docker. If the handler is disabled because cleanup or processing cannot be confirmed, the service stops with a nonzero status; do not automatically restart it. An operator must reconcile any orphan worker containers and verify any stale socket before relaunching. The process-local latch is not durable orphan tracking.

The listener tests simulate the Unix socket and filesystem. The [local browser exercise](validacion-staging.md#ensayo-local-con-la-interfaz-actual) used a WSL adapter rather than this listener. Validate the native path with distinct Linux UIDs, effective socket permissions and kernel peer credentials, descriptor handling, and end-to-end staging isolation before using real files.
