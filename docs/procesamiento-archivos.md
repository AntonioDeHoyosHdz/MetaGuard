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

The proposal's seeded corpus (20 images and 10 active-content PDFs) was not available, so its 100% corpus target is **not** claimed. ExifTool and qpdf are not dependencies in this unit; the output checks use the same pinned Pillow and pikepdf libraries used for cleaning. Runtime isolation, hostile-file resource behavior under the supervisor, and production cleanup remain for T3c/T3d and corpus validation.

## Supervisor runtime configuration

The private `ProcessingSupervisor` now requires a `DockerRuntimeConfig` supplied by trusted host code: absolute Linux executable, local Unix socket path, absolute Docker configuration directory, and SHA-256-pinned image reference. No runtime value comes from an upload. The launch and cleanup processes receive only the configured Docker endpoint and configuration directory, not the inherited environment. This replaces the previous implicit executable and mutable image tag; callers must configure the runtime explicitly.

Path and digest syntax do not verify ownership, executable integrity, socket identity, Docker configuration contents, or image provenance. Those are deployment responsibilities. The supervisor remains unconnected to the API; Linux Docker runtime, isolation, cleanup and Windows compatibility have not been verified.

## Candidate API–supervisor frame codec

`processing_ipc_frame` defines a codec for exactly one version-1 frame: a 12-byte network-order header (`MGIP` magic, version, kind, zero reserved bits, unsigned payload length) and its payload. Request and success payloads must be nonempty and fit the existing worker request and response limits; error payloads are empty. The codec rejects invalid headers, lengths, truncation and trailing frames, and `decode_header` permits length validation before a transport reads a body.

This is **not an IPC service**. It does not perform socket reads, deadlines, peer authentication, ancillary-data handling, concurrency admission, EOF verification or worker JSON-schema validation. A future transport must enforce all of those before the codec can support real uploads; loading the codec currently also imports the worker's parser dependencies. No API endpoint or file-processing connection is enabled by this change.
