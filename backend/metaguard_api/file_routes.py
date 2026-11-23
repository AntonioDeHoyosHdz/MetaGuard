"""Authenticated upload and processing orchestration routes."""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from hashlib import sha256
from threading import BoundedSemaphore, Lock, RLock
from typing import ParamSpec, TypeVar
from uuid import UUID, uuid4

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, StrictBool, ValidationError
from starlette.concurrency import run_in_threadpool

from metaguard_api.account_security_events import AccountSecurityEventKind, account_event_task
from metaguard_api.auth_routes import (
    AuthenticatedOwner,
    AuthRuntime,
    _current_time,
    _error,
    authenticate_owner,
)
from metaguard_api.database import Database
from metaguard_api.file_signature import supported_file_signature
from metaguard_api.file_storage import InMemoryTemporaryFileStore
from metaguard_api.processing_ipc_client import ProcessingClient
from metaguard_api.processing_limits import MAX_FILE_SIZE
from metaguard_api.processing_types import ProcessedFile, ProcessingReport
from metaguard_api.reports import _REPORT_CATEGORIES, create_report
from metaguard_api.settings import Settings
from metaguard_api.virustotal import VirusTotalLookup, VirusTotalResult, VirusTotalStatus

_SUPPORTED_MEDIA_TYPES = frozenset({"image/jpeg", "image/png", "application/pdf"})
_TEMPORARY_FILE_TTL = timedelta(minutes=10)
_MAX_ANALYSIS_BODY_BYTES = 1024
_ANALYSIS_RETRY_AFTER_SECONDS = "1"
_P = ParamSpec("_P")
_T = TypeVar("_T")


@dataclass(frozen=True, slots=True)
class _UploadMetadata:
    owner_id: str
    content_type: str
    expires_at: datetime


@dataclass(slots=True)
class FileRuntime:
    """Injected file dependencies; key material is never included in repr output."""

    store: InMemoryTemporaryFileStore = field(repr=False)
    storage_key: bytes = field(repr=False)
    processing_client: ProcessingClient = field(repr=False)
    database: Database | None = field(default=None, repr=False)
    _uploads: dict[str, _UploadMetadata] = field(default_factory=dict, repr=False)
    _lock: RLock = field(default_factory=RLock, repr=False)


class AnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    virus_total_consent: StrictBool = False


class _AnalysisPermit:
    """Release a reserved slot only after any active synchronous stage exits."""

    def __init__(self, slots: BoundedSemaphore) -> None:
        self._slots = slots
        self._lock = Lock()
        self._running = False
        self._closed = False

    def run(self, stage: Callable[_P, _T], *args: _P.args, **kwargs: _P.kwargs) -> _T:
        with self._lock:
            if self._closed:
                raise RuntimeError("Analysis request already ended")
            self._running = True
        try:
            return stage(*args, **kwargs)
        finally:
            with self._lock:
                self._running = False
                if self._closed:
                    self._slots.release()

    def close(self) -> None:
        with self._lock:
            self._closed = True
            if not self._running:
                self._slots.release()


async def _read_limited_body(
    request: Request, *, maximum_bytes: int
) -> tuple[bytes | None, JSONResponse | None]:
    """Read a request body without multipart decoding or filesystem spooling."""
    declared_length = request.headers.get("content-length")
    if declared_length is not None:
        if not declared_length.isascii() or not declared_length.isdecimal():
            return None, _error(400, "invalid_request", "Invalid request")
        try:
            if int(declared_length) > maximum_bytes:
                return None, _error(413, "file_too_large", "Request body exceeds the size limit")
        except ValueError:
            return None, _error(400, "invalid_request", "Invalid request")

    body = bytearray()
    try:
        async for chunk in request.stream():
            if not isinstance(chunk, bytes):
                return None, _error(400, "invalid_request", "Invalid request")
            if len(body) + len(chunk) > maximum_bytes:
                return None, _error(413, "file_too_large", "Request body exceeds the size limit")
            body.extend(chunk)
    except Exception:
        return None, _error(400, "invalid_request", "Invalid request")

    if not body:
        return None, _error(400, "invalid_request", "Request body must not be empty")
    return bytes(body), None


def _media_type(request: Request) -> str | None:
    raw_value = request.headers.get("content-type", "")
    if "," in raw_value:
        return None
    media_type = raw_value.split(";", 1)[0].strip().lower()
    return media_type if media_type in _SUPPORTED_MEDIA_TYPES else None


def _json_media_type(request: Request) -> bool:
    raw_value = request.headers.get("content-type", "")
    return "," not in raw_value and raw_value.split(";", 1)[0].strip().lower() == "application/json"


def _file_runtime_ready(runtime: FileRuntime | None) -> bool:
    return (
        isinstance(runtime, FileRuntime)
        and isinstance(runtime.store, InMemoryTemporaryFileStore)
        and isinstance(runtime.storage_key, bytes)
        and len(runtime.storage_key) == 32
        and isinstance(runtime.processing_client, ProcessingClient)
        and isinstance(runtime.database, Database)
        and isinstance(runtime._uploads, dict)
        and callable(getattr(runtime._lock, "__enter__", None))
    )


def _prune_metadata(runtime: FileRuntime, *, now: datetime) -> None:
    expired = [
        upload_id for upload_id, metadata in runtime._uploads.items() if now >= metadata.expires_at
    ]
    for upload_id in expired:
        del runtime._uploads[upload_id]


def _owned_upload_metadata(
    runtime: FileRuntime, upload_id: str, owner_id: str, *, now: datetime
) -> _UploadMetadata | None:
    """Return active owner metadata and delete that owner's expired ciphertext."""
    with runtime._lock:
        metadata = runtime._uploads.get(upload_id)
        if metadata is None or metadata.owner_id != owner_id:
            return None
        if now >= metadata.expires_at:
            runtime.store.delete(upload_id, owner_id)
            del runtime._uploads[upload_id]
            return None
        return metadata


def _report_payload(
    report: ProcessingReport, *, expected_media_type: str
) -> dict[str, object] | None:
    categories = report.metadata_categories
    if (
        report.media_type != expected_media_type
        or expected_media_type not in _SUPPORTED_MEDIA_TYPES
        or not isinstance(categories, tuple)
        or len(categories) > len(_REPORT_CATEGORIES)
        or any(
            not isinstance(category, str) or category not in _REPORT_CATEGORIES
            for category in categories
        )
        or len(categories) != len(set(categories))
        or report.output_verified is not True
        or not isinstance(report.active_content_removed, bool)
        or not isinstance(report.uri_links_removed, int)
        or isinstance(report.uri_links_removed, bool)
        or report.uri_links_removed < 0
    ):
        return None

    dimensions = (report.width, report.height, report.page_count)
    if any(
        value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 0)
        for value in dimensions
    ):
        return None
    if expected_media_type in {"image/jpeg", "image/png"}:
        if (
            not isinstance(report.width, int)
            or isinstance(report.width, bool)
            or report.width < 1
            or not isinstance(report.height, int)
            or isinstance(report.height, bool)
            or report.height < 1
            or report.page_count is not None
        ):
            return None
    elif (
        report.width is not None
        or report.height is not None
        or not isinstance(report.page_count, int)
    ):
        return None

    return {
        "media_type": report.media_type,
        "metadata_categories": list(categories),
        "output_verified": report.output_verified,
        "width": report.width,
        "height": report.height,
        "page_count": report.page_count,
        "active_content_removed": report.active_content_removed,
        "uri_links_removed": report.uri_links_removed,
    }


def _virus_total_payload(
    client: VirusTotalLookup | None,
    original: bytes,
    cleaned: bytes,
    database: Database | None,
    *,
    consent: bool,
    now: datetime,
) -> dict[str, dict[str, object]]:
    if not consent:
        not_requested = VirusTotalResult(status=VirusTotalStatus.NOT_REQUESTED).as_payload()
        return {"original": not_requested, "cleaned": not_requested}

    unavailable = VirusTotalResult(status=VirusTotalStatus.UNAVAILABLE).as_payload()
    if client is None:
        return {"original": unavailable, "cleaned": unavailable}

    digests = {"original": sha256(original).hexdigest(), "cleaned": sha256(cleaned).hexdigest()}
    results: dict[str, dict[str, object]] = {}
    by_digest: dict[str, dict[str, object]] = {}
    for label, digest in digests.items():
        if digest not in by_digest:
            try:
                result = client.lookup(digest, database, now=int(now.timestamp()))
                by_digest[digest] = (
                    result.as_payload() if isinstance(result, VirusTotalResult) else unavailable
                )
            except Exception:
                # Optional reputation failure never changes successful file analysis.
                by_digest[digest] = unavailable
        results[label] = by_digest[digest]
    return results


def create_file_router(
    settings: Settings,
    auth_runtime: AuthRuntime | None,
    file_runtime: FileRuntime | None,
    virus_total_client: VirusTotalLookup | None = None,
) -> APIRouter:
    router = APIRouter(tags=["files"])
    analysis_slots = BoundedSemaphore(settings.worker_concurrency)

    @router.post(
        "/v1/uploads",
        status_code=201,
        summary="Store a bounded binary upload for the authenticated owner",
    )
    async def upload(request: Request):
        owner, auth_error = await run_in_threadpool(
            authenticate_owner,
            request,
            settings,
            auth_runtime,
            ip_rate_action="uploads_per_minute_per_ip",
            account_rate_action="uploads_per_hour_per_account",
        )
        if auth_error is not None:
            return auth_error
        if not _file_runtime_ready(file_runtime):
            return _error(503, "files_unavailable", "File processing is unavailable")

        media_type = _media_type(request)
        if media_type is None:
            return _error(415, "unsupported_media_type", "Unsupported media type")
        maximum_bytes = min(settings.upload_max_bytes, MAX_FILE_SIZE)
        content, body_error = await _read_limited_body(request, maximum_bytes=maximum_bytes)
        if body_error is not None:
            return body_error
        if not isinstance(owner, AuthenticatedOwner) or content is None:
            return _error(503, "files_unavailable", "File processing is unavailable")

        now = await run_in_threadpool(_current_time, auth_runtime)
        if now is None:
            return _error(503, "files_unavailable", "File processing is unavailable")
        upload_id = str(uuid4())
        stored = False
        try:
            await run_in_threadpool(file_runtime.store.purge_expired, now=now)
            with file_runtime._lock:
                _prune_metadata(file_runtime, now=now)
            stored = await run_in_threadpool(
                file_runtime.store.put,
                upload_id,
                owner.account_id,
                content,
                key=file_runtime.storage_key,
                now=now,
            )
            if not stored:
                return _error(503, "files_unavailable", "File processing is unavailable")
            metadata = _UploadMetadata(
                owner_id=owner.account_id,
                content_type=media_type,
                expires_at=now + _TEMPORARY_FILE_TTL,
            )
            with file_runtime._lock:
                file_runtime._uploads[upload_id] = metadata
        except Exception:
            if stored:
                try:
                    await run_in_threadpool(file_runtime.store.delete, upload_id, owner.account_id)
                except Exception:
                    pass
            return _error(503, "files_unavailable", "File processing is unavailable")

        detected_media_type = supported_file_signature(content)
        background = (
            account_event_task(
                file_runtime.database.transaction,
                owner.account_id,
                AccountSecurityEventKind.UPLOAD_TYPE_MISMATCH,
                now,
            )
            if detected_media_type is not None and detected_media_type != media_type
            else None
        )
        return JSONResponse(
            {"upload_id": upload_id, "media_type": media_type},
            status_code=201,
            headers={"Cache-Control": "no-store"},
            background=background,
        )

    @router.post(
        "/v1/analyses/{upload_id}",
        summary="Analyze an owned upload through the injected API-side processor",
    )
    async def analyse(upload_id: str, request: Request):
        owner, auth_error = await run_in_threadpool(
            authenticate_owner,
            request,
            settings,
            auth_runtime,
            ip_rate_action="requests_per_minute_per_ip",
            account_rate_action="requests_per_minute_per_account",
        )
        if auth_error is not None:
            return auth_error
        if not _file_runtime_ready(file_runtime):
            return _error(503, "files_unavailable", "File processing is unavailable")
        if not isinstance(owner, AuthenticatedOwner):
            return _error(503, "files_unavailable", "File processing is unavailable")
        if not _json_media_type(request):
            return _error(415, "unsupported_media_type", "JSON request body is required")

        body, body_error = await _read_limited_body(request, maximum_bytes=_MAX_ANALYSIS_BODY_BYTES)
        if body_error is not None:
            return body_error
        try:
            analysis_request = AnalysisRequest.model_validate_json(body)
        except ValidationError:
            return _error(400, "invalid_request", "Invalid request")

        try:
            canonical_upload_id = str(UUID(upload_id))
        except (ValueError, AttributeError):
            return _error(404, "not_found", "Upload not found")

        now = await run_in_threadpool(_current_time, auth_runtime)
        if now is None:
            return _error(503, "files_unavailable", "File processing is unavailable")
        try:
            metadata = await run_in_threadpool(
                _owned_upload_metadata,
                file_runtime,
                canonical_upload_id,
                owner.account_id,
                now=now,
            )
        except Exception:
            return _error(503, "files_unavailable", "File processing is unavailable")
        if metadata is None:
            return _error(404, "not_found", "Upload not found")

        if not analysis_slots.acquire(blocking=False):
            response = _error(503, "processing_busy", "File processing is busy; retry later")
            response.headers["Retry-After"] = _ANALYSIS_RETRY_AFTER_SECONDS
            return response

        permit = _AnalysisPermit(analysis_slots)
        try:
            return await _analyse_owned_upload(
                file_runtime,
                virus_total_client,
                permit,
                upload_id=canonical_upload_id,
                metadata=metadata,
                consent=analysis_request.virus_total_consent,
                now=now,
            )
        finally:
            permit.close()

    return router


async def _analyse_owned_upload(
    runtime: FileRuntime,
    virus_total_client: VirusTotalLookup | None,
    permit: _AnalysisPermit,
    *,
    upload_id: str,
    metadata: _UploadMetadata,
    consent: bool,
    now: datetime,
) -> JSONResponse:
    owner_id = metadata.owner_id
    try:
        original = await run_in_threadpool(
            permit.run, runtime.store.get, upload_id, owner_id, key=runtime.storage_key, now=now
        )
        if not isinstance(original, bytes) or not original:
            return _error(404, "not_found", "Upload not found")
        processed = await run_in_threadpool(
            permit.run, runtime.processing_client.process, original, metadata.content_type
        )
    except Exception:
        return _error(503, "files_unavailable", "File processing is unavailable")

    if (
        not isinstance(processed, ProcessedFile)
        or not isinstance(processed.cleaned_bytes, bytes)
        or not processed.cleaned_bytes
        or not isinstance(processed.report, ProcessingReport)
    ):
        return _error(503, "files_unavailable", "File processing is unavailable")
    report = _report_payload(processed.report, expected_media_type=metadata.content_type)
    if report is None or processed.media_type != metadata.content_type:
        return _error(503, "files_unavailable", "File processing is unavailable")

    background = (
        account_event_task(
            runtime.database.transaction,
            owner_id,
            AccountSecurityEventKind.DANGEROUS_CONTENT_DETECTED,
            now,
        )
        if metadata.content_type == "application/pdf" and report["active_content_removed"] is True
        else None
    )
    report_id = str(uuid4())
    try:
        stored_cleaned = await run_in_threadpool(
            permit.run,
            runtime.store.put,
            report_id,
            owner_id,
            processed.cleaned_bytes,
            key=runtime.storage_key,
            now=now,
        )
        if not stored_cleaned:
            return _error(
                503, "files_unavailable", "File processing is unavailable", background=background
            )
        resource = await run_in_threadpool(
            permit.run,
            create_report,
            runtime.database,
            report_id=report_id,
            owner_id=owner_id,
            report=report,
            now=now,
        )
        if resource is None:
            await run_in_threadpool(permit.run, runtime.store.delete, report_id, owner_id)
            return _error(
                503, "files_unavailable", "File processing is unavailable", background=background
            )
    except Exception:
        try:
            await run_in_threadpool(permit.run, runtime.store.delete, report_id, owner_id)
        except Exception:
            pass
        return _error(
            503, "files_unavailable", "File processing is unavailable", background=background
        )

    virus_total = await run_in_threadpool(
        permit.run,
        _virus_total_payload,
        virus_total_client,
        original,
        processed.cleaned_bytes,
        runtime.database,
        consent=consent,
        now=now,
    )
    return JSONResponse(
        {**resource, "virus_total": virus_total},
        headers={"Cache-Control": "no-store"},
        background=background,
    )
