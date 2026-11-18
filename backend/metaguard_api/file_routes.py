"""Authenticated upload and processing orchestration routes."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from threading import RLock
from uuid import UUID, uuid4

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, StrictBool, ValidationError
from starlette.concurrency import run_in_threadpool

from metaguard_api.auth_routes import (
    AuthenticatedOwner,
    AuthRuntime,
    _current_time,
    _error,
    authenticate_owner,
)
from metaguard_api.file_storage import InMemoryTemporaryFileStore
from metaguard_api.processing_ipc_client import ProcessingClient
from metaguard_api.processing_limits import MAX_FILE_SIZE
from metaguard_api.processing_types import ProcessedFile, ProcessingReport
from metaguard_api.settings import Settings

_SUPPORTED_MEDIA_TYPES = frozenset({"image/jpeg", "image/png", "application/pdf"})
_REPORT_CATEGORIES = frozenset(
    {
        "author",
        "color_profile",
        "date_time",
        "device_model",
        "document_info",
        "gps",
        "image_metadata",
        "manufacturer_notes",
        "path",
        "serial_number",
        "software",
        "thumbnail",
        "xmp",
    }
)
_TEMPORARY_FILE_TTL = timedelta(minutes=10)
_MAX_ANALYSIS_BODY_BYTES = 1024


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
    _uploads: dict[str, _UploadMetadata] = field(default_factory=dict, repr=False)
    _lock: RLock = field(default_factory=RLock, repr=False)


class AnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    virus_total_consent: StrictBool = False


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


def create_file_router(
    settings: Settings,
    auth_runtime: AuthRuntime | None,
    file_runtime: FileRuntime | None,
) -> APIRouter:
    router = APIRouter(tags=["files"])

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

        return JSONResponse(
            {"upload_id": upload_id, "media_type": media_type},
            status_code=201,
            headers={"Cache-Control": "no-store"},
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
            AnalysisRequest.model_validate_json(body)
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

        try:
            original = await run_in_threadpool(
                file_runtime.store.get,
                canonical_upload_id,
                owner.account_id,
                key=file_runtime.storage_key,
                now=now,
            )
            if not isinstance(original, bytes) or not original:
                return _error(404, "not_found", "Upload not found")
            processed = await run_in_threadpool(
                file_runtime.processing_client.process,
                original,
                metadata.content_type,
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

        # Consent is parsed for the per-file contract; no VirusTotal provider is configured here.
        return JSONResponse({"report": report}, headers={"Cache-Control": "no-store"})

    return router
