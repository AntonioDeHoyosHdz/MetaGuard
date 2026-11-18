"""Authenticated owner-only report and cleaned-file download routes."""

import json
from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from metaguard_api.auth_routes import (
    AuthenticatedOwner,
    AuthRuntime,
    _error,
    authenticate_owner,
)
from metaguard_api.database import Database
from metaguard_api.file_routes import FileRuntime
from metaguard_api.file_storage import InMemoryTemporaryFileStore
from metaguard_api.reports import (
    consume_download_token,
    delete_owner_report,
    digest_download_token,
    get_owner_report,
    issue_download_token,
    list_owner_reports,
    new_download_token,
    report_resource,
)
from metaguard_api.settings import Settings

_SUPPORTED_MEDIA_TYPES = frozenset({"image/jpeg", "image/png", "application/pdf"})


def _report_runtime_ready(runtime: FileRuntime | None) -> bool:
    return (
        isinstance(runtime, FileRuntime)
        and isinstance(runtime.database, Database)
        and isinstance(runtime.store, InMemoryTemporaryFileStore)
        and isinstance(runtime.storage_key, bytes)
        and len(runtime.storage_key) == 32
    )


def _canonical_report_id(value: str) -> str | None:
    try:
        return str(UUID(value))
    except (ValueError, AttributeError):
        return None


def _list_reports(runtime: FileRuntime, owner: AuthenticatedOwner) -> list[dict[str, object]]:
    with runtime.database.transaction() as session:
        rows = list_owner_reports(session, owner.account_id, now=owner.now)
        return [report_resource(row) for row in rows]


def _get_report(
    runtime: FileRuntime, report_id: str, owner: AuthenticatedOwner
) -> dict[str, object] | None:
    with runtime.database.transaction() as session:
        row = get_owner_report(session, report_id, owner.account_id, now=owner.now)
        return report_resource(row) if row is not None else None


def _delete_report(runtime: FileRuntime, report_id: str, owner: AuthenticatedOwner) -> bool:
    with runtime.database.transaction() as session:
        deleted_id = delete_owner_report(session, report_id, owner.account_id, now=owner.now)
    if deleted_id is None:
        return False
    # The database owns report deletion; only remove the separate in-memory copy after commit.
    runtime.store.delete(deleted_id, owner.account_id)
    return True


def create_report_router(
    settings: Settings,
    auth_runtime: AuthRuntime | None,
    file_runtime: FileRuntime | None,
) -> APIRouter:
    router = APIRouter(tags=["reports"])

    @router.get("/v1/reports", summary="List the authenticated owner's active reports")
    async def list_reports(request: Request):
        owner, auth_error = await run_in_threadpool(
            authenticate_owner,
            request,
            settings,
            auth_runtime,
            ip_rate_action="requests_per_minute_per_ip",
            account_rate_action="reports_per_minute_per_account",
        )
        if auth_error is not None:
            return auth_error
        if not _report_runtime_ready(file_runtime) or not isinstance(owner, AuthenticatedOwner):
            return _error(503, "reports_unavailable", "Reports are unavailable")
        try:
            reports = await run_in_threadpool(_list_reports, file_runtime, owner)
        except Exception:
            return _error(503, "reports_unavailable", "Reports are unavailable")
        return JSONResponse({"reports": reports}, headers={"Cache-Control": "no-store"})

    @router.get("/v1/reports/{report_id}", summary="Get one active report owned by the caller")
    async def get_report(report_id: str, request: Request):
        owner, auth_error = await run_in_threadpool(
            authenticate_owner,
            request,
            settings,
            auth_runtime,
            ip_rate_action="requests_per_minute_per_ip",
            account_rate_action="reports_per_minute_per_account",
        )
        if auth_error is not None:
            return auth_error
        if not _report_runtime_ready(file_runtime) or not isinstance(owner, AuthenticatedOwner):
            return _error(503, "reports_unavailable", "Reports are unavailable")
        canonical_id = _canonical_report_id(report_id)
        if canonical_id is None:
            return _error(404, "not_found", "Report not found")
        try:
            report = await run_in_threadpool(_get_report, file_runtime, canonical_id, owner)
        except Exception:
            return _error(503, "reports_unavailable", "Reports are unavailable")
        if report is None:
            return _error(404, "not_found", "Report not found")
        return JSONResponse(report, headers={"Cache-Control": "no-store"})

    @router.delete(
        "/v1/reports/{report_id}",
        status_code=204,
        summary="Delete one active report owned by the caller",
    )
    async def delete_report_route(report_id: str, request: Request):
        owner, auth_error = await run_in_threadpool(
            authenticate_owner,
            request,
            settings,
            auth_runtime,
            ip_rate_action="requests_per_minute_per_ip",
            account_rate_action="report_deletions_per_minute_per_account",
        )
        if auth_error is not None:
            return auth_error
        if not _report_runtime_ready(file_runtime) or not isinstance(owner, AuthenticatedOwner):
            return _error(503, "reports_unavailable", "Reports are unavailable")
        canonical_id = _canonical_report_id(report_id)
        if canonical_id is None:
            return _error(404, "not_found", "Report not found")
        try:
            deleted = await run_in_threadpool(_delete_report, file_runtime, canonical_id, owner)
        except Exception:
            return _error(503, "reports_unavailable", "Reports are unavailable")
        if not deleted:
            return _error(404, "not_found", "Report not found")
        return Response(status_code=204, headers={"Cache-Control": "no-store"})

    @router.post(
        "/v1/reports/{report_id}/download-token",
        summary="Issue a one-use token for the owner's cleaned report file",
    )
    async def create_download_token(report_id: str, request: Request):
        owner, auth_error = await run_in_threadpool(
            authenticate_owner,
            request,
            settings,
            auth_runtime,
            ip_rate_action="requests_per_minute_per_ip",
            account_rate_action="download_tokens_per_hour_per_account",
        )
        if auth_error is not None:
            return auth_error
        if not _report_runtime_ready(file_runtime) or not isinstance(owner, AuthenticatedOwner):
            return _error(503, "reports_unavailable", "Reports are unavailable")
        canonical_id = _canonical_report_id(report_id)
        if canonical_id is None:
            return _error(404, "not_found", "Report not found")
        token, digest = new_download_token()
        try:
            token_expires_at = await run_in_threadpool(
                _issue_download_token,
                file_runtime,
                canonical_id,
                owner,
                digest,
            )
        except Exception:
            return _error(503, "reports_unavailable", "Reports are unavailable")
        if token_expires_at is None:
            return _error(404, "not_found", "Report not found")
        expires_at = datetime.fromtimestamp(token_expires_at, UTC).isoformat()
        return JSONResponse(
            {"token": token, "expires_at": expires_at},
            headers={"Cache-Control": "no-store"},
        )

    @router.get("/v1/downloads/{token}", summary="Download one cleaned file with an active token")
    async def download_file(token: str, request: Request):
        owner, auth_error = await run_in_threadpool(
            authenticate_owner,
            request,
            settings,
            auth_runtime,
            ip_rate_action="downloads_per_minute_per_ip",
            account_rate_action="downloads_per_minute_per_account",
        )
        if auth_error is not None:
            return auth_error
        if not _report_runtime_ready(file_runtime) or not isinstance(owner, AuthenticatedOwner):
            return _error(503, "reports_unavailable", "Reports are unavailable")
        digest = digest_download_token(token)
        if digest is None:
            return _error(404, "not_found", "Download not found")
        try:
            with file_runtime.database.transaction() as session:
                consumed = consume_download_token(session, owner.account_id, digest, now=owner.now)
        except Exception:
            return _error(503, "reports_unavailable", "Reports are unavailable")
        if consumed is None:
            return _error(404, "not_found", "Download not found")

        try:
            report = json.loads(consumed.report_json)
            media_type = report.get("media_type")
            if media_type not in _SUPPORTED_MEDIA_TYPES:
                return _error(503, "reports_unavailable", "Reports are unavailable")
            content = await run_in_threadpool(
                file_runtime.store.get,
                consumed.report_id,
                owner.account_id,
                key=file_runtime.storage_key,
                now=owner.now,
            )
            if not isinstance(content, bytes) or not content:
                return _error(404, "not_found", "Download not found")
            await run_in_threadpool(file_runtime.store.delete, consumed.report_id, owner.account_id)
        except Exception:
            return _error(503, "reports_unavailable", "Reports are unavailable")
        return Response(
            content=content,
            media_type=media_type,
            headers={
                "Cache-Control": "no-store",
                "Content-Disposition": 'attachment; filename="cleaned-file"',
            },
        )

    return router


def _issue_download_token(
    runtime: FileRuntime,
    report_id: str,
    owner: AuthenticatedOwner,
    digest: str,
) -> int | None:
    with runtime.database.transaction() as session:
        return issue_download_token(
            session,
            report_id,
            owner.account_id,
            digest,
            now=owner.now,
        )
