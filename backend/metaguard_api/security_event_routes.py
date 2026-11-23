"""Authenticated account-event history API."""

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from metaguard_api.account_security_events import account_event_resource, list_account_events
from metaguard_api.auth_routes import AuthRuntime, _error, authenticate_owner
from metaguard_api.settings import Settings


def create_security_event_router(settings: Settings, runtime: AuthRuntime | None) -> APIRouter:
    router = APIRouter(tags=["account security"])

    @router.get("/v1/security/events", summary="List the authenticated owner's security events")
    def security_events(request: Request):
        owner, auth_error = authenticate_owner(
            request,
            settings,
            runtime,
            ip_rate_action="requests_per_minute_per_ip",
            account_rate_action="requests_per_minute_per_account",
            audit_rate_limit=False,
        )
        if auth_error is not None:
            return auth_error
        try:
            with runtime.session_factory.begin() as session:
                rows = list_account_events(session, owner.account_id, now=owner.now)
                events = [account_event_resource(row) for row in rows]
        except Exception:
            return _error(503, "security_events_unavailable", "Security history is unavailable")
        return JSONResponse({"events": events}, headers={"Cache-Control": "no-store"})

    return router
