"""Privacy-limited VirusTotal hash lookups with a fixed HTTPS destination."""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from http.client import HTTPException
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from metaguard_api.database import Database
from metaguard_api.reputation_cache import (
    CacheVerdict,
    get_cached_verdict,
    reserve_virustotal_request,
    save_verdict,
)
from metaguard_api.secrets import SecretName, SecretStore, SecretUnavailable

_FILE_URL = "https://www.virustotal.com/api/v3/files/{}"
_REPORT_URL = "https://www.virustotal.com/gui/file/{}"
_MAX_RESPONSE_BYTES = 64 * 1024
_TIMEOUT_SECONDS = 10
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_STAT_KEYS = frozenset(
    {
        "confirmed-timeout",
        "failure",
        "harmless",
        "malicious",
        "suspicious",
        "timeout",
        "type-unsupported",
        "undetected",
    }
)


class VirusTotalStatus(StrEnum):
    FOUND = "found"
    NOT_FOUND = "not_found"
    NOT_REQUESTED = "not_requested"
    RATE_LIMITED = "rate_limited"
    KEY_UNAVAILABLE = "key_unavailable"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class VirusTotalResult:
    status: VirusTotalStatus
    last_analysis_stats: dict[str, int] | None = None
    last_analysis_date: int | None = None
    report_url: str | None = None

    def as_payload(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "last_analysis_stats": dict(self.last_analysis_stats)
            if self.last_analysis_stats is not None
            else None,
            "last_analysis_date": self.last_analysis_date,
            "report_url": self.report_url,
        }


class VirusTotalLookup(Protocol):
    def lookup(self, digest: str, database: Database | None, *, now: int) -> VirusTotalResult: ...


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _unavailable(status: VirusTotalStatus = VirusTotalStatus.UNAVAILABLE) -> VirusTotalResult:
    return VirusTotalResult(status=status)


def _parse_stats(value: object) -> dict[str, int] | None:
    if not isinstance(value, dict) or not value or not set(value) <= _STAT_KEYS:
        return None
    if any(type(count) is not int or count < 0 for count in value.values()):
        return None
    return dict(value)


def _http_error_status(code: int) -> VirusTotalStatus:
    if code == 404:
        return VirusTotalStatus.NOT_FOUND
    if code in {401, 403}:
        return VirusTotalStatus.KEY_UNAVAILABLE
    if code == 429:
        return VirusTotalStatus.RATE_LIMITED
    return VirusTotalStatus.UNAVAILABLE


def fetch_file_report(sha256: str, api_key: str) -> VirusTotalResult:
    """Fetch and project a report; never follow redirects or use a caller URL."""
    if _SHA256_RE.fullmatch(sha256) is None:
        return _unavailable()
    if not isinstance(api_key, str) or not api_key.strip():
        return _unavailable(VirusTotalStatus.KEY_UNAVAILABLE)

    request = Request(
        _FILE_URL.format(sha256),
        headers={"x-apikey": api_key, "Accept": "application/json"},
        method="GET",
    )
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=_TIMEOUT_SECONDS) as response:
            if response.status != 200:
                return _unavailable(_http_error_status(response.status))
            body = response.read(_MAX_RESPONSE_BYTES + 1)
    except HTTPError as error:
        return _unavailable(_http_error_status(error.code))
    except (HTTPException, OSError, TimeoutError, URLError, ValueError):
        return _unavailable()

    if len(body) > _MAX_RESPONSE_BYTES:
        return _unavailable()
    try:
        payload = json.loads(body)
    except (UnicodeError, ValueError):
        return _unavailable()
    try:
        attributes = payload["data"]["attributes"]
        stats = _parse_stats(attributes.get("last_analysis_stats"))
        analysis_date = attributes.get("last_analysis_date")
    except (KeyError, TypeError):
        return _unavailable()
    if stats is None:
        return _unavailable()
    if analysis_date is not None and (type(analysis_date) is not int or analysis_date < 0):
        return _unavailable()
    return VirusTotalResult(
        status=VirusTotalStatus.FOUND,
        last_analysis_stats=stats,
        last_analysis_date=analysis_date,
        report_url=_REPORT_URL.format(sha256),
    )


def _result_from_cache(
    verdict: CacheVerdict, stats: dict[str, int] | None, date: int | None, digest: str
):
    status = (
        VirusTotalStatus.NOT_FOUND if verdict is CacheVerdict.NO_RECORD else VirusTotalStatus.FOUND
    )
    return VirusTotalResult(
        status=status,
        last_analysis_stats=stats,
        last_analysis_date=date,
        report_url=_REPORT_URL.format(digest) if status is VirusTotalStatus.FOUND else None,
    )


def _cache_verdict(stats: dict[str, int]) -> CacheVerdict:
    if stats.get("malicious", 0) > 0:
        return CacheVerdict.MALICIOUS
    if stats.get("suspicious", 0) > 0:
        return CacheVerdict.SUSPICIOUS
    return CacheVerdict.UNDETECTED


class VirusTotalClient:
    """Hash-only lookup client; quota/cache state is stored in the shared database."""

    def __init__(
        self,
        secret_store: SecretStore,
        *,
        transport=fetch_file_report,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._secret_store = secret_store
        self._transport = transport
        self._clock = clock or (lambda: int(time.time()))

    def lookup(self, digest: str, database: Database | None, *, now: int) -> VirusTotalResult:
        if _SHA256_RE.fullmatch(digest) is None or database is None:
            return _unavailable()
        try:
            with database.transaction() as session:
                cached = get_cached_verdict(session, digest, now=now)
        except Exception:
            return _unavailable()
        if cached is not None:
            return _result_from_cache(
                cached.verdict, cached.last_analysis_stats, cached.last_analysis_date, digest
            )

        try:
            api_key = self._secret_store.read_text(SecretName.VIRUSTOTAL_API_KEY)
        except SecretUnavailable:
            return _unavailable(VirusTotalStatus.KEY_UNAVAILABLE)
        except Exception:
            return _unavailable(VirusTotalStatus.KEY_UNAVAILABLE)

        try:
            with database.transaction() as session:
                if not reserve_virustotal_request(session, now=self._clock()):
                    return _unavailable(VirusTotalStatus.RATE_LIMITED)
        except Exception:
            return _unavailable()

        try:
            result = self._transport(digest, api_key)
        except Exception:
            return _unavailable()
        if not isinstance(result, VirusTotalResult):
            return _unavailable()
        if result.status is VirusTotalStatus.FOUND:
            if result.last_analysis_stats is None:
                return _unavailable()
            verdict = _cache_verdict(result.last_analysis_stats)
        elif result.status is VirusTotalStatus.NOT_FOUND:
            verdict = CacheVerdict.NO_RECORD
        else:
            return result

        try:
            with database.transaction() as session:
                save_verdict(
                    session,
                    digest,
                    verdict,
                    now=now,
                    last_analysis_stats=result.last_analysis_stats,
                    last_analysis_date=result.last_analysis_date,
                )
        except Exception:
            # The current result is still useful; a failed cache write only means a later miss.
            pass
        return result
