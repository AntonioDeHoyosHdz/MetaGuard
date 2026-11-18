"""Minimized, owner-scoped processing report persistence."""

import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    case,
    delete,
    select,
    update,
)
from sqlalchemy.orm import Mapped, Session, mapped_column

from metaguard_api.database import Base, Database

_REPORT_TTL_SECONDS = 24 * 60 * 60
_DOWNLOAD_TOKEN_TTL_SECONDS = 10 * 60
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
_REPORT_FIELDS = frozenset(
    {
        "media_type",
        "metadata_categories",
        "output_verified",
        "width",
        "height",
        "page_count",
        "active_content_removed",
        "uri_links_removed",
    }
)
_TOKEN_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


class FileReport(Base):
    """A small allowlisted report plus digest-only download-token state."""

    __tablename__ = "file_reports"
    __table_args__ = (
        CheckConstraint("length(id) = 36", name="ck_file_reports_id_length"),
        CheckConstraint("created_at >= 0", name="ck_file_reports_created_at"),
        CheckConstraint("expires_at > created_at", name="ck_file_reports_expiry"),
        CheckConstraint(
            "(download_token_digest IS NULL AND download_token_expires_at IS NULL) OR "
            "(length(download_token_digest) = 64 AND download_token_expires_at > 0)",
            name="ck_file_reports_download_token_pair",
        ),
        UniqueConstraint("download_token_digest", name="uq_file_reports_download_token_digest"),
        Index("ix_file_reports_owner_created", "owner_id", "created_at"),
        Index("ix_file_reports_expires_at", "expires_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False
    )
    report_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    download_token_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    download_token_expires_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)


@dataclass(frozen=True, slots=True)
class ConsumedDownload:
    report_id: str
    report_json: str


def _utc_epoch(value: datetime) -> int | None:
    if not isinstance(value, datetime):
        return None
    try:
        if value.utcoffset() != timedelta(0):
            return None
        return int(value.astimezone(UTC).timestamp())
    except (OverflowError, TypeError, ValueError):
        return None


def _safe_report_json(report: dict[str, object]) -> str | None:
    """Serialize only the existing ProcessingReport projection fields."""
    if not isinstance(report, dict) or set(report) != _REPORT_FIELDS:
        return None
    categories = report["metadata_categories"]
    if (
        report["media_type"] not in _SUPPORTED_MEDIA_TYPES
        or not isinstance(categories, list)
        or len(categories) > len(_REPORT_CATEGORIES)
        or any(
            not isinstance(category, str) or category not in _REPORT_CATEGORIES
            for category in categories
        )
        or len(categories) != len(set(categories))
        or report["output_verified"] is not True
        or not isinstance(report["active_content_removed"], bool)
        or type(report["uri_links_removed"]) is not int
        or report["uri_links_removed"] < 0
    ):
        return None
    dimensions = (report["width"], report["height"], report["page_count"])
    if any(value is not None and (type(value) is not int or value < 0) for value in dimensions):
        return None
    if report["media_type"] in {"image/jpeg", "image/png"}:
        if (
            type(report["width"]) is not int
            or report["width"] < 1
            or type(report["height"]) is not int
            or report["height"] < 1
            or report["page_count"] is not None
        ):
            return None
    elif (
        report["width"] is not None
        or report["height"] is not None
        or type(report["page_count"]) is not int
    ):
        return None
    try:
        serialized = json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError):
        return None
    if len(serialized.encode("utf-8")) > 2048:
        return None
    return serialized


def _iso_utc(value: int) -> str:
    return datetime.fromtimestamp(value, UTC).isoformat()


def report_resource(row: FileReport) -> dict[str, object]:
    """Return only a report ID, minimized projection, and retention timestamps."""
    return {
        "report_id": row.id,
        "report": json.loads(row.report_json),
        "created_at": _iso_utc(row.created_at),
        "expires_at": _iso_utc(row.expires_at),
    }


def create_report(
    database: Database,
    *,
    report_id: str,
    owner_id: str,
    report: dict[str, object],
    now: datetime,
) -> dict[str, object] | None:
    """Persist the allowlisted report in a caller-independent DB transaction."""
    current_time = _utc_epoch(now)
    payload = _safe_report_json(report)
    if (
        not isinstance(report_id, str)
        or len(report_id) != 36
        or not isinstance(owner_id, str)
        or not 1 <= len(owner_id) <= 36
        or current_time is None
        or payload is None
    ):
        return None

    row = FileReport(
        id=report_id,
        owner_id=owner_id,
        report_json=payload,
        created_at=current_time,
        expires_at=current_time + _REPORT_TTL_SECONDS,
    )
    with database.transaction() as session:
        session.add(row)
    return report_resource(row)


def list_owner_reports(session: Session, owner_id: str, *, now: datetime) -> list[FileReport]:
    current_time = _utc_epoch(now)
    if current_time is None:
        return []
    return list(
        session.scalars(
            select(FileReport)
            .where(FileReport.owner_id == owner_id, FileReport.expires_at > current_time)
            .order_by(FileReport.created_at.desc(), FileReport.id.desc())
        )
    )


def get_owner_report(
    session: Session, report_id: str, owner_id: str, *, now: datetime
) -> FileReport | None:
    current_time = _utc_epoch(now)
    if current_time is None:
        return None
    return session.scalar(
        select(FileReport).where(
            FileReport.id == report_id,
            FileReport.owner_id == owner_id,
            FileReport.expires_at > current_time,
        )
    )


def issue_download_token(
    session: Session,
    report_id: str,
    owner_id: str,
    token_digest: str,
    *,
    now: datetime,
) -> int | None:
    current_time = _utc_epoch(now)
    if current_time is None or len(token_digest) != 64:
        return None
    return session.execute(
        update(FileReport)
        .where(
            FileReport.id == report_id,
            FileReport.owner_id == owner_id,
            FileReport.expires_at > current_time,
            FileReport.created_at + _DOWNLOAD_TOKEN_TTL_SECONDS > current_time,
        )
        .values(
            download_token_digest=token_digest,
            download_token_expires_at=case(
                (
                    FileReport.created_at + _DOWNLOAD_TOKEN_TTL_SECONDS
                    < current_time + _DOWNLOAD_TOKEN_TTL_SECONDS,
                    FileReport.created_at + _DOWNLOAD_TOKEN_TTL_SECONDS,
                ),
                else_=current_time + _DOWNLOAD_TOKEN_TTL_SECONDS,
            ),
        )
        .returning(FileReport.download_token_expires_at)
        .execution_options(synchronize_session=False)
    ).scalar_one_or_none()


def consume_download_token(
    session: Session, owner_id: str, token_digest: str, *, now: datetime
) -> ConsumedDownload | None:
    """Atomically consume one active token and return its report identity/payload."""
    current_time = _utc_epoch(now)
    if current_time is None or len(token_digest) != 64:
        return None
    row = session.execute(
        update(FileReport)
        .where(
            FileReport.owner_id == owner_id,
            FileReport.download_token_digest == token_digest,
            FileReport.download_token_expires_at > current_time,
            FileReport.expires_at > current_time,
        )
        .values(download_token_digest=None, download_token_expires_at=None)
        .returning(FileReport.id, FileReport.report_json)
        .execution_options(synchronize_session=False)
    ).one_or_none()
    if row is None:
        return None
    return ConsumedDownload(report_id=row.id, report_json=row.report_json)


def delete_owner_report(
    session: Session, report_id: str, owner_id: str, *, now: datetime
) -> str | None:
    current_time = _utc_epoch(now)
    if current_time is None:
        return None
    return session.execute(
        delete(FileReport)
        .where(
            FileReport.id == report_id,
            FileReport.owner_id == owner_id,
            FileReport.expires_at > current_time,
        )
        .returning(FileReport.id)
        .execution_options(synchronize_session=False)
    ).scalar_one_or_none()


def new_download_token() -> tuple[str, str]:
    """Generate an opaque bearer value while retaining only its SHA-256 digest."""
    token = secrets.token_urlsafe(32)
    return token, sha256(token.encode("ascii")).hexdigest()


def digest_download_token(token: str) -> str | None:
    if (
        not isinstance(token, str)
        or len(token) != 43
        or any(character not in _TOKEN_ALPHABET for character in token)
    ):
        return None
    return sha256(token.encode("ascii")).hexdigest()


def purge_expired_reports(session: Session, *, now: int) -> int:
    """Delete reports at their 24-hour retention boundary in the caller transaction."""
    if type(now) is not int or not 0 <= now <= 2**63 - 1:
        raise ValueError("Expected a valid UTC epoch timestamp")
    return session.execute(delete(FileReport).where(FileReport.expires_at <= now)).rowcount
