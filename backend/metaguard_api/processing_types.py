"""Parser-free file-processing result types shared by private components."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ProcessingReport:
    """Privacy-minimized inspection results; metadata values are never returned."""

    media_type: str
    metadata_categories: tuple[str, ...]
    output_verified: bool
    width: int | None = None
    height: int | None = None
    page_count: int | None = None
    active_content_removed: bool = False
    uri_links_removed: int = 0


@dataclass(frozen=True)
class ProcessedFile:
    """Sanitized bytes, a minimized report, and optional transient PDF previews."""

    cleaned_bytes: bytes
    media_type: str
    report: ProcessingReport
    removed_pdf_links: tuple[str, ...] | None = field(default=None, repr=False)
