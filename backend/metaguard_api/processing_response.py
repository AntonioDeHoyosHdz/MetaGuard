"""Parser-free validation of processor responses shared by private clients."""

import base64
import binascii
import json

from metaguard_api.processing_errors import ProcessingSupervisorError
from metaguard_api.processing_limits import (
    MAX_FILE_SIZE,
    MAX_IMAGE_PIXELS,
    MAX_IMAGE_SIDE,
    MAX_PDF_PAGES,
    MAX_RESPONSE_BYTES,
)
from metaguard_api.processing_types import ProcessedFile, ProcessingReport

_ALLOWED_METADATA_CATEGORIES = frozenset(
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
_REPORT_KEYS = frozenset(
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


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ProcessingSupervisorError("Processor returned an invalid response")
        result[key] = value
    return result


def _decode_response(raw_response: bytes, expected_media_type: str) -> ProcessedFile:
    if not isinstance(raw_response, bytes) or len(raw_response) > MAX_RESPONSE_BYTES:
        raise ProcessingSupervisorError("Processor returned an invalid response")
    try:
        response = json.loads(
            raw_response.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ProcessingSupervisorError("Processor returned an invalid response") from exc
    if not isinstance(response, dict) or frozenset(response) != {
        "cleaned_bytes_base64",
        "media_type",
        "report",
    }:
        raise ProcessingSupervisorError("Processor returned an invalid response")

    encoded_data = response["cleaned_bytes_base64"]
    media_type = response["media_type"]
    raw_report = response["report"]
    if (
        not isinstance(encoded_data, str)
        or not isinstance(media_type, str)
        or media_type != expected_media_type
        or not isinstance(raw_report, dict)
        or frozenset(raw_report) != _REPORT_KEYS
    ):
        raise ProcessingSupervisorError("Processor returned an invalid response")
    try:
        cleaned_bytes = base64.b64decode(encoded_data.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ProcessingSupervisorError("Processor returned invalid file bytes") from exc
    if not cleaned_bytes or len(cleaned_bytes) > MAX_FILE_SIZE:
        raise ProcessingSupervisorError("Processor output exceeds the file size limit")

    report_type = raw_report["media_type"]
    categories = raw_report["metadata_categories"]
    verified = raw_report["output_verified"]
    active_content = raw_report["active_content_removed"]
    uri_count = raw_report["uri_links_removed"]
    dimensions = (raw_report["width"], raw_report["height"], raw_report["page_count"])
    if (
        report_type != media_type
        or not isinstance(categories, list)
        or len(categories) > len(_ALLOWED_METADATA_CATEGORIES)
        or any(
            not isinstance(category, str) or category not in _ALLOWED_METADATA_CATEGORIES
            for category in categories
        )
        or len(categories) != len(set(categories))
        or verified is not True
        or not isinstance(active_content, bool)
        or not isinstance(uri_count, int)
        or isinstance(uri_count, bool)
        or uri_count < 0
        or any(
            value is not None
            and (not isinstance(value, int) or isinstance(value, bool) or value < 0)
            for value in dimensions
        )
    ):
        raise ProcessingSupervisorError("Processor returned an invalid report")

    width, height, page_count = dimensions
    if media_type in {"image/jpeg", "image/png"}:
        if (
            not _is_integer(width)
            or not _is_integer(height)
            or width < 1
            or height < 1
            or width > MAX_IMAGE_SIDE
            or height > MAX_IMAGE_SIDE
            or width * height > MAX_IMAGE_PIXELS
            or page_count is not None
        ):
            raise ProcessingSupervisorError("Processor returned invalid image dimensions")
    elif (
        width is not None
        or height is not None
        or not _is_integer(page_count)
        or page_count < 1
        or page_count > MAX_PDF_PAGES
    ):
        raise ProcessingSupervisorError("Processor returned invalid PDF dimensions")

    report = ProcessingReport(
        media_type=media_type,
        metadata_categories=tuple(categories),
        output_verified=True,
        width=raw_report["width"],
        height=raw_report["height"],
        page_count=raw_report["page_count"],
        active_content_removed=active_content,
        uri_links_removed=uri_count,
    )
    return ProcessedFile(cleaned_bytes=cleaned_bytes, media_type=media_type, report=report)


def _is_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)
