"""Bounded, in-memory sanitization for JPEG, PNG, and PDF files."""

from __future__ import annotations

import re
import warnings
import zlib
from io import BytesIO
from itertools import chain

import pikepdf
from PIL import ExifTags, Image, ImageOps, UnidentifiedImageError

from metaguard_api.processing_limits import (
    MAX_FILE_SIZE,
    MAX_IMAGE_PIXELS,
    MAX_IMAGE_SIDE,
    MAX_PDF_PAGES,
)
from metaguard_api.processing_types import ProcessedFile, ProcessingReport

MAX_PDF_CONTENT_BYTES = 25 * 1024 * 1024

_MIME_FORMATS = {
    "image/jpeg": "JPEG",
    "image/png": "PNG",
    "application/pdf": "PDF",
}
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_PDF_SIGNATURE = b"%PDF-"
_EXIF_TAGS = ExifTags.TAGS
_DANGEROUS_PDF_KEYS = frozenset(
    {
        "/AA",
        "/AcroForm",
        "/AF",
        "/Annots",
        "/EmbeddedFile",
        "/EmbeddedFiles",
        "/EF",
        "/Filespec",
        "/GoToE",
        "/GoToR",
        "/ImportData",
        "/JavaScript",
        "/JS",
        "/Launch",
        "/OpenAction",
        "/RichMedia",
        "/SubmitForm",
        "/Thumb",
        "/Metadata",
        "/XFA",
    }
)
_DANGEROUS_PDF_ACTIONS = frozenset(
    {
        "/GoToE",
        "/GoToR",
        "/ImportData",
        "/JavaScript",
        "/Launch",
        "/RichMedia",
        "/SubmitForm",
    }
)
_TRAILER_ID_RE = re.compile(rb"/ID\s*\[\s*<[^>]*>\s*<[^>]*>\s*\]")
_PRIVATE_PDF_METADATA_KEYS = frozenset({"/PieceInfo"})
_SENSITIVE_PDF_INFO_KEYS = frozenset(
    {
        "/Author",
        "/CreationDate",
        "/ModDate",
        "/Owner",
        "/Subject",
        "/Title",
        "/Trapped",
    }
)
_IMAGE_METADATA_KEYS = frozenset(
    {"exif", "icc_profile", "xmp", "iptc", "photoshop", "comment", "xml"}
)
_PRESERVED_PNG_MODES = frozenset(
    {"1", "L", "LA", "P", "RGB", "RGBA", "I", "I;16", "I;16B", "I;16L"}
)


class FileProcessingError(ValueError):
    """Raised when an input cannot be safely inspected or verified."""


def process_file(data: bytes, content_type: str) -> ProcessedFile:
    """Inspect, sanitize, and verify a supported file using bounded in-memory I/O.

    ``content_type`` is an allowlisted MIME type and must agree with the actual
    signature. Unsupported, malformed, oversized, encrypted, or unverifiable
    inputs raise :class:`FileProcessingError` without returning partial output.
    """
    if not isinstance(data, bytes) or not data:
        raise FileProcessingError("Input must be non-empty bytes")
    if len(data) > MAX_FILE_SIZE:
        raise FileProcessingError("Input exceeds the 25 MiB size limit")
    if not isinstance(content_type, str) or content_type not in _MIME_FORMATS:
        raise FileProcessingError("Unsupported media type")

    expected_format = _MIME_FORMATS[content_type]
    if expected_format == "PDF":
        if not data.startswith(_PDF_SIGNATURE):
            raise FileProcessingError("Input signature does not match media type")
        return _process_pdf(data)

    expected_signature = b"\xff\xd8\xff" if expected_format == "JPEG" else _PNG_SIGNATURE
    if not data.startswith(expected_signature):
        raise FileProcessingError("Input signature does not match media type")
    return _process_image(data, content_type, expected_format)


def _process_image(data: bytes, media_type: str, expected_format: str) -> ProcessedFile:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            with Image.open(BytesIO(data)) as check_image:
                if check_image.format != expected_format:
                    raise FileProcessingError("Input signature does not match media type")
                if getattr(check_image, "n_frames", 1) != 1:
                    raise FileProcessingError("Animated images are not supported")
                _check_image_dimensions(*check_image.size)
                check_image.verify()

            with Image.open(BytesIO(data)) as image:
                categories = _image_metadata_categories(image)
                image.load()
                oriented = ImageOps.exif_transpose(image)
                _check_image_dimensions(*oriented.size)
                if media_type == "image/jpeg":
                    clean_image = oriented.convert("RGB")
                elif oriented.mode == "P" and "transparency" in oriented.info:
                    clean_image = oriented.convert("RGBA")
                elif oriented.mode == "RGB" and "transparency" in oriented.info:
                    clean_image = oriented.convert("RGBA")
                elif oriented.mode in _PRESERVED_PNG_MODES:
                    clean_image = oriented.copy()
                else:
                    clean_image = oriented.convert("RGBA")

        # Pillow's encoders may reuse info from the source image unless cleared.
        clean_image.info.clear()

        output = BytesIO()
        if media_type == "image/jpeg":
            clean_image.save(
                output,
                format="JPEG",
                quality=95,
                subsampling=0,
                optimize=False,
                progressive=False,
            )
        else:
            clean_image.save(output, format="PNG", optimize=False, compress_level=9)
        cleaned = output.getvalue()
        if len(cleaned) > MAX_FILE_SIZE:
            raise FileProcessingError("Sanitized image exceeds the 25 MiB size limit")
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            _verify_image(cleaned, expected_format)
    except FileProcessingError:
        raise
    except (
        Image.DecompressionBombError,
        OSError,
        ValueError,
        SyntaxError,
        Warning,
        UnidentifiedImageError,
    ) as exc:
        raise FileProcessingError("Image is malformed or cannot be verified") from exc

    return ProcessedFile(
        cleaned_bytes=cleaned,
        media_type=media_type,
        report=ProcessingReport(
            media_type=media_type,
            metadata_categories=tuple(sorted(categories)),
            output_verified=True,
            width=clean_image.width,
            height=clean_image.height,
        ),
    )


def _check_image_dimensions(width: int, height: int) -> None:
    if (
        width < 1
        or height < 1
        or width > MAX_IMAGE_SIDE
        or height > MAX_IMAGE_SIDE
        or width * height > MAX_IMAGE_PIXELS
    ):
        raise FileProcessingError("Image dimensions exceed the configured limits")


def _image_metadata_categories(image: Image.Image) -> set[str]:
    categories: set[str] = set()
    exif = image.getexif()

    def record_tags(tags: object, ifd_id: int | None = None) -> None:
        for tag_id in tags:
            name = _EXIF_TAGS.get(tag_id, str(tag_id)).casefold()
            category = _metadata_category(name)
            if category:
                categories.add(category)
            if tag_id == 34853 or ifd_id == ExifTags.IFD.GPSInfo:
                categories.add("gps")
            if tag_id in {513, 514} or ifd_id == ExifTags.IFD.IFD1:
                categories.add("thumbnail")
            if tag_id == 37500 or ifd_id == ExifTags.IFD.MakerNote:
                categories.add("manufacturer_notes")
            if tag_id == 700:
                categories.add("xmp")

    record_tags(exif)
    for ifd_id in (
        ExifTags.IFD.Exif,
        ExifTags.IFD.GPSInfo,
        ExifTags.IFD.MakerNote,
        ExifTags.IFD.Interop,
        ExifTags.IFD.IFD1,
    ):
        try:
            tags = exif.get_ifd(ifd_id)
        except (KeyError, TypeError, ValueError):
            continue
        record_tags(tags, ifd_id)

    for key in image.info:
        normalized = str(key).casefold()
        if normalized in _IMAGE_METADATA_KEYS:
            categories.add("image_metadata")
        category = _metadata_category(normalized)
        if category:
            categories.add(category)
    if "icc_profile" in image.info:
        categories.add("color_profile")
    return categories


def _metadata_category(name: str) -> str | None:
    if "gps" in name or "latitude" in name or "longitude" in name:
        return "gps"
    if "serial" in name:
        return "serial_number"
    if "author" in name or "artist" in name or "owner" in name:
        return "author"
    if "date" in name or "time" in name:
        return "date_time"
    if "path" in name or "directory" in name or "filename" in name:
        return "path"
    if "thumbnail" in name:
        return "thumbnail"
    if "model" in name:
        return "device_model"
    if "software" in name or "creator" in name:
        return "software"
    if "maker" in name or "note" in name:
        return "manufacturer_notes"
    return None


def _verify_image(data: bytes, expected_format: str) -> None:
    with Image.open(BytesIO(data)) as image:
        if image.format != expected_format or getattr(image, "n_frames", 1) != 1:
            raise FileProcessingError("Sanitized image format verification failed")
        image.load()
        if image.getexif():
            raise FileProcessingError("Sanitized image still contains EXIF metadata")
        if any(str(key).casefold() in _IMAGE_METADATA_KEYS for key in image.info):
            raise FileProcessingError("Sanitized image still contains metadata")


def _process_pdf(data: bytes) -> ProcessedFile:
    try:
        with pikepdf.open(BytesIO(data), attempt_recovery=False) as pdf:
            if pdf.is_encrypted:
                raise FileProcessingError("Encrypted PDFs are not supported")
            page_count = len(pdf.pages)
            if page_count < 1 or page_count > MAX_PDF_PAGES:
                raise FileProcessingError("PDF exceeds the 100 page limit")
            if pdf.get_warnings():
                raise FileProcessingError("PDF parser reported a structural warning")

            private_objects = _collect_private_metadata_objects(pdf)
            categories, active_content, uri_count = _scan_pdf(pdf, sanitize=True)
            if pdf.get_warnings():
                raise FileProcessingError("PDF parser reported a structural warning")
            _verify_page_content_streams(pdf)
            if pdf.get_warnings():
                raise FileProcessingError("PDF parser reported a structural warning")
            for key in list(pdf.docinfo.keys()):
                del pdf.docinfo[key]
            if "/Metadata" in pdf.Root:
                del pdf.Root["/Metadata"]
            if "/ID" in pdf.trailer:
                del pdf.trailer["/ID"]
            _reject_retained_private_objects(pdf, private_objects)
            output = BytesIO()
            pdf.save(output, deterministic_id=True, fix_metadata_version=False)
        cleaned = output.getvalue()
        if len(cleaned) > MAX_FILE_SIZE:
            raise FileProcessingError("Sanitized PDF exceeds the 25 MiB size limit")
        cleaned = _remove_serialized_trailer_id(cleaned)
        _verify_pdf(cleaned, page_count)
    except FileProcessingError:
        raise
    except pikepdf.PasswordError as exc:
        raise FileProcessingError("Encrypted PDFs are not supported") from exc
    except (pikepdf.PdfError, OSError, ValueError, RuntimeError) as exc:
        raise FileProcessingError("PDF is malformed or cannot be verified") from exc

    return ProcessedFile(
        cleaned_bytes=cleaned,
        media_type="application/pdf",
        report=ProcessingReport(
            media_type="application/pdf",
            metadata_categories=tuple(sorted(categories)),
            output_verified=True,
            page_count=page_count,
            active_content_removed=active_content,
            uri_links_removed=uri_count,
        ),
    )


def _walk_pdf_graph(roots):
    """Walk bounded object graphs without decoding stream payloads."""
    visited: set[tuple[int, int]] = set()
    nodes = 0

    def visit(obj, depth):
        nonlocal nodes
        nodes += 1
        if depth > 128 or nodes > 100_000:
            raise FileProcessingError("PDF object graph exceeds safe inspection limits")
        if isinstance(obj, pikepdf.Object):
            identity = tuple(obj.objgen)
            if identity != (0, 0):
                if identity in visited:
                    return
                visited.add(identity)
        yield obj
        if isinstance(obj, (pikepdf.Dictionary, pikepdf.Stream)):
            for key in obj.keys():
                yield from visit(obj.get(key), depth + 1)
        elif isinstance(obj, pikepdf.Array):
            for value in obj:
                yield from visit(value, depth + 1)

    for root in roots:
        yield from visit(root, 0)


def _collect_private_metadata_objects(pdf: pikepdf.Pdf) -> set[tuple[int, int]]:
    """Remember indirect objects reachable from private metadata before removal."""
    roots = []
    for obj in _walk_pdf_graph(chain(pdf.objects, (pdf.Root, pdf.trailer))):
        if isinstance(obj, (pikepdf.Dictionary, pikepdf.Stream)):
            for key in obj.keys():
                if str(key) in _PRIVATE_PDF_METADATA_KEYS:
                    roots.append(obj.get(key))
    return {
        tuple(obj.objgen)
        for obj in _walk_pdf_graph(roots)
        if isinstance(obj, pikepdf.Object) and tuple(obj.objgen) != (0, 0)
    }


def _reject_retained_private_objects(
    pdf: pikepdf.Pdf, private_objects: set[tuple[int, int]]
) -> None:
    """Reject indirect private objects still reachable after metadata removal."""
    if not private_objects:
        return
    for obj in _walk_pdf_graph((pdf.trailer,)):
        if isinstance(obj, pikepdf.Object) and tuple(obj.objgen) in private_objects:
            raise FileProcessingError("PDF contains shared private metadata")


def _scan_pdf(pdf: pikepdf.Pdf, *, sanitize: bool) -> tuple[set[str], bool, int]:
    categories: set[str] = set()
    active_content = False
    uri_count = 0
    visited: set[tuple[str, int, int] | tuple[str, int]] = set()
    nodes_visited = 0

    for key in list(pdf.docinfo.keys()):
        category = _metadata_category(str(key).lstrip("/").casefold())
        if category:
            categories.add(category)
        elif str(key) in _SENSITIVE_PDF_INFO_KEYS:
            categories.add("document_info")

    if "/Metadata" in pdf.Root:
        categories.add("xmp")

    def visit(obj: object, depth: int = 0) -> None:
        nonlocal active_content, nodes_visited, uri_count
        nodes_visited += 1
        if depth > 128 or nodes_visited > 100_000:
            raise FileProcessingError("PDF object graph exceeds safe inspection limits")
        if isinstance(obj, (pikepdf.Dictionary, pikepdf.Stream, pikepdf.Array)):
            objgen = getattr(obj, "objgen", (0, 0))
            if objgen != (0, 0):
                identity = (
                    "indirect",
                    int(objgen[0]),
                    int(objgen[1]),
                )
                if identity in visited:
                    return
                visited.add(identity)

        if isinstance(obj, (pikepdf.Dictionary, pikepdf.Stream)):
            try:
                object_type = str(obj.get("/Type", ""))
                action_type = str(obj.get("/S", ""))
                is_uri_action = action_type == "/URI"
                if object_type in {"/Filespec", "/EmbeddedFile"}:
                    active_content = True
                    if sanitize and object_type == "/Filespec":
                        for file_key in ("/Type", "/EF", "/F", "/UF", "/Desc"):
                            if file_key in obj:
                                del obj[file_key]
                if action_type in _DANGEROUS_PDF_ACTIONS:
                    active_content = True
            except (AttributeError, ValueError):
                action_type = ""
                is_uri_action = False
            if is_uri_action:
                uri_count += 1
            keys = list(obj.keys())
            for key in keys:
                normalized_key = str(key)
                if normalized_key in _PRIVATE_PDF_METADATA_KEYS:
                    categories.add("document_info")
                    if sanitize:
                        del obj[key]
                    continue
                category = _metadata_category(normalized_key.lstrip("/").casefold())
                if category:
                    categories.add(category)
                    if sanitize and category in {
                        "author",
                        "date_time",
                        "device_model",
                        "gps",
                        "manufacturer_notes",
                        "path",
                        "serial_number",
                        "software",
                        "thumbnail",
                    }:
                        del obj[key]
                        continue
                elif normalized_key in _SENSITIVE_PDF_INFO_KEYS:
                    categories.add("document_info")
                    if sanitize:
                        del obj[key]
                        continue
                if normalized_key == "/Metadata":
                    categories.add("xmp")
                if normalized_key in {"/Annots", "/AcroForm"}:
                    active_content = True
                value = obj.get(key)
                is_external_file_reference = normalized_key == "/F" and isinstance(
                    value, (pikepdf.String, pikepdf.Dictionary, pikepdf.Stream)
                )
                if is_external_file_reference:
                    active_content = True
                    if sanitize:
                        del obj[key]
                    continue
                is_dangerous_action = isinstance(
                    value, (pikepdf.Dictionary, pikepdf.Stream)
                ) and str(value.get("/S", "")) in _DANGEROUS_PDF_ACTIONS | {"/URI"}
                if normalized_key in _DANGEROUS_PDF_KEYS and normalized_key != "/Metadata":
                    active_content = True
                    if isinstance(value, (pikepdf.Dictionary, pikepdf.Stream, pikepdf.Array)):
                        visit(value, depth + 1)
                    if sanitize:
                        del obj[key]
                    continue
                if is_dangerous_action:
                    active_content = True
                    visit(value, depth + 1)
                    if sanitize:
                        del obj[key]
                    continue
                if normalized_key == "/Metadata" and sanitize:
                    del obj[key]
                    continue
                if isinstance(value, (pikepdf.Dictionary, pikepdf.Stream, pikepdf.Array)):
                    visit(value, depth + 1)
                if is_uri_action and sanitize and normalized_key in {"/S", "/URI"}:
                    # The URI action itself is discarded by its parent below;
                    # these entries are not exposed in the report.
                    continue

        elif isinstance(obj, pikepdf.Array):
            for value in obj:
                visit(value, depth + 1)

    # Include every parsed indirect object, including compressed object streams,
    # rather than relying only on the reachable page/catalog tree.
    for obj in pdf.objects:
        visit(obj)
    visit(pdf.Root)
    visit(pdf.trailer)

    # Remove URI action dictionaries wherever they occur, after the traversal has
    # counted them. Re-walk parents to avoid leaking or consulting URI values.
    if sanitize and uri_count:
        for obj in pdf.objects:
            _remove_uri_actions(obj, set())
        _remove_uri_actions(pdf.Root, set())
        _remove_uri_actions(pdf.trailer, set())

    return categories, active_content, uri_count


def _remove_uri_actions(obj: object, visited: set[tuple[int, int] | tuple[int]]) -> None:
    if isinstance(obj, (pikepdf.Dictionary, pikepdf.Stream, pikepdf.Array)):
        objgen = getattr(obj, "objgen", (0, 0))
        if objgen != (0, 0):
            identity = (int(objgen[0]), int(objgen[1]))
            if identity in visited:
                return
            visited.add(identity)

    if isinstance(obj, (pikepdf.Dictionary, pikepdf.Stream)):
        for key in list(obj.keys()):
            value = obj.get(key)
            if isinstance(value, (pikepdf.Dictionary, pikepdf.Stream)) and str(
                value.get("/S", "")
            ) in _DANGEROUS_PDF_ACTIONS | {"/URI"}:
                del obj[key]
            elif isinstance(value, (pikepdf.Dictionary, pikepdf.Stream, pikepdf.Array)):
                _remove_uri_actions(value, visited)
    elif isinstance(obj, pikepdf.Array):
        for value in obj:
            _remove_uri_actions(value, visited)


def _verify_pdf(data: bytes, expected_pages: int) -> None:
    with pikepdf.open(BytesIO(data), attempt_recovery=False) as pdf:
        if pdf.is_encrypted or len(pdf.pages) != expected_pages:
            raise FileProcessingError("Sanitized PDF structure verification failed")
        if pdf.get_warnings():
            raise FileProcessingError("Sanitized PDF parser reported a warning")
        if pdf.docinfo or "/Metadata" in pdf.Root or "/ID" in pdf.trailer:
            raise FileProcessingError("Sanitized PDF still contains document metadata")
        categories, active_content, uri_count = _scan_pdf(pdf, sanitize=False)
        if "document_info" in categories:
            raise FileProcessingError("Sanitized PDF still contains document metadata")
        if pdf.get_warnings():
            raise FileProcessingError("Sanitized PDF parser reported a warning")
        _verify_page_content_streams(pdf)
        if pdf.get_warnings():
            raise FileProcessingError("Sanitized PDF parser reported a warning")
        if active_content or uri_count:
            raise FileProcessingError("Sanitized PDF still contains active content")


def _verify_page_content_streams(pdf: pikepdf.Pdf) -> None:
    decoded_total = 0
    for page in pdf.pages:
        contents = page.obj.get("/Contents")
        if contents is None:
            continue
        streams = contents if isinstance(contents, pikepdf.Array) else [contents]
        for stream in streams:
            if not isinstance(stream, pikepdf.Stream):
                raise FileProcessingError("PDF page content is not a stream")
            raw = stream.read_raw_bytes()
            decoded_total += len(_decode_page_content_stream(stream, raw))
            if decoded_total > MAX_PDF_CONTENT_BYTES:
                raise FileProcessingError("Decoded PDF page content exceeds safe limits")


def _decode_page_content_stream(stream: pikepdf.Stream, raw: bytes) -> bytes:
    if len(raw) > MAX_PDF_CONTENT_BYTES:
        raise FileProcessingError("PDF page content exceeds safe limits")
    filter_value = stream.get("/Filter")
    if filter_value is None:
        filters: list[str] = []
    elif isinstance(filter_value, pikepdf.Array):
        filters = [str(value) for value in filter_value]
    else:
        filters = [str(filter_value)]

    if len(filters) > 1 or filters not in ([], ["/FlateDecode"], ["/Fl"]):
        raise FileProcessingError("Unsupported PDF page content filter")
    if "/DecodeParms" in stream:
        parameters = stream.get("/DecodeParms")
        if not (
            parameters is None
            or str(parameters) == "None"
            or isinstance(parameters, pikepdf.Dictionary)
            and len(parameters) == 0
        ):
            raise FileProcessingError("Unsupported PDF page content parameters")
    if not filters:
        return raw
    if not raw:
        return b""

    try:
        decoder = zlib.decompressobj()
        decoded = decoder.decompress(raw, MAX_PDF_CONTENT_BYTES + 1)
        if len(decoded) > MAX_PDF_CONTENT_BYTES or decoder.unconsumed_tail:
            raise FileProcessingError("Decoded PDF page content exceeds safe limits")
        decoded += decoder.flush(MAX_PDF_CONTENT_BYTES + 1 - len(decoded))
    except zlib.error as exc:
        raise FileProcessingError("PDF page content cannot be decoded") from exc
    if len(decoded) > MAX_PDF_CONTENT_BYTES or not decoder.eof or decoder.unused_data:
        raise FileProcessingError("PDF page content cannot be decoded")
    return decoded


def _remove_serialized_trailer_id(data: bytes) -> bytes:
    startxref_start = data.rfind(b"startxref")
    if startxref_start < 0:
        raise FileProcessingError("Sanitized PDF trailer could not be verified")
    startxref_match = re.match(rb"startxref\s+(\d+)", data[startxref_start:])
    if startxref_match is None:
        raise FileProcessingError("Sanitized PDF trailer could not be verified")

    xref_offset = int(startxref_match.group(1))
    if xref_offset >= startxref_start:
        raise FileProcessingError("Sanitized PDF trailer could not be verified")

    if data[xref_offset : xref_offset + 4] == b"xref":
        trailer_start = data.find(b"trailer", xref_offset, startxref_start)
        if trailer_start < 0:
            raise FileProcessingError("Sanitized PDF trailer could not be verified")
        region_start = trailer_start
        region_end = startxref_start
    else:
        xref_stream_region = data[xref_offset:startxref_start]
        stream_match = re.search(rb"\bstream[ \t]*(?:\r\n|\n|\r)", xref_stream_region)
        if stream_match is None:
            raise FileProcessingError("Sanitized PDF trailer could not be verified")
        region_start = xref_offset
        region_end = xref_offset + stream_match.start()
        if re.search(rb"/Type\s*/XRef\b", data[region_start:region_end]) is None:
            raise FileProcessingError("Sanitized PDF trailer could not be verified")

    trailer_or_xref_dictionary = data[region_start:region_end]
    cleaned_dictionary, count = _TRAILER_ID_RE.subn(b"", trailer_or_xref_dictionary)
    if count != 1:
        raise FileProcessingError("Sanitized PDF trailer identifier could not be removed")
    return data[:region_start] + cleaned_dictionary + data[region_end:]
