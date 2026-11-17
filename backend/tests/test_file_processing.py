"""Behavioral tests for the in-memory file processor."""

import struct
import zlib
from io import BytesIO

import pikepdf
import pytest
from PIL import ExifTags, Image, ImageCms, PngImagePlugin

from metaguard_api.file_processing import (
    MAX_FILE_SIZE,
    MAX_IMAGE_PIXELS,
    MAX_IMAGE_SIDE,
    MAX_PDF_PAGES,
    FileProcessingError,
    process_file,
)


def _image_bytes(
    format_name: str,
    *,
    size: tuple[int, int] = (3, 2),
    exif: Image.Exif | None = None,
    pnginfo: PngImagePlugin.PngInfo | None = None,
    icc_profile: bytes | None = None,
) -> bytes:
    image = Image.new("RGB", size, color=(40, 80, 120))
    output = BytesIO()
    options: dict[str, object] = {}
    if exif is not None:
        options["exif"] = exif
    if pnginfo is not None:
        options["pnginfo"] = pnginfo
    if icc_profile is not None:
        options["icc_profile"] = icc_profile
    image.save(output, format=format_name, **options)
    return output.getvalue()


def _pdf_bytes(*, encrypted: bool = False, pages: int = 1) -> bytes:
    pdf = pikepdf.Pdf.new()
    for _ in range(pages):
        pdf.add_blank_page(page_size=(100, 100))
    pdf.docinfo["/Author"] = "private author"
    pdf.docinfo["/Title"] = "private title"
    pdf.Root["/Metadata"] = pdf.make_stream(
        b"<?xpacket begin=''?><x:xmpmeta xmlns:x='adobe:ns:meta/'>"
        b"<rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>"
        b"<rdf:Description xmlns:dc='http://purl.org/dc/elements/1.1/'>"
        b"<dc:creator>private author</dc:creator>"
        b"</rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end='w'?>"
    )
    pdf.Root["/OpenAction"] = pikepdf.Dictionary(
        S=pikepdf.Name.JavaScript,
        JS=pikepdf.String("app.alert('unsafe')"),
    )
    pdf.Root["/CustomMetadata"] = pikepdf.Dictionary(
        GPS=pikepdf.String("private coordinates"),
        Path=pikepdf.String("/private/path/document.pdf"),
        SerialNumber=pikepdf.String("private serial"),
    )
    pdf.Root["/Names"] = pikepdf.Dictionary(
        EmbeddedFiles=pikepdf.Dictionary(),
    )
    embedded_file = pdf.make_stream(b"private attachment")
    embedded_file["/Type"] = pikepdf.Name.EmbeddedFile
    file_spec = pdf.make_indirect(
        pikepdf.Dictionary(
            Type=pikepdf.Name.Filespec,
            F=pikepdf.String("private-name.txt"),
            EF=pikepdf.Dictionary(F=embedded_file),
        )
    )
    pdf.Root["/CustomFiles"] = pikepdf.Array([file_spec])
    page = pdf.pages[0]
    page.obj["/AA"] = pikepdf.Dictionary()
    page.obj["/Annots"] = pikepdf.Array(
        [
            pikepdf.Dictionary(
                Type=pikepdf.Name.Annot,
                Subtype=pikepdf.Name.Link,
                A=pikepdf.Dictionary(
                    S=pikepdf.Name.URI,
                    URI=pikepdf.String("https://private.example/"),
                ),
            )
        ]
    )
    output = BytesIO()
    if encrypted:
        pdf.save(output, encryption=pikepdf.Encryption(owner="owner", user="user"))
    else:
        pdf.save(output, deterministic_id=True)
    pdf.close()
    return output.getvalue()


def _pdf_with_outline_action(action: pikepdf.Dictionary) -> bytes:
    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(100, 100))
    outlines = pdf.make_indirect(pikepdf.Dictionary(Type=pikepdf.Name.Outlines, Count=1))
    item = pdf.make_indirect(
        pikepdf.Dictionary(
            Title=pikepdf.String("private outline"),
            Parent=outlines,
            A=action,
        )
    )
    outlines["/First"] = item
    outlines["/Last"] = item
    pdf.Root["/Outlines"] = outlines
    output = BytesIO()
    pdf.save(output, deterministic_id=True)
    pdf.close()
    return output.getvalue()


def _pdf_with_external_stream_file() -> bytes:
    pdf = pikepdf.Pdf.new()
    page = pdf.add_blank_page(page_size=(100, 100))
    content = pdf.make_stream(b"q Q\n")
    content["/F"] = pikepdf.String("C:/private/external-content.dat")
    page.obj["/Contents"] = content
    output = BytesIO()
    pdf.save(output, deterministic_id=True)
    pdf.close()
    return output.getvalue()


def _pdf_with_bad_flate_content() -> bytes:
    pdf = pikepdf.Pdf.new()
    page = pdf.add_blank_page(page_size=(100, 100))
    content = pdf.make_stream(b"not a valid zlib stream")
    content["/Filter"] = pikepdf.Name.FlateDecode
    page.obj["/Contents"] = content
    output = BytesIO()
    pdf.save(output, deterministic_id=True)
    pdf.close()
    return output.getvalue()


def _classic_pdf(objects: dict[int, bytes], *, trailer_entries: bytes = b"") -> bytes:
    """Build a tiny classic-xref PDF for parser-edge regression fixtures."""
    maximum = max(objects)
    output = bytearray(b"%PDF-1.4\n")
    offsets: dict[int, int] = {}
    for object_number, body in sorted(objects.items()):
        offsets[object_number] = len(output)
        output.extend(f"{object_number} 0 obj\n".encode())
        output.extend(body)
        output.extend(b"\nendobj\n")

    xref_offset = len(output)
    output.extend(f"xref\n0 {maximum + 1}\n".encode())
    output.extend(b"0000000000 65535 f \n")
    for object_number in range(1, maximum + 1):
        if object_number in offsets:
            output.extend(f"{offsets[object_number]:010d} 00000 n \n".encode())
        else:
            output.extend(b"0000000000 00000 f \n")
    output.extend(
        f"trailer\n<< /Size {maximum + 1} /Root 1 0 R ".encode() + trailer_entries + b" >>\n"
    )
    output.extend(f"startxref\n{xref_offset}\n%%EOF\n".encode())
    return bytes(output)


def _pdf_with_xref_stream_and_compressed_javascript() -> bytes:
    """Build an xref-stream PDF whose OpenAction is in an object stream."""
    output = bytearray(b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[int, int] = {}
    objects = {
        1: b"<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>",
        2: b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
        3: (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] "
            b"/Resources 7 0 R /Contents 4 0 R >>"
        ),
        4: b"<< /Length 0 >>\nstream\n\nendstream",
    }
    for object_number, body in objects.items():
        offsets[object_number] = len(output)
        output.extend(f"{object_number} 0 obj\n".encode() + body + b"\nendobj\n")

    javascript_object = b"<< /S /JavaScript /JS (private-script) >>"
    resource_object = b"<< /ProcSet [/PDF] >>"
    object_header = f"6 0 7 {len(javascript_object)} ".encode()
    object_body = javascript_object + resource_object
    object_stream = zlib.compress(object_header + object_body)
    offsets[5] = len(output)
    output.extend(
        b"5 0 obj\n"
        + f"<< /Type /ObjStm /N 2 /First {len(object_header)} ".encode()
        + f"/Filter /FlateDecode /Length {len(object_stream)} >>\nstream\n".encode()
        + object_stream
        + b"\nendstream\nendobj\n"
    )

    xref_offset = len(output)
    xref_entries = bytearray(b"\x00\x00\x00\x00\x00\xff\xff")
    for object_number in range(1, 6):
        xref_entries.extend(b"\x01" + offsets[object_number].to_bytes(4, "big") + b"\x00\x00")
    xref_entries.extend(b"\x02" + (5).to_bytes(4, "big") + b"\x00\x00")
    xref_entries.extend(b"\x02" + (5).to_bytes(4, "big") + b"\x00\x01")
    xref_entries.extend(b"\x01" + xref_offset.to_bytes(4, "big") + b"\x00\x00")
    output.extend(
        b"8 0 obj\n"
        + b"<< /Type /XRef /Size 9 /Root 1 0 R /W [1 4 2] /Index [0 9] "
        + b"/ID [<736f757263652d69642d303132333435><736f757263652d69642d303132333435>] "
        + f"/Length {len(xref_entries)} >>\nstream\n".encode()
        + xref_entries
        + b"\nendstream\nendobj\n"
    )
    output.extend(f"startxref\n{xref_offset}\n%%EOF\n".encode())
    return bytes(output)


def _pdf_with_duplicate_dictionary_key() -> bytes:
    return _classic_pdf(
        {
            1: b"<< /Type /Catalog /Pages 2 0 R /PrivateData 5 0 R >>",
            2: b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
            3: (
                b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] "
                b"/Resources << /ProcSet [/PDF] >> "
                b"/Contents 4 0 R >>"
            ),
            4: b"<< /Length 0 >>\nstream\n\nendstream",
            5: b"<< /Marker /first /Marker /second >>",
        }
    )


def _gray16_png(values: list[int]) -> bytes:
    image = Image.new("I;16", (len(values), 1))
    image.putdata(values)
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def _jpeg_with_embedded_thumbnail() -> bytes:
    thumbnail = _image_bytes("JPEG", size=(1, 1))
    tiff = (
        b"II*\x00"
        + struct.pack("<I", 8)
        + struct.pack("<H", 0)
        + struct.pack("<I", 14)
        + struct.pack("<H", 2)
        + struct.pack("<HHII", 513, 4, 1, 44)
        + struct.pack("<HHII", 514, 4, 1, len(thumbnail))
        + struct.pack("<I", 0)
        + thumbnail
    )
    payload = b"Exif\x00\x00" + tiff
    marker = b"\xff\xe1" + struct.pack(">H", len(payload) + 2) + payload
    source = _image_bytes("JPEG")
    return source[:2] + marker + source[2:]


def test_jpeg_removes_high_risk_exif_and_preserves_oriented_pixels() -> None:
    exif = Image.Exif()
    exif[274] = 6  # Rotate 90 degrees clockwise.
    exif[315] = "private author"
    exif[306] = "2026:11:16 12:00:00"
    exif[42033] = "private camera serial"
    exif[34853] = {1: "N", 2: (19, 26, 0), 3: "W", 4: (99, 8, 0)}
    result = process_file(_image_bytes("JPEG", exif=exif), "image/jpeg")

    with Image.open(BytesIO(result.cleaned_bytes)) as cleaned:
        cleaned.load()
        assert cleaned.format == "JPEG"
        assert cleaned.size == (2, 3)
        assert not cleaned.getexif()
        assert all(
            abs(actual - expected) <= 4
            for actual, expected in zip(cleaned.getpixel((0, 0)), (40, 80, 120), strict=False)
        )
    assert result.media_type == "image/jpeg"
    assert result.report.output_verified is True
    assert {"gps", "author", "date_time", "serial_number"}.issubset(
        set(result.report.metadata_categories)
    )


def test_png_reencoding_discards_text_profile_and_exif_metadata() -> None:
    pnginfo = PngImagePlugin.PngInfo()
    pnginfo.add_text("Author", "private author")
    pnginfo.add_text("Path", "C:/Users/private/photo.png")
    exif = Image.Exif()
    exif[315] = "private author"
    original = _image_bytes("PNG", exif=exif, pnginfo=pnginfo)

    result = process_file(original, "image/png")

    with Image.open(BytesIO(result.cleaned_bytes)) as cleaned:
        cleaned.load()
        assert cleaned.format == "PNG"
        assert cleaned.size == (3, 2)
        assert cleaned.info == {}
        assert not cleaned.getexif()
    assert result.report.output_verified is True
    assert {"author", "path"}.issubset(set(result.report.metadata_categories))


def test_png_discards_valid_srgb_profile_without_rejecting_image() -> None:
    profile = ImageCms.ImageCmsProfile(ImageCms.createProfile("sRGB")).tobytes()
    source = _image_bytes("PNG", icc_profile=profile)

    result = process_file(source, "image/png")

    with Image.open(BytesIO(result.cleaned_bytes)) as cleaned:
        cleaned.load()
        assert "icc_profile" not in cleaned.info
        assert cleaned.getpixel((0, 0)) == (40, 80, 120)


def test_png_preserves_rgb_trns_transparency_without_private_metadata() -> None:
    source_image = Image.new("RGB", (2, 1))
    source_image.putdata([(255, 0, 0), (0, 255, 0)])
    source = BytesIO()
    source_image.save(source, format="PNG", transparency=(255, 0, 0))

    result = process_file(source.getvalue(), "image/png")

    with Image.open(BytesIO(result.cleaned_bytes)) as cleaned:
        cleaned.load()
        assert cleaned.mode == "RGBA"
        assert [cleaned.getpixel((x, 0)) for x in range(2)] == [
            (255, 0, 0, 0),
            (0, 255, 0, 255),
        ]
        assert "transparency" not in cleaned.info
        assert "icc_profile" not in cleaned.info


def test_png_16_bit_grayscale_preserves_every_sample() -> None:
    samples = [0, 16384, 32768, 65535]

    result = process_file(_gray16_png(samples), "image/png")

    with Image.open(BytesIO(result.cleaned_bytes)) as cleaned:
        cleaned.load()
        assert cleaned.mode.startswith("I;16")
        assert [cleaned.getpixel((x, 0)) for x in range(len(samples))] == samples


def test_nested_exif_date_and_serial_are_reported() -> None:
    exif = Image.Exif()
    exif.get_ifd(ExifTags.IFD.Exif).update(
        {36867: "2026:11:16 12:00:00", 42033: "private nested serial"}
    )
    source = _image_bytes("JPEG", exif=exif)

    result = process_file(source, "image/jpeg")

    assert {"date_time", "serial_number"}.issubset(set(result.report.metadata_categories))


def test_png_without_iend_is_rejected_without_mutating_input() -> None:
    source = _image_bytes("PNG")
    truncated = source[:-12]
    original = truncated[:]

    with pytest.raises(FileProcessingError):
        process_file(truncated, "image/png")

    assert truncated == original


def test_jpeg_with_corrupt_exif_warning_is_rejected() -> None:
    payload = b"Exif\x00\x00II*\x00\x08\x00\x00\x00"
    marker = b"\xff\xe1" + struct.pack(">H", len(payload) + 2) + payload
    image = _image_bytes("JPEG")
    source = image[:2] + marker + image[2:]

    with pytest.raises(FileProcessingError):
        process_file(source, "image/jpeg")


def test_jpeg_embedded_thumbnail_is_removed_and_reported() -> None:
    result = process_file(_jpeg_with_embedded_thumbnail(), "image/jpeg")

    with Image.open(BytesIO(result.cleaned_bytes)) as cleaned:
        assert not cleaned.getexif()
    assert "thumbnail" in result.report.metadata_categories


def test_pdf_removes_metadata_actions_annotations_and_embedded_files() -> None:
    result = process_file(_pdf_bytes(), "application/pdf")

    with pikepdf.open(BytesIO(result.cleaned_bytes), attempt_recovery=False) as clean:
        assert len(clean.pages) == 1
        assert not clean.docinfo
        assert "/Metadata" not in clean.Root
        assert "/OpenAction" not in clean.Root
        assert "/GPS" not in clean.Root.CustomMetadata
        assert "/Path" not in clean.Root.CustomMetadata
        assert "/SerialNumber" not in clean.Root.CustomMetadata
        assert "/AA" not in clean.pages[0].obj
        assert "/Annots" not in clean.pages[0].obj
        assert "/Names" not in clean.Root or "/EmbeddedFiles" not in clean.Root.Names
        assert "/F" not in clean.Root.CustomFiles[0]
        assert all(
            not (isinstance(obj, pikepdf.Stream) and str(obj.get("/Type", "")) == "/EmbeddedFile")
            for obj in clean.objects
        )
    assert result.media_type == "application/pdf"
    assert result.report.output_verified is True
    assert result.report.page_count == 1
    assert result.report.uri_links_removed == 1
    assert "author" in result.report.metadata_categories
    assert {"gps", "path", "serial_number"}.issubset(set(result.report.metadata_categories))
    assert result.report.active_content_removed is True


def test_pdf_actions_inside_indirect_objects_are_removed() -> None:
    pdf = pikepdf.Pdf.new()
    page = pdf.add_blank_page(page_size=(100, 100))
    action = pdf.make_indirect(
        pikepdf.Dictionary(
            S=pikepdf.Name.JavaScript,
            JS=pikepdf.String("unsafe"),
            OpenAction=pikepdf.Name.GoToR,
            Launch=pikepdf.String("unsafe"),
        )
    )
    page.obj["/Resources"] = pikepdf.Dictionary(XObject=pikepdf.Dictionary(X=action))
    source = BytesIO()
    pdf.save(source, deterministic_id=True)
    pdf.close()

    result = process_file(source.getvalue(), "application/pdf")
    with pikepdf.open(BytesIO(result.cleaned_bytes), attempt_recovery=False) as clean:
        assert "/X" not in clean.pages[0].obj.Resources.XObject


def test_pdf_page_thumbnail_stream_is_removed() -> None:
    pdf = pikepdf.Pdf.new()
    page = pdf.add_blank_page(page_size=(100, 100))
    thumbnail = pdf.make_stream(b"private-thumbnail-payload")
    page.obj["/Thumb"] = thumbnail
    source = BytesIO()
    pdf.save(source, deterministic_id=True)
    pdf.close()

    result = process_file(source.getvalue(), "application/pdf")
    with pikepdf.open(BytesIO(result.cleaned_bytes), attempt_recovery=False) as clean:
        assert "/Thumb" not in clean.pages[0].obj
        assert all(
            not (
                isinstance(obj, pikepdf.Stream)
                and obj.read_raw_bytes() == b"private-thumbnail-payload"
            )
            for obj in clean.objects
        )


def test_pdf_gotoe_outline_action_and_external_filename_are_removed() -> None:
    filename = "C:/private/linked-document.pdf"
    source = _pdf_with_outline_action(
        pikepdf.Dictionary(S=pikepdf.Name.GoToE, F=pikepdf.String(filename))
    )

    result = process_file(source, "application/pdf")

    with pikepdf.open(BytesIO(result.cleaned_bytes), attempt_recovery=False) as clean:
        assert "/A" not in clean.Root.Outlines.First
    assert filename.encode() not in result.cleaned_bytes
    assert filename not in repr(result.report)


def test_pdf_external_content_stream_file_reference_is_removed() -> None:
    filename = "C:/private/external-content.dat"
    source = _pdf_with_external_stream_file()

    result = process_file(source, "application/pdf")

    with pikepdf.open(BytesIO(result.cleaned_bytes), attempt_recovery=False) as clean:
        content = clean.pages[0].obj.Contents
        assert "/F" not in content
    assert filename.encode() not in result.cleaned_bytes


def test_pdf_invalid_flate_page_content_is_rejected_without_mutating_input() -> None:
    source = _pdf_with_bad_flate_content()
    original = source[:]

    with pytest.raises(FileProcessingError):
        process_file(source, "application/pdf")

    assert source == original


def test_pdf_lazy_duplicate_key_warning_is_rejected(monkeypatch) -> None:
    source = _pdf_with_duplicate_dictionary_key()
    original_get_warnings = pikepdf.Pdf.get_warnings
    observed_warnings: list[list[str]] = []

    def track_warnings(pdf):
        warnings = original_get_warnings(pdf)
        observed_warnings.append(warnings)
        return warnings

    monkeypatch.setattr(pikepdf.Pdf, "get_warnings", track_warnings)

    with pytest.raises(FileProcessingError):
        process_file(source, "application/pdf")
    assert observed_warnings and not observed_warnings[0]
    assert any(observed_warnings[1:])


def test_pdf_trailer_identifier_is_removed() -> None:
    source = _classic_pdf(
        {
            1: b"<< /Type /Catalog /Pages 2 0 R >>",
            2: b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
            3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] /Resources << >> >>",
        },
        trailer_entries=(
            b"/ID [<736f757263652d69642d303132333435><736f757263652d69642d303132333435>]"
        ),
    )

    result = process_file(source, "application/pdf")

    with pikepdf.open(BytesIO(result.cleaned_bytes), attempt_recovery=False) as clean:
        assert "/ID" not in clean.trailer
    assert b"736f757263652d69642d303132333435" not in result.cleaned_bytes


def test_pdf_xref_stream_compressed_javascript_is_sanitized_and_reparsed() -> None:
    source = _pdf_with_xref_stream_and_compressed_javascript()
    original = source[:]
    with pikepdf.open(BytesIO(source), attempt_recovery=False) as original_pdf:
        assert original_pdf.Root.OpenAction.S == pikepdf.Name.JavaScript
        assert "/ID" in original_pdf.trailer

    result = process_file(source, "application/pdf")

    with pikepdf.open(BytesIO(result.cleaned_bytes), attempt_recovery=False) as cleaned:
        assert len(cleaned.pages) == 1
        assert "/ID" not in cleaned.trailer
        assert "/OpenAction" not in cleaned.Root
        assert all(
            not (
                isinstance(obj, (pikepdf.Dictionary, pikepdf.Stream))
                and str(obj.get("/S", "")) == "/JavaScript"
            )
            for obj in cleaned.objects
        )
    assert source == original
    assert result.report.output_verified is True
    assert result.report.active_content_removed is True


def test_pdf_with_unsupported_encryption_is_rejected() -> None:
    with pytest.raises(FileProcessingError, match="[Ee]ncrypted"):
        process_file(_pdf_bytes(encrypted=True), "application/pdf")


@pytest.mark.parametrize(
    ("data", "content_type"),
    [
        (b"not an image", "image/jpeg"),
        (b"%PDF-1.7\nnot a valid PDF", "application/pdf"),
        (_image_bytes("PNG"), "image/jpeg"),
        (_image_bytes("JPEG"), "image/png"),
        (_pdf_bytes(), "image/png"),
        (_image_bytes("PNG"), "image/gif"),
    ],
)
def test_invalid_or_mismatched_input_fails_closed(data: bytes, content_type: str) -> None:
    with pytest.raises(FileProcessingError):
        process_file(data, content_type)


def test_empty_or_non_bytes_input_is_rejected() -> None:
    with pytest.raises(FileProcessingError):
        process_file(b"", "image/png")
    with pytest.raises(FileProcessingError):
        process_file(bytearray(b"data"), "image/png")  # type: ignore[arg-type]


def test_input_size_limit_fails_before_parsing() -> None:
    with pytest.raises(FileProcessingError, match="size limit"):
        process_file(b"x" * (MAX_FILE_SIZE + 1), "image/png")


def test_image_dimension_limits_are_enforced_before_decode() -> None:
    too_wide = _image_bytes("PNG", size=(MAX_IMAGE_SIDE + 1, 1))
    with pytest.raises(FileProcessingError, match="dimensions"):
        process_file(too_wide, "image/png")

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr("metaguard_api.file_processing.MAX_IMAGE_PIXELS", 5)
        too_many_pixels = _image_bytes("PNG", size=(3, 2))
        with pytest.raises(FileProcessingError, match="dimensions"):
            process_file(too_many_pixels, "image/png")


def test_pdf_page_limit_is_enforced() -> None:
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr("metaguard_api.file_processing.MAX_PDF_PAGES", 1)
        with pytest.raises(FileProcessingError, match="page limit"):
            process_file(_pdf_bytes(pages=2), "application/pdf")


def test_declared_image_limit_constants_match_approved_demo_limits() -> None:
    assert MAX_IMAGE_PIXELS == 40_000_000
    assert MAX_IMAGE_SIDE == 8_000
    assert MAX_PDF_PAGES == 100


@pytest.mark.parametrize(
    ("source", "content_type"),
    [
        (_image_bytes("JPEG"), "image/jpeg"),
        (_image_bytes("PNG"), "image/png"),
        (_pdf_bytes(), "application/pdf"),
    ],
)
def test_reprocessing_same_input_is_deterministic(source: bytes, content_type: str) -> None:
    first = process_file(source, content_type)
    second = process_file(source, content_type)

    assert first.cleaned_bytes == second.cleaned_bytes
    assert first.report == second.report


def test_processor_does_not_write_plaintext_files(tmp_path) -> None:
    source = _image_bytes("PNG", pnginfo=PngImagePlugin.PngInfo())

    process_file(source, "image/png")

    assert list(tmp_path.iterdir()) == []


def test_unverifiable_sanitized_output_is_rejected(monkeypatch) -> None:
    source = _image_bytes("PNG")

    def write_corrupt_output(image, destination, **options) -> None:
        destination.write(b"not a png")

    monkeypatch.setattr(Image.Image, "save", write_corrupt_output)

    with pytest.raises(FileProcessingError, match="malformed or cannot be verified"):
        process_file(source, "image/png")
