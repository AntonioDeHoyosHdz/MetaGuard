"""Verify the synthetic corpus against the in-memory processor and stubbed HTTP."""

import json
import shutil
import subprocess
from hashlib import sha1
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock

import pikepdf
import pytest
from academic_corpus import IMAGES, PASSWORDS, PDFS, manifest
from PIL import ExifTags, Image

from metaguard_api.file_processing import process_file
from metaguard_api.password_policy import screen_password
from metaguard_api.pwned_passwords import fetch_password_range


def test_manifest_matches_generated_fixtures():
    path = Path(__file__).with_name("academic_corpus_manifest.json")
    checked_in = json.loads(path.read_text(encoding="ascii"))
    generated = json.loads(json.dumps(manifest()))
    assert checked_in == generated
    assert len({row["sha256"] for row in generated["cases"]}) == 50
    assert sum(case.filename.endswith(".jpg") for case in IMAGES) == 10
    assert sum(case.filename.endswith(".png") for case in IMAGES) == 10
    assert len(PDFS) == 10
    assert len(PASSWORDS) == 20


def check_image_input(image, case):
    image.load()
    exif = image.getexif()
    for name, value in case.fields.items():
        if name == "GPSInfo":
            parsed = exif.get_ifd(ExifTags.IFD.GPSInfo)
            assert {key: parsed[key] for key in value} == value
        elif name == "Thumbnail":
            thumbnail_ifd = exif.get_ifd(ExifTags.IFD.IFD1)
            start = 6 + thumbnail_ifd[ExifTags.Base.JpegIFOffset]
            end = start + thumbnail_ifd[ExifTags.Base.JpegIFByteCount]
            with Image.open(BytesIO(image.info["exif"][start:end])) as thumbnail:
                assert thumbnail.format == "JPEG" and thumbnail.size == (1, 1)
                thumbnail.load()
        elif case.tag_set in {"text", "software"}:
            assert image.text[name] == value
        else:
            tag = ExifTags.Base[name]
            fields = exif.get_ifd(ExifTags.IFD.Exif) if case.tag_set != "identity" else exif
            assert fields[tag] == value


def png_chunk_types(data):
    assert data.startswith(b"\x89PNG\r\n\x1a\n")
    offset = 8
    chunks = set()
    while offset < len(data):
        size = int.from_bytes(data[offset : offset + 4], "big")
        chunks.add(data[offset + 4 : offset + 8])
        offset += size + 12
    assert offset == len(data) and b"IEND" in chunks
    return chunks


@pytest.mark.parametrize("case", IMAGES, ids=lambda case: case.filename)
def test_image_corpus(case):
    source = case.encode()
    mime = "image/jpeg" if case.filename.endswith(".jpg") else "image/png"
    with Image.open(BytesIO(source)) as original:
        check_image_input(original, case)
        result = process_file(source, mime)
        assert result.report.output_verified
        assert result.report.metadata_categories == case.categories
        with Image.open(BytesIO(result.cleaned_bytes)) as cleaned:
            cleaned.load()
            assert cleaned.format == original.format
            assert cleaned.size == original.size == (16, 12)
            assert not cleaned.getexif()
            if mime == "image/png":
                assert not cleaned.text
                assert cleaned.tobytes() == original.tobytes()
                marker = b"tEXt" if case.tag_set in {"text", "software"} else b"eXIf"
                assert marker in png_chunk_types(source)
                assert not {b"eXIf", b"tEXt", b"zTXt", b"iTXt"} & png_chunk_types(
                    result.cleaned_bytes
                )
            else:
                assert b"Exif\0\0" in source and b"Exif\0\0" not in result.cleaned_bytes
                delta = map(
                    lambda samples: abs(samples[0] - samples[1]),
                    zip(original.tobytes(), cleaned.tobytes(), strict=True),
                )
                assert max(delta) <= 3


def pdf_value(pdf, path):
    parent, *keys = path.split(".")
    value = pdf.Root if parent == "Root" else pdf.pages[0].obj
    for key in keys:
        value = value.get(f"/{key}")
        if value is None:
            return None
    return value


@pytest.mark.parametrize("case", PDFS, ids=lambda case: case.filename)
def test_pdf_corpus(case):
    source = case.encode()
    with pikepdf.open(BytesIO(source), attempt_recovery=False) as original:
        assert str(original.docinfo["/Title"]) == case.title
        assert len(original.pages) == 1
        if case.empty_key:
            marker = pdf_value(original, case.empty_key)
            assert isinstance(marker, (pikepdf.Dictionary, pikepdf.Array)) and len(marker) == 0
        assert all(
            not {"/A", "/S", "/JS", "/URI", "/F", "/EF", "/XFA"} & set(obj.keys())
            for obj in original.objects
            if isinstance(obj, (pikepdf.Dictionary, pikepdf.Stream))
        )

    result = process_file(source, "application/pdf")
    assert result.report.output_verified
    assert result.report.active_content_removed is bool(case.empty_key)
    assert result.report.metadata_categories == ("document_info",)
    assert result.report.uri_links_removed == 0
    with pikepdf.open(BytesIO(result.cleaned_bytes), attempt_recovery=False) as cleaned:
        assert "/Title" not in cleaned.docinfo
        assert len(cleaned.pages) == 1
        if case.empty_key:
            assert pdf_value(cleaned, case.empty_key) is None


@pytest.mark.parametrize("case", PDFS, ids=lambda case: case.filename)
def test_pdf_corpus_with_poppler(case, tmp_path):
    pdfinfo = shutil.which("pdfinfo")
    render = shutil.which("pdftoppm")
    if not pdfinfo or not render:
        pytest.skip("independent checks require pdfinfo and pdftoppm")

    source = case.encode()
    cleaned = process_file(source, "application/pdf").cleaned_bytes
    for name, data in (("source", source), ("cleaned", cleaned)):
        path = tmp_path / f"{name}.pdf"
        path.write_bytes(data)
        info = subprocess.run(
            [pdfinfo, str(path)], capture_output=True, check=True, text=True, timeout=10
        ).stdout
        fields = dict(line.split(":", 1) for line in info.splitlines() if ":" in line)
        assert fields["Pages"].strip() == "1"
        assert fields.get("Title", "").strip() == (case.title if name == "source" else "")
        subprocess.run(
            [render, "-singlefile", "-r", "36", str(path), str(tmp_path / name)],
            capture_output=True,
            check=True,
            timeout=10,
        )
    assert (tmp_path / "source.ppm").read_bytes() == (tmp_path / "cleaned.ppm").read_bytes()


@pytest.mark.parametrize("case", PASSWORDS, ids=lambda case: case.case_id)
def test_password_corpus(case, monkeypatch):
    password = case.synthetic_input
    digest = sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
    opener = MagicMock()
    if case.scenario == "timeout":
        opener.open.side_effect = TimeoutError("synthetic timeout")
    else:
        response = opener.open.return_value.__enter__.return_value
        response.status = 503 if case.scenario == "unavailable" else 200
        response.length = 0
        response.chunked = False
        response.read.return_value = case.response_body(digest[5:])
    build_opener = MagicMock(return_value=opener)
    monkeypatch.setattr("metaguard_api.pwned_passwords.build_opener", build_opener)

    local_blocklist = frozenset({password if case.scenario == "local-blocklist" else "test only"})
    events = []
    result = screen_password(
        password,
        common_passwords=local_blocklist,
        lookup=fetch_password_range,
        report_outage=events.append,
    )
    assert result == case.expected
    failure = case.scenario in {"timeout", "unavailable", "malformed-response"}
    assert events == (["password_breach_check_unavailable"] if failure else [])
    if case.scenario == "local-blocklist":
        build_opener.assert_not_called()
    else:
        assert opener.open.call_count == 1
        request = opener.open.call_args.args[0]
        assert request.get_method() == "GET" and request.data is None
        assert request.full_url == f"https://api.pwnedpasswords.com/range/{digest[:5]}"
        assert dict(request.header_items()) == {
            "Add-padding": "true",
            "User-agent": "MetaGuard/0.1",
        }
