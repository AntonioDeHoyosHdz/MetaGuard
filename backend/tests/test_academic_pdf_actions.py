"""Non-executable PDF fixtures for the U2 sanitization evidence."""

import json
import shutil
import subprocess
from dataclasses import dataclass
from hashlib import sha256
from io import BytesIO
from pathlib import Path

import pikepdf
import pytest

from metaguard_api.file_processing import process_file


@dataclass(frozen=True)
class ActionCase:
    name: str
    kind: str
    removed_key: str
    compressed: bool = False
    escaped_destination_name: bool = False

    @property
    def marker(self) -> str:
        return f"https://example.invalid/{self.name}"


CASES = (
    ActionCase("ACT-01", "open-destination", "/OpenAction"),
    ActionCase("ACT-02", "open-action", "/OpenAction", True),
    ActionCase("ACT-03", "page-action", "/AA"),
    ActionCase("ACT-04", "internal-link", "/Annots", escaped_destination_name=True),
    ActionCase("ACT-05", "uri-link", "/URI"),
    ActionCase("ACT-06", "uri-link", "/URI", True),
    ActionCase("ACT-07", "attachment", "/EmbeddedFiles"),
    ActionCase("ACT-08", "attachment", "/EmbeddedFiles", True),
    ActionCase("ACT-09", "form", "/AcroForm"),
    ActionCase("ACT-10", "form", "/AcroForm", True),
)


def case_bytes(case: ActionCase, *, with_action: bool = True) -> bytes:
    """Add normal links, internal navigation, forms or a harmless text attachment.

    The originals are parsed, never opened in a browser or used to invoke an action.
    """
    out = BytesIO()
    with pikepdf.Pdf.new() as pdf:
        page = pdf.add_blank_page(page_size=(144, 96))
        page.Contents = pdf.make_stream(b"0.4 g 12 12 120 72 re f\n")
        if with_action:
            pdf.docinfo["/Title"] = f"Synthetic action inspection: {case.name}"
            destination = pikepdf.Array([page.obj, pikepdf.Name.Fit])
            internal = pikepdf.Dictionary(S=pikepdf.Name.GoTo, D=destination)
            if case.kind == "open-destination":
                pdf.Root["/OpenAction"] = destination
            elif case.kind == "open-action":
                pdf.Root["/OpenAction"] = pdf.make_indirect(internal)
            elif case.kind == "page-action":
                page.obj["/AA"] = pikepdf.Dictionary(O=internal)
            elif case.kind in {"internal-link", "uri-link"}:
                annotation = pikepdf.Dictionary(
                    Type=pikepdf.Name.Annot,
                    Subtype=pikepdf.Name.Link,
                    Rect=pikepdf.Array([12, 12, 86, 28]),
                    Border=pikepdf.Array([0, 0, 0]),
                )
                if case.kind == "uri-link":
                    annotation["/A"] = pdf.make_indirect(
                        pikepdf.Dictionary(
                            S=pikepdf.Name.URI,
                            URI=pikepdf.String(case.marker),
                        )
                    )
                else:
                    annotation["/Dest"] = destination
                page.obj["/Annots"] = pikepdf.Array([pdf.make_indirect(annotation)])
            elif case.kind == "attachment":
                pdf.attachments["nota-de-prueba.txt"] = b"Synthetic text attachment.\n"
            elif case.kind == "form":
                widget = pdf.make_indirect(
                    pikepdf.Dictionary(
                        Type=pikepdf.Name.Annot,
                        Subtype=pikepdf.Name.Widget,
                        FT=pikepdf.Name.Tx,
                        T=pikepdf.String("synthetic field"),
                        Rect=pikepdf.Array([10, 10, 70, 22]),
                        P=page.obj,
                    )
                )
                pdf.Root["/AcroForm"] = pikepdf.Dictionary(Fields=pikepdf.Array([widget]))
                page.obj["/Annots"] = pikepdf.Array([widget])
            else:
                raise ValueError("Unknown benign action fixture")

        mode = (
            pikepdf.ObjectStreamMode.generate
            if case.compressed and with_action
            else pikepdf.ObjectStreamMode.disable
        )
        pdf.save(out, object_stream_mode=mode, deterministic_id=True)
    contents = out.getvalue()
    if with_action and case.escaped_destination_name:
        canonical = b"/Dest [ "
        alternate = b"/Des#74["
        # Same byte length preserves the classic cross-reference offsets.
        assert len(canonical) == len(alternate) and contents.count(canonical) == 1
        contents = contents.replace(canonical, alternate)
    return contents


def _has_object_key(pdf: pikepdf.Pdf, key: str) -> bool:
    seen = set()

    def visit(obj: object) -> bool:
        if not isinstance(obj, (pikepdf.Dictionary, pikepdf.Stream, pikepdf.Array)):
            return False
        if obj.is_indirect:
            if obj.objgen in seen:
                return False
            seen.add(obj.objgen)
        if isinstance(obj, pikepdf.Array):
            return any(visit(value) for value in obj)
        return key in obj or any(visit(value) for _, value in obj.items())

    return any(visit(obj) for obj in pdf.objects)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
def test_benign_pdf_actions_are_removed_from_reparsed_copy(case):
    source = case_bytes(case)
    assert (b"/Des#74[" in source) is case.escaped_destination_name
    with pikepdf.open(BytesIO(source), attempt_recovery=False) as original:
        assert _has_object_key(original, case.removed_key)
        compressed = any(
            isinstance(obj, pikepdf.Stream) and obj.get("/Type") == pikepdf.Name.ObjStm
            for obj in original.objects
        )
        assert compressed is case.compressed
    output = process_file(source, "application/pdf")
    assert output.report.active_content_removed
    assert output.report.output_verified
    assert output.report.uri_links_removed == int(case.kind == "uri-link")
    with pikepdf.open(BytesIO(output.cleaned_bytes), attempt_recovery=False) as clean:
        assert len(clean.pages) == 1
        assert not _has_object_key(clean, case.removed_key)
        assert "/Title" not in clean.docinfo
        assert not clean.attachments
        assert bytes(clean.pages[0].Contents.read_bytes()) == b"0.4 g 12 12 120 72 re f\n"


def _json_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        result = set(value)
        for child in value.values():
            result.update(_json_keys(child))
        return result
    if isinstance(value, list):
        return set().union(*(_json_keys(child) for child in value))
    return set()


def inspect_action_pair(
    case: ActionCase, directory: Path, *, qpdf: str, pdftoppm: str
) -> dict[str, str]:
    """Inspect the PDF structure and render only the copy and the no-action reference."""
    directory.mkdir(parents=True, exist_ok=True)
    source = case_bytes(case)
    result = process_file(source, "application/pdf")
    original = directory / "original.pdf"
    clean = directory / "clean.pdf"
    reference = directory / "reference.pdf"
    original.write_bytes(source)
    clean.write_bytes(result.cleaned_bytes)
    reference.write_bytes(case_bytes(case, with_action=False))

    def run(*args: str) -> bytes:
        return subprocess.run(args, capture_output=True, check=True, timeout=15).stdout

    def object_keys(pdf: Path) -> set[str]:
        return _json_keys(
            json.loads(run(qpdf, "--json", "--json-key=qpdf", "--json-stream-data=none", str(pdf)))
        )

    for path in (original, clean):
        run(qpdf, "--check", str(path))
    assert case.removed_key in object_keys(original)
    copy_keys = object_keys(clean)
    assert case.removed_key not in copy_keys and "/Title" not in copy_keys
    assert result.report.active_content_removed and result.report.output_verified
    for path in (clean, reference):
        run(pdftoppm, "-singlefile", "-r", "72", str(path), str(path.with_suffix("")))
    assert clean.with_suffix(".ppm").read_bytes() == reference.with_suffix(".ppm").read_bytes()
    return {
        "case": case.name,
        "structure": case.kind,
        "compressed_objects": str(case.compressed).lower(),
        "escaped_destination_name": str(case.escaped_destination_name).lower(),
        "verified_removed_key": case.removed_key,
        "original_sha256": sha256(source).hexdigest(),
        "copy_sha256": sha256(result.cleaned_bytes).hexdigest(),
        "qpdf_check": "PASS",
        "poppler_copy_vs_reference": "identical",
    }


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
def test_pdf_action_corpus_with_command_line_tools(case, tmp_path):
    qpdf, pdftoppm = shutil.which("qpdf"), shutil.which("pdftoppm")
    if not qpdf or not pdftoppm:
        pytest.skip("independent command-line checks require qpdf and pdftoppm")
    assert inspect_action_pair(case, tmp_path, qpdf=qpdf, pdftoppm=pdftoppm)["qpdf_check"] == "PASS"
