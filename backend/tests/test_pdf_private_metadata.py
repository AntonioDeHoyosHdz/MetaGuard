"""Regression coverage for application-private PDF metadata."""

from io import BytesIO

import pikepdf
import pytest

from metaguard_api.file_processing import (
    FileProcessingError,
    _remove_serialized_trailer_id,
    _verify_pdf,
    process_file,
)


def pdf_with_private_metadata(location: str, indirect: bool, stream: bool) -> bytes:
    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(100, 100))
    secret = (
        pdf.make_stream(b"synthetic private identity")
        if stream
        else pikepdf.String("synthetic private identity")
    )
    piece_info = pikepdf.Dictionary({"/Illustrator": pikepdf.Dictionary({"/Private": secret})})
    if indirect:
        piece_info = pdf.make_indirect(piece_info)
    target = {"catalog": pdf.Root, "page": pdf.pages[0].obj, "trailer": pdf.trailer}[location]
    target["/PieceInfo"] = piece_info
    out = BytesIO()
    pdf.save(out)
    pdf.close()
    return out.getvalue()


@pytest.mark.parametrize("location", ["catalog", "page", "trailer"])
@pytest.mark.parametrize("indirect", [False, True])
@pytest.mark.parametrize("stream", [False, True])
def test_pieceinfo_is_removed_and_reported(location, indirect, stream):
    source = pdf_with_private_metadata(location, indirect, stream)
    result = process_file(source, "application/pdf")
    with pikepdf.open(BytesIO(result.cleaned_bytes)) as cleaned:
        assert "/PieceInfo" not in cleaned.Root
        assert all("/PieceInfo" not in page.obj for page in cleaned.pages)
        assert "/PieceInfo" not in cleaned.trailer
        assert len(cleaned.pages) == 1
    assert result.report.output_verified is True
    assert "document_info" in result.report.metadata_categories
    assert result.report.active_content_removed is False


@pytest.mark.parametrize("location", ["catalog", "page", "trailer"])
def test_verification_rejects_private_pieceinfo_if_removal_fails(location):
    raw = _remove_serialized_trailer_id(pdf_with_private_metadata(location, False, True))
    with pytest.raises(FileProcessingError, match="metadata"):
        _verify_pdf(raw, 1)


@pytest.mark.parametrize("alias", ["container", "nested", "array", "stream", "string", "trailer"])
def test_shared_private_objects_are_rejected_without_returning_output(alias):
    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(100, 100))
    private_string = pdf.make_indirect(pikepdf.String("synthetic private identity"))
    private_stream = pdf.make_stream(b"synthetic private identity")
    private_array = pdf.make_indirect(pikepdf.Array([private_string, private_stream]))
    nested = pdf.make_indirect(pikepdf.Dictionary({"/Private": private_array}))
    container = pdf.make_indirect(pikepdf.Dictionary({"/Vendor": nested}))
    pdf.Root["/PieceInfo"] = container
    selected = {
        "container": container,
        "nested": nested,
        "array": private_array,
        "stream": private_stream,
        "string": private_string,
        "trailer": private_stream,
    }[alias]
    target = pdf.trailer if alias == "trailer" else pdf.Root
    target["/CustomAlias"] = selected
    output = BytesIO()
    pdf.save(output)
    pdf.close()
    with pytest.raises(FileProcessingError, match="shared private metadata"):
        process_file(output.getvalue(), "application/pdf")


def test_shared_page_resource_is_rejected_without_damaging_page():
    pdf = pikepdf.Pdf.new()
    page = pdf.add_blank_page(page_size=(100, 100))
    resource = pdf.make_indirect(
        pikepdf.Dictionary({"/ProcSet": pikepdf.Array([pikepdf.Name.PDF])})
    )
    page.obj["/Resources"] = resource
    pdf.Root["/PieceInfo"] = pikepdf.Dictionary({"/Vendor": resource})
    output = BytesIO()
    pdf.save(output)
    pdf.close()
    with pytest.raises(FileProcessingError, match="shared private metadata"):
        process_file(output.getvalue(), "application/pdf")


@pytest.mark.parametrize("back_to_catalog", [False, True])
def test_private_cycles_terminate_and_reject_retained_catalog(back_to_catalog):
    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page(page_size=(100, 100))
    private = pdf.make_indirect(pikepdf.Dictionary())
    private["/Next"] = pdf.Root if back_to_catalog else private
    pdf.Root["/PieceInfo"] = private
    output = BytesIO()
    pdf.save(output)
    pdf.close()
    if back_to_catalog:
        with pytest.raises(FileProcessingError, match="shared private metadata"):
            process_file(output.getvalue(), "application/pdf")
    else:
        result = process_file(output.getvalue(), "application/pdf")
        with pikepdf.open(BytesIO(result.cleaned_bytes)) as cleaned:
            assert "/PieceInfo" not in cleaned.Root
            assert len(cleaned.pages) == 1
