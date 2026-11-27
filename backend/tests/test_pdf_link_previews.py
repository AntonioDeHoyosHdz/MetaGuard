"""Verify URL reduction and the closed transient display contract."""

import pytest

from metaguard_api.pdf_link_previews import redact_pdf_link, valid_pdf_link_previews


@pytest.mark.parametrize(
    ("original", "preview"),
    [
        ("HTTPS://Example.INVALID/guide?color=blue#introduction", "https://example.invalid/guide"),
        ("http://127.0.0.1:8080/guide", "http://127.0.0.1:8080/guide"),
        ("https://[2001:DB8::1]:443/guide", "https://[2001:db8::1]:443/guide"),
        ("https://example.invalid/encoded%20title", "https://example.invalid/encoded%20title"),
    ],
)
def test_preview_retains_only_a_valid_bounded_absolute_destination(original, preview) -> None:
    assert redact_pdf_link(original) == preview
    assert valid_pdf_link_previews((preview,), media_type="application/pdf", uri_count=1)


@pytest.mark.parametrize(
    "value",
    [
        "https://placeholder@example.invalid/guide",
        "https://example.invalid:/guide",
        "https://example.invalid:65536/guide",
        "https://example.invalid:0/guide",
        "https://example..invalid/guide",
        "https://-example.invalid/guide",
        "https:///guide",
        "https://999.1.2.3/guide",
        "https://[2001:db8::1]other:80/guide",
        "https://example.invalid/guide\n",
        "https://example.invalid/guide room",
        "https://example.invalid/guide%not-decoded",
        "https://example.invalid/guía",
        "https://example.invalid/" + "a" * 370,
        "mailto:example@example.invalid",
        "/guide",
    ],
)
def test_invalid_destination_is_not_a_preview(value) -> None:
    assert redact_pdf_link(value) is None


def test_preview_frame_has_a_closed_count_and_shape() -> None:
    def valid(links, count=17):
        return valid_pdf_link_previews(links, media_type="application/pdf", uri_count=count)

    links = [f"https://example.invalid/{i}" for i in range(17)]
    assert valid(links[:-1], count=16)
    assert not valid(links)
    assert not valid(links[:-1], count=15)
    assert not valid([links[0], links[0]])
    assert not valid([["https://example.invalid"]])
    assert not valid(["https://example.invalid?omitted=true"])
    assert not valid(None)
