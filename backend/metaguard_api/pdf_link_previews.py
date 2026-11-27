"""Bounded, parser-free validation for transient PDF link previews."""

import re
from ipaddress import IPv4Address, IPv6Address, ip_address
from urllib.parse import urlsplit

MAX_PDF_LINK_PREVIEWS = 16
_MAX_PREVIEW_LENGTH = 384
_MAX_INPUT_LENGTH = 4096
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_PATH = re.compile(r"(?:[a-zA-Z0-9._~!$&()*+,;=:@/-]|%[a-fA-F0-9]{2})*\Z")


def _valid_host(host: str, *, bracketed: bool) -> bool:
    if bracketed or all(character in "0123456789." for character in host):
        try:
            address = ip_address(host)
        except ValueError:
            return False
        return isinstance(address, IPv6Address if bracketed else IPv4Address)
    hostname = host.removesuffix(".")
    return 1 <= len(hostname) <= 253 and all(
        _DNS_LABEL.fullmatch(label) for label in hostname.split(".")
    )


def redact_pdf_link(value: str) -> str | None:
    """Return a bounded HTTP(S) destination without user info, query or fragment."""
    if not 1 <= len(value) <= _MAX_INPUT_LENGTH or any(
        not "!" <= char <= "~" or char in "\"'\\<>" for char in value
    ):
        return None
    try:
        parts = urlsplit(value)
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None
    authority = parts.netloc
    if (
        parts.scheme not in {"http", "https"}
        or not host
        or "@" in authority
        or "%" in authority
        or authority.endswith(":")
        or (port is not None and port == 0)
        or not _valid_host(host, bracketed=authority.startswith("["))
        or not _PATH.fullmatch(parts.path)
    ):
        return None
    host_text = f"[{host}]" if authority.startswith("[") else host
    # Do not rely on permissive URL splitting to recognize the whole authority.
    authority_lower = authority.lower()
    suffix = authority_lower.removeprefix(host_text)
    if not authority_lower.startswith(host_text) or (
        suffix != "" and (not suffix.startswith(":") or not suffix[1:].isdigit())
    ):
        return None
    preview = f"{parts.scheme}://{authority_lower}{parts.path}"
    return preview if len(preview) <= _MAX_PREVIEW_LENGTH else None


def valid_pdf_link_previews(links: object, *, media_type: str, uri_count: int) -> bool:
    """Accept only data the preview normalizer could have emitted."""
    return (
        media_type == "application/pdf"
        and isinstance(links, (tuple, list))
        and type(uri_count) is int
        and len(links) <= min(uri_count, MAX_PDF_LINK_PREVIEWS)
        and all(
            isinstance(link, str)
            and len(link) <= _MAX_PREVIEW_LENGTH
            and redact_pdf_link(link) == link
            for link in links
        )
        and len(set(links)) == len(links)
    )
