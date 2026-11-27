"""Cheap, positive recognition of the three supported file signatures."""

_SIGNATURES = (
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"%PDF-", "application/pdf"),
)


def supported_file_signature(content: bytes) -> str | None:
    """Return a recognizable header, not proof that the file is valid or safe."""
    for magic, media_type in _SIGNATURES:
        if content.startswith(magic):
            return media_type
    return None
