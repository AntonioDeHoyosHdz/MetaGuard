"""Generate the synthetic academic corpus without calling any remote service."""

import argparse
import json
import struct
from dataclasses import dataclass
from hashlib import sha256
from io import BytesIO
from pathlib import Path

import pikepdf
from PIL import ExifTags, Image, PngImagePlugin

ARTIST = ExifTags.Base.Artist
MODEL = ExifTags.Base.Model
DATE = ExifTags.Base.DateTimeOriginal
SERIAL = ExifTags.Base.BodySerialNumber
GPS = {1: "N", 2: (0, 3, 0), 3: "E", 4: (0, 7, 0)}


def canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True).encode("ascii")


def fingerprint(data: bytes) -> str:
    return sha256(data).hexdigest()


@dataclass(frozen=True)
class ImageCase:
    index: int
    tag_set: str

    @property
    def filename(self) -> str:
        extension = "jpg" if self.index <= 10 else "png"
        return f"IMG-{self.index:02d}.{extension}"

    @property
    def fields(self) -> dict:
        label = self.filename.split(".")[0]
        return {
            "identity": {"Artist": label, "Model": "Synthetic camera"},
            "timestamp": {"DateTimeOriginal": "2000:01:01 12:34:56"},
            "serial": {"BodySerialNumber": f"TEST-{label}"},
            "location": {"GPSInfo": GPS},
            "thumbnail": {"Thumbnail": "embedded JPEG, 1 x 1"},
            "text": {"Author": label, "SourcePath": f"/synthetic/{self.filename}"},
            "software": {"Software": label, "Description": "Synthetic image"},
        }[self.tag_set]

    @property
    def categories(self) -> tuple[str, ...]:
        return {
            "identity": ("author", "device_model", "image_metadata"),
            "timestamp": ("date_time", "image_metadata"),
            "serial": ("image_metadata", "serial_number"),
            "location": ("gps", "image_metadata"),
            "thumbnail": ("image_metadata", "thumbnail"),
            "text": ("author", "path"),
            "software": ("software",),
        }[self.tag_set]

    def encode(self) -> bytes:
        color = (self.index * 7, 80, 120)
        image = Image.new("RGB", (16, 12), color)
        output = BytesIO()
        if self.tag_set == "thumbnail":
            thumb = BytesIO()
            Image.new("RGB", (1, 1), (120, 80, self.index)).save(thumb, format="JPEG")
            tiff = (
                b"II*\x00"
                + struct.pack("<IHIH", 8, 0, 14, 2)
                + struct.pack("<HHII", 513, 4, 1, 44)
                + struct.pack("<HHII", 514, 4, 1, thumb.tell())
                + struct.pack("<I", 0)
                + thumb.getvalue()
            )
            image.save(output, format="JPEG", exif=b"Exif\x00\x00" + tiff)
        elif self.tag_set in {"text", "software"}:
            pnginfo = PngImagePlugin.PngInfo()
            for name, value in self.fields.items():
                pnginfo.add_text(name, value)
            image.save(output, format="PNG", pnginfo=pnginfo)
        else:
            exif = Image.Exif()
            if self.tag_set == "identity":
                exif[ARTIST] = self.fields["Artist"]
                exif[MODEL] = self.fields["Model"]
            elif self.tag_set == "location":
                exif[ExifTags.IFD.GPSInfo] = self.fields["GPSInfo"]
            else:
                tag = DATE if self.tag_set == "timestamp" else SERIAL
                exif[ExifTags.IFD.Exif] = {tag: next(iter(self.fields.values()))}
            image.save(output, format="JPEG" if self.index <= 10 else "PNG", exif=exif)
        return output.getvalue()


IMAGES = tuple(
    ImageCase(index, tags)
    for index, tags in enumerate(
        ("identity", "timestamp", "serial", "location", "thumbnail") * 2
        + ("text", "software", "location", "timestamp", "serial") * 2,
        start=1,
    )
)


@dataclass(frozen=True)
class PdfCase:
    index: int
    label: str
    empty_key: str | None = None

    @property
    def filename(self) -> str:
        return f"PDF-{self.index:02d}.pdf"

    @property
    def title(self) -> str:
        return f"Synthetic inert label: {self.label}"

    def encode(self) -> bytes:
        with pikepdf.Pdf.new() as pdf:
            page = pdf.add_blank_page(page_size=(144, 96))
            shade = f"0.{self.index:02d}".encode("ascii")
            page.Contents = pdf.make_stream(shade + b" g 12 12 120 72 re f\n")
            pdf.docinfo["/Title"] = self.title
            if self.empty_key == "Root.OpenAction":
                pdf.Root["/OpenAction"] = pikepdf.Dictionary()
            elif self.empty_key == "Page.AA":
                page.obj["/AA"] = pikepdf.Dictionary()
            elif self.empty_key == "Page.Annots":
                page.obj["/Annots"] = pikepdf.Array()
            elif self.empty_key == "Root.AcroForm.Fields":
                pdf.Root["/AcroForm"] = pikepdf.Dictionary(Fields=pikepdf.Array())
            elif self.empty_key:
                name = self.empty_key.split(".")[-1]
                pdf.Root["/Names"] = pikepdf.Dictionary({f"/{name}": pikepdf.Dictionary()})
            output = BytesIO()
            pdf.save(output, deterministic_id=True)
            return output.getvalue()


PDFS = (
    PdfCase(1, "OpenAction", "Root.OpenAction"),
    PdfCase(2, "AA", "Page.AA"),
    PdfCase(3, "JavaScript", "Root.Names.JavaScript"),
    PdfCase(4, "Launch"),
    PdfCase(5, "GoToR"),
    PdfCase(6, "SubmitForm"),
    PdfCase(7, "ImportData"),
    PdfCase(8, "RichMedia and file annotation", "Page.Annots"),
    PdfCase(9, "XFA", "Root.AcroForm.Fields"),
    PdfCase(10, "EmbeddedFiles", "Root.Names.EmbeddedFiles"),
)


@dataclass(frozen=True)
class PasswordCase:
    index: int
    scenario: str
    expected: str

    @property
    def case_id(self) -> str:
        return f"PWD-{self.index:02d}"

    @property
    def synthetic_input(self) -> str:
        return f"MetaGuard academic synthetic input {self.index:02d}"

    def response_body(self, suffix: str) -> bytes:
        if self.scenario == "malformed-response":
            return b"malformed-range-row\r\n"
        other = "0" * 35 if suffix != "0" * 35 else "1" * 35
        if self.scenario == "matched":
            return f"{other}:0\r\n{suffix}:{self.index}\r\n".encode("ascii")
        if self.scenario == "padding-match":
            return f"{suffix}:0\r\n{other}:2\r\n".encode("ascii")
        return f"{other}:2\r\n".encode("ascii")


PASSWORDS = tuple(
    PasswordCase(index, scenario, expected)
    for index, (scenario, expected) in enumerate(
        [("matched", "rejected")] * 10
        + [("absent", "accepted")] * 4
        + [("padding-match", "accepted")] * 2
        + [
            ("timeout", "accepted_reduced"),
            ("unavailable", "accepted_reduced"),
            ("malformed-response", "rejected"),
            ("local-blocklist", "rejected"),
        ],
        start=1,
    )
)


def manifest(output_dir: Path | None = None) -> dict:
    rows = []
    for image in IMAGES:
        data = image.encode()
        if output_dir is not None:
            (output_dir / image.filename).write_bytes(data)
        rows.append(
            {
                "file": image.filename,
                "sha256": fingerprint(data),
                "seeded_fields": sorted(image.fields),
                "expected_categories": image.categories,
                "expected": "metadata-removed",
            }
        )
    for pdf in PDFS:
        data = pdf.encode()
        if output_dir is not None:
            (output_dir / pdf.filename).write_bytes(data)
        rows.append(
            {
                "file": pdf.filename,
                "sha256": fingerprint(data),
                "title_label": pdf.label,
                "empty_structure": pdf.empty_key,
                "expected": "title-and-empty-structure-removed"
                if pdf.empty_key
                else "title-removed",
            }
        )
    for password in PASSWORDS:
        inputs = {"id": password.case_id, "scenario": password.scenario}
        rows.append(
            {
                **inputs,
                "sha256": fingerprint(
                    canonical_json({**inputs, "synthetic_input": password.synthetic_input})
                ),
                "expected": password.expected,
            }
        )
    return {
        "schema": 1,
        "origin": "Deterministic synthetic fixtures; no external assets",
        "cases": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=Path, help="New directory for temporary fixtures")
    args = parser.parse_args()
    args.output_dir.mkdir()
    (args.output_dir / "academic_corpus_manifest.json").write_bytes(
        (json.dumps(manifest(args.output_dir), indent=2) + "\n").encode("ascii")
    )


if __name__ == "__main__":
    main()
