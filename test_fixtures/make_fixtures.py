from PIL import Image
import io

img = Image.new("RGB", (100, 100), color=(73, 109, 137))
img.save("C:/Users/jaras/Downloads/MetaGuard/test_fixtures/sample.jpg", "JPEG")

pdf_content = (
    b"%PDF-1.4\n"
    b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 144] /Contents 4 0 R >>\nendobj\n"
    b"4 0 obj\n<< /Length 40 >>\nstream\nBT /F1 12 Tf 10 10 Td (MetaGuard) Tj ET\nendstream\nendobj\n"
    b"xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000202 00000 n \n"
    b"trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n290\n%%EOF\n"
)

with open("C:/Users/jaras/Downloads/MetaGuard/test_fixtures/sample.pdf", "wb") as f:
    f.write(pdf_content)

print("FIXTURES CREATED SUCCESSFULLY")
