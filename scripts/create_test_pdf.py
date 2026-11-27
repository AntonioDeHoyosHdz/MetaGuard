import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas

class MetaCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setAuthor("Equipo MetaGuard — Seguridad Informática")
        self.setTitle("Muestra de Ensayo de Higienización")
        self.setSubject("Prueba Técnica de Detección de Metadatos y Enlaces")
        self.setCreator("MetaGuard Security Laboratory Suite")

def create_rich_pdf(output_path):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
        title="Muestra de Ensayo de Higienización",
        author="Equipo MetaGuard — Seguridad Informática",
        subject="Prueba Técnica de Detección de Metadatos y Enlaces",
        creator="MetaGuard Security Laboratory Suite"
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#0284c7'),
        spaceAfter=10
    )
    h1_style = ParagraphStyle(
        'H1',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=colors.HexColor('#0f172a'),
        spaceBefore=8,
        spaceAfter=3
    )
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor('#334155'),
        spaceAfter=4
    )
    callout_style = ParagraphStyle(
        'Callout',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#0369a1')
    )

    story = []

    story.append(Paragraph("MetaGuard — Prueba de Detección de Amenazas y Metadatos", title_style))
    story.append(Paragraph("Archivo sintético de ensayo para análisis de seguridad &bull; Uso demostrativo", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284c7'), spaceAfter=10))

    banner = [
        [
            Paragraph("<b>¿QUÉ CONTIENE ESTE ARCHIVO PARA LA PRUEBA?</b><br/>"
                      "&bull; <b>Metadatos ocultos:</b> Autor, Asunto, Título y Programa creador sembrados a propósito.<br/>"
                      "&bull; <b>Hipervínculo activo:</b> Enlace HTTPS que MetaGuard debe detectar y retirar en la copia limpia.<br/>"
                      "&bull; <b>Guía técnica:</b> Explicación de los 3 filtros de detección de código malicioso.", callout_style)
        ]
    ]
    t = Table(banner, colWidths=[504])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f0f9ff')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#38bdf8')),
        ('PADDING', (0,0), (-1,-1), 7),
    ]))
    story.append(t)
    story.append(Spacer(1, 8))

    story.append(Paragraph("1. ¿Cómo sabe MetaGuard si un archivo tiene código malicioso?", h1_style))
    story.append(Paragraph(
        "Al subir este archivo a <b>https://metaguard.duckdns.org</b>, el sistema aplica 3 barreras de seguridad independientes:",
        body_style
    ))

    mechanisms = [
        ("A. Reputación Criptográfica Global (Threat Intelligence)",
         "El backend calcula la huella <b>SHA-256</b> de este PDF. Al marcar el consentimiento, consulta en tiempo real a <b>VirusTotal v3</b> para contrastar el hash contra más de 70 motores antivirus internacionales (Kaspersky, Microsoft Defender, CrowdStrike)."),
        ("B. Desarme Estructural (Content Disarm & Reconstruction - CDR)",
         "Los atacantes suelen esconder exploits en scripts <code>/JavaScript</code>, acciones automáticas <code>/Launch</code> o enlaces de phishing. MetaGuard analiza el árbol interno de este documento, <b>detecta el hipervínculo que incrustamos abajo</b> y lo neutraliza en la copia limpia."),
        ("C. Aislamiento Físico en Sandbox Docker (Defensa contra exploits 0-Day)",
         "Para protegernos de exploits que intenten desbordar la memoria del servidor, este PDF es parseado dentro de un contenedor Docker efímero con <code>--network=none</code>, <code>--read-only</code> y <code>--cap-drop=ALL</code>. Ningún payload puede escapar al sistema anfitrión.")
    ]

    for title, desc in mechanisms:
        story.append(Paragraph(f"<b>{title}</b>", ParagraphStyle('Sub', parent=h1_style, fontSize=9.5, textColor=colors.HexColor('#0369a1'))))
        story.append(Paragraph(desc, body_style))

    story.append(Spacer(1, 6))
    story.append(Paragraph("2. Enlace Activo Sembrado para la Prueba", h1_style))
    story.append(Paragraph(
        "A continuación se encuentra un hipervínculo activo. Al subir este PDF a MetaGuard, verás cómo el sistema extrae este enlace en la sección de <b>«Destinos retirados de PDF»</b> y genera una copia higienizada donde el enlace deja de ser ejecutable:",
        body_style
    ))

    link_text = 'Enlace de prueba: <a href="https://seguridad.upchiapas.edu.mx/alerta-malware"><font color="#0284c7"><u>https://seguridad.upchiapas.edu.mx/alerta-malware</u></font></a>'
    story.append(Paragraph(link_text, ParagraphStyle('Link', parent=body_style, fontSize=9.5)))

    story.append(Spacer(1, 8))
    story.append(Paragraph("3. Metadatos Sembrados que MetaGuard debe Detectar", h1_style))
    meta_table_data = [
        [Paragraph("Campo de Metadatos", ParagraphStyle('TH', parent=body_style, fontName='Helvetica-Bold', textColor=colors.white)),
         Paragraph("Valor Sembrado en el Archivo", ParagraphStyle('TH', parent=body_style, fontName='Helvetica-Bold', textColor=colors.white))],
        [Paragraph("<b>Autor</b>", body_style), Paragraph("Equipo MetaGuard — Seguridad Informática", body_style)],
        [Paragraph("<b>Título</b>", body_style), Paragraph("Muestra de Ensayo de Higienización", body_style)],
        [Paragraph("<b>Asunto</b>", body_style), Paragraph("Prueba Técnica de Detección de Metadatos y Enlaces", body_style)],
        [Paragraph("<b>Programa Creador</b>", body_style), Paragraph("MetaGuard Security Laboratory Suite", body_style)]
    ]
    mt = Table(meta_table_data, colWidths=[150, 354])
    mt.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
        ('PADDING', (0,0), (-1,-1), 4),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')])
    ]))
    story.append(mt)

    doc.build(story, canvasmaker=MetaCanvas)
    print(f"Generated PDF with metadata & link at: {output_path}")

if __name__ == "__main__":
    out = r"C:\Users\jaras\Downloads\MetaGuard_Prueba_Seguridad_Malware.pdf"
    create_rich_pdf(out)
