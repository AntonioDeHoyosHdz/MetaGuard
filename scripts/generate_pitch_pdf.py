import os
import sys
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))
        
        # Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(54, 11 * 72 - 36, "MetaGuard — Guión de Pitch y Defensa Técnica (U2)")
            self.drawRightString(8.5 * 72 - 54, 11 * 72 - 36, "Despliegue Público AWS")
            self.setStrokeColor(colors.HexColor("#e2e8f0"))
            self.setLineWidth(0.5)
            self.line(54, 11 * 72 - 42, 8.5 * 72 - 54, 11 * 72 - 42)

        # Footer
        footer_text = f"Página {self._pageNumber} de {page_count}"
        self.drawString(54, 36, "Confidencial / Entrega Académica U2 — metaguard.duckdns.org")
        self.drawRightString(8.5 * 72 - 54, 36, footer_text)
        self.setStrokeColor(colors.HexColor("#e2e8f0"))
        self.setLineWidth(0.5)
        self.line(54, 46, 8.5 * 72 - 54, 46)
        self.restoreState()

def build_pdf(filename):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=22,
        leading=26,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=11,
        leading=15,
        textColor=colors.HexColor('#0284c7'),
        spaceAfter=15
    )
    h1_style = ParagraphStyle(
        'SectionHeading1',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=17,
        textColor=colors.HexColor('#0f172a'),
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True
    )
    h2_style = ParagraphStyle(
        'SectionHeading2',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10.5,
        leading=14,
        textColor=colors.HexColor('#0369a1'),
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=True
    )
    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#334155'),
        spaceAfter=6
    )
    body_bold = ParagraphStyle(
        'BodyDarkBold',
        parent=body_style,
        fontName='Helvetica-Bold'
    )
    speech_style = ParagraphStyle(
        'SpeechQuote',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=9,
        leading=13.5,
        textColor=colors.HexColor('#1e293b')
    )
    table_cell = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor('#1e293b')
    )
    table_cell_bold = ParagraphStyle(
        'TableCellBold',
        parent=table_cell,
        fontName='Helvetica-Bold',
        textColor=colors.HexColor('#0f172a')
    )
    table_cell_header = ParagraphStyle(
        'TableCellHeader',
        parent=table_cell,
        fontName='Helvetica-Bold',
        textColor=colors.white
    )

    story = []

    # Title block
    story.append(Paragraph("MetaGuard — Guión de Pitch y Defensa Técnica", title_style))
    story.append(Paragraph("Entrega Académica U2 &bull; Despliegue en Producción AWS &bull; Duración: 5 a 7 min", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284c7'), spaceAfter=12))

    # Meta banner table
    banner_data = [
        [
            Paragraph("<b>URL Pública:</b> https://metaguard.duckdns.org", table_cell),
            Paragraph("<b>Stack:</b> React 18, FastAPI, Docker, PostgreSQL 17", table_cell),
            Paragraph("<b>Enfoque:</b> Privacy by Design & Zero Trust", table_cell)
        ]
    ]
    banner_table = Table(banner_data, colWidths=[180, 180, 144])
    banner_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f1f5f9')),
        ('PADDING', (0,0), (-1,-1), 6),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(banner_table)
    story.append(Spacer(1, 10))

    # 1. El Gancho y el Problema
    story.append(Paragraph("1. El Gancho y el Problema (1 minuto)", h1_style))
    speech_1 = """<b>«Qué decir:»</b> <i>"Buenas tardes a todos. Cuando subimos una foto tomada con el celular o compartimos un contrato en PDF, rara vez somos conscientes de la fuga masiva de datos que ocurre en segundo plano. Una foto contiene coordenadas GPS exactas de dónde vivimos o trabajamos, número de serie del sensor y fecha exacta. Un PDF corporativo expone nombres de autores, rutas internas de red y scripts potencialmente maliciosos.<br/><br/>
Para resolver esto desarrollamos <b>MetaGuard</b>: una plataforma de inspección, análisis de reputación y sanitización profunda de archivos, concebida bajo el principio de <b>Privacidad por Diseño</b> y respaldada por una arquitectura de <b>Defensa en Profundidad en AWS</b>."</i>"""
    
    quote_table1 = Table([[Paragraph(speech_1, speech_style)]], colWidths=[504])
    quote_table1.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#38bdf8')),
        ('PADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(quote_table1)
    story.append(Spacer(1, 10))

    # 2. Arquitectura y Despliegue en AWS
    story.append(Paragraph("2. Arquitectura y Despliegue en AWS (1.5 minutos)", h1_style))
    story.append(Paragraph("No implementamos un monolito expuesto. El sistema está segmentado en <b>3 instancias EC2</b> dentro de una VPC de AWS para aplicar el principio de menor privilegio:", body_style))

    infra_data = [
        [
            Paragraph("Capa / Instancia", table_cell_header),
            Paragraph("Tecnología & Rol", table_cell_header),
            Paragraph("Medidas de Seguridad Clave", table_cell_header)
        ],
        [
            Paragraph("<b>1. Perímetro Público</b><br/>(3.209.212.22)", table_cell),
            Paragraph("<b>Nginx + React SPA</b><br/>metaguard.duckdns.org", table_cell),
            Paragraph("&bull; Solo puerto 443 abierto con TLS/SSL.<br/>&bull; Rate limiting estricto contra ataques de fuerza bruta.<br/>&bull; SPA en React 18 + Vite optimizada.", table_cell)
        ],
        [
            Paragraph("<b>2. Backend & Worker</b><br/>(54.197.251.32)", table_cell),
            Paragraph("<b>FastAPI + Docker Worker</b><br/>(Python 3.12)", table_cell),
            Paragraph("&bull; El procesador corre en <b>contenedor Docker aislado</b>.<br/>&bull; Sin privilegios de root, sin red y con <code>read_only_rootfs</code>.<br/>&bull; API y supervisor desacoplados por IPC local.", table_cell)
        ],
        [
            Paragraph("<b>3. Base de Datos</b><br/>(172.31.26.1:55432)", table_cell),
            Paragraph("<b>PostgreSQL 17</b><br/>Subred Privada VPC", table_cell),
            Paragraph("&bull; <b>Cero acceso a Internet</b> (sin IP pública).<br/>&bull; Accesible solo desde la IP interna del backend.<br/>&bull; Cuentas SQL independientes por servicio con menor privilegio.", table_cell)
        ]
    ]
    infra_table = Table(infra_data, colWidths=[120, 164, 220])
    infra_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
        ('PADDING', (0,0), (-1,-1), 6),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')])
    ]))
    story.append(infra_table)
    story.append(Spacer(1, 10))

    # 3. Guion de la Demostración en Vivo
    story.append(Paragraph("3. Guión de la Demostración en Vivo (2.5 a 3 minutos)", h1_style))
    story.append(Paragraph("Ejecutar el recorrido en <b>https://metaguard.duckdns.org</b> siguiendo estos 4 momentos clave:", body_style))

    demo_steps = [
        ("A. Autenticación y Doble Factor (MFA / TOTP)", 
         "1. Iniciar sesión o mostrar registro verificado por correo (Gmail SMTP TLS).<br/>"
         "2. Mostrar <b>«Configurar autenticador»</b>: demostrar el alta de TOTP (RFC 6238 con Google/Microsoft Authenticator) y códigos de respaldo de un solo uso.<br/>"
         "<i>Enfasis: Cumplimiento explícito de los objetivos OBJ-02 y OBJ-04 de la rúbrica U2.</i>"),
        
        ("B. Privacidad por Diseño: El Mapa GPS Local", 
         "1. En <code>#demostracion</code>, seleccionar una imagen JPEG o PNG con metadatos de ubicación.<br/>"
         "2. Señalar el botón <b>«Revelar GPS en este dispositivo»</b>.<br/>"
         "3. <b>Momento Wow para el jurado:</b> Abrir la pestaña <i>Network</i> del navegador y demostrar que hay <b>CERO peticiones de red</b>. El parseo binario EXIF y el renderizado SVG del mapa mundial se ejecutan 100% en la memoria del cliente."),
        
        ("C. Sanitización Aislada en Docker", 
         "1. Hacer clic en <b>«Subir y analizar»</b>.<br/>"
         "2. Explicar cómo el contenedor Docker efímero elimina metadatos EXIF sensibles, neutraliza enlaces/JavaScript en PDFs y genera un reporte detallado.<br/>"
         "3. Descargar la copia limpia y destacar la política de <b>un solo uso</b> (el archivo higienizado se purga tras descargarse para no retener datos de terceros)."),

        ("D. Threat Intelligence (VirusTotal)", 
         "1. Mostrar el resultado de reputación con los hashes SHA-256 del original y de la copia limpia.<br/>"
         "2. Resaltar que <b>nunca se sube el archivo del usuario a un servicio externo</b>: solo se consulta por huella digital criptográfica bajo consentimiento explícito.")
    ]

    for title, desc in demo_steps:
        step_content = [
            Paragraph(f"<b>{title}</b>", h2_style),
            Paragraph(desc, body_style)
        ]
        story.append(KeepTogether(step_content))

    story.append(Spacer(1, 10))

    # 4. Métricas de Calidad e Ingeniería
    story.append(Paragraph("4. Calidad, Testing y Conclusión (1 minuto)", h1_style))
    quality_text = """Para garantizar robustez real y no una simple maqueta, MetaGuard implementa:<br/>
&bull; <b>Backend Testing:</b> Más de <b>770 pruebas automatizadas</b> con una cobertura superior al <b>90%</b> (Pytest).<br/>
&bull; <b>Frontend Testing:</b> 140 pruebas con Vitest y validación estricta de TypeScript (<code>tsc --noEmit</code>).<br/>
&bull; <b>Pruebas E2E:</b> Automatización completa con <b>Playwright</b> sobre Edge headless contra el dominio real en AWS.<br/>
&bull; <b>Análisis Estático:</b> 0 vulnerabilidades críticas reportadas por <b>CodeQL</b> y linters estrictos (<b>Ruff</b>)."""
    story.append(Paragraph(quality_text, body_style))
    story.append(Spacer(1, 10))

    # 5. Defensa ante Preguntas del Jurado
    story.append(Paragraph("5. Defensa ante Preguntas Difíciles del Jurado", h1_style))
    
    qa_list = [
        ("¿Por qué procesar en Docker y no directamente en la API con librerías de Python?",
         "Por mitigación de RCE (Remote Code Execution). Los parsers de imágenes y PDFs en C/C++ históricamente han sufrido desbordamientos de búfer (ej. ImageTragick). Si procesáramos dentro de la API, un archivo malicioso tomaría el control del proceso web y las credenciales de BD. En Docker, el contenedor carece de privilegios (no-root), no tiene salida a red y su sistema de archivos es de solo lectura."),
        
        ("¿Por qué el mapa GPS no usa Google Maps o Leaflet con OpenStreetMap?",
         "Por Principio de Privacidad por Diseño. Consultar Google Maps o teselas de OpenStreetMap filtraría a terceros la dirección IP del usuario y las coordenadas que está inspeccionando. Nuestra solución parsea el ArrayBuffer en local y proyecta sobre un SVG nativo: privacidad matemática absoluta."),
        
        ("¿Por qué la base de datos está en una tercera instancia separada?",
         "Para evitar que la saturación de CPU/memoria durante el procesamiento afecte la persistencia transaccional, y por segmentación de red: si el servidor web es comprometido, el atacante no tiene acceso directo a la base de datos."),

        ("¿Qué pasa si la API de VirusTotal se cae o agota su cuota?",
         "El sistema cuenta con degradación elegante (fail-safe). El flujo de higienización del archivo nunca se bloquea: el usuario recibe su copia limpia y el reporte indica claramente que la consulta de reputación externa no estuvo disponible.")
    ]

    for q, a in qa_list:
        qa_block = [
            Paragraph(f"<b>P: {q}</b>", table_cell_bold),
            Paragraph(f"<b>R:</b> {a}", table_cell),
            Spacer(1, 4)
        ]
        qa_table = Table([[qa_block]], colWidths=[504])
        qa_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(KeepTogether([qa_table, Spacer(1, 6)]))

    # Build
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"PDF successfully generated at: {filename}")

if __name__ == "__main__":
    out_path = r"C:\Users\jaras\Downloads\MetaGuard_Guion_Pitch_U2.pdf"
    build_pdf(out_path)
