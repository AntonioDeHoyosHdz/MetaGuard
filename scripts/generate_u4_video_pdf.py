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
            self.drawString(54, 11 * 72 - 36, "MetaGuard — Guión y Rúbrica Técnica: Video U4 (Seguridad Informática)")
            self.drawRightString(8.5 * 72 - 54, 11 * 72 - 36, "Prof. Jose Alonso Macias Montoya")
            self.setStrokeColor(colors.HexColor("#e2e8f0"))
            self.setLineWidth(0.5)
            self.line(54, 11 * 72 - 42, 8.5 * 72 - 54, 11 * 72 - 42)

        # Footer
        footer_text = f"Página {self._pageNumber} de {page_count}"
        self.drawString(54, 36, "U4: Video del Proyecto Final — Rúbrica 100 Puntos")
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

    # Custom typography
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10.5,
        leading=14,
        textColor=colors.HexColor('#0284c7'),
        spaceAfter=12
    )
    h1_style = ParagraphStyle(
        'SectionHeading1',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#0f172a'),
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True
    )
    h2_style = ParagraphStyle(
        'SectionHeading2',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=13,
        textColor=colors.HexColor('#0369a1'),
        spaceBefore=6,
        spaceAfter=3,
        keepWithNext=True
    )
    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor('#334155'),
        spaceAfter=5
    )
    speech_style = ParagraphStyle(
        'SpeechQuote',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=8.5,
        leading=12.5,
        textColor=colors.HexColor('#1e293b')
    )
    cue_style = ParagraphStyle(
        'VisualCue',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#d97706')
    )
    table_cell = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
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

    # Title & Metadata
    story.append(Paragraph("MetaGuard — Guión Técnico y Rúbrica de Video (U4)", title_style))
    story.append(Paragraph("Asignatura: Seguridad Informática &bull; Evaluación: 100 puntos &bull; Duración: 3 a 6 minutos", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284c7'), spaceAfter=10))

    # Rubric checklist banner
    banner_data = [
        [
            Paragraph("<b>Requisitos de Grabación:</b><br/>&bull; Formato: Horizontal (1080p)<br/>&bull; Duración: 3 a 6 minutos<br/>&bull; Audio claro, sin música alta", table_cell),
            Paragraph("<b>Entrega en Google Drive:</b><br/>&bull; Subir video en MP4 (1080p)<br/>&bull; <b>¡Permisos de acceso públicos («Cualquiera con el enlace»)!</b>", table_cell),
            Paragraph("<b>Integrantes a Cuadro:</b><br/>&bull; Todos salen a cuadro al inicio<br/>&bull; Nombre + área de mayor involucramiento en el proyecto", table_cell)
        ]
    ]
    banner_table = Table(banner_data, colWidths=[170, 164, 170])
    banner_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('PADDING', (0,0), (-1,-1), 5),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(banner_table)
    story.append(Spacer(1, 8))

    # Bloque 1: Introducción y Presentación (30 - 45 seg)
    story.append(Paragraph("BLOQUE 1: Introducción y Presentación (30 a 45 segundos)", h1_style))
    story.append(Paragraph("<b>[ESCENA]:</b> Todos los integrantes aparecen a cuadro (cámara encendida). Tono profesional y seguro.", cue_style))
    
    intro_speech = """<b>«Guión hablado:»</b><br/>
<i>"Buenos días / tardes, profesor y compañeros. Presentamos <b>MetaGuard</b>, una plataforma de higienización de archivos, neutralización de exploits y privacidad por diseño para entornos corporativos.<br/>
Somos el equipo desarrollador: [Nombre 1], enfocado en la arquitectura perimetral en AWS, Nginx y seguridad en el frontend; [Nombre 2], enfocado en el backend FastAPI y aislamiento de contenedores Docker; y [Nombre 3], responsable del modelo criptográfico y los flujos de autenticación MFA.<br/>
<b>Problema a resolver:</b> Al compartir fotos y PDFs, se produce una fuga involuntaria masiva de información confidencial: coordenadas GPS milimétricas, nombres de usuario, versiones de software interno y rutas de servidores corporativos. Además, los archivos PDF son vectores habituales de malware y exploits (JavaScript embebido y URLs de phishing). MetaGuard mitiga estos riesgos antes de que los archivos sean procesados o compartidos."</i>"""
    
    quote_table1 = Table([[Paragraph(intro_speech, speech_style)]], colWidths=[504])
    quote_table1.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f1f5f9')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#0284c7')),
        ('PADDING', (0,0), (-1,-1), 7),
    ]))
    story.append(quote_table1)
    story.append(Spacer(1, 8))

    # Bloque 2: Características y Arquitectura (1 minuto)
    story.append(Paragraph("BLOQUE 2: Características Principales y Arquitectura de Seguridad (1 minuto)", h1_style))
    story.append(Paragraph("<b>[ESCENA]:</b> Compartir pantalla mostrando el diagrama de arquitectura y la consola de AWS.", cue_style))

    arch_speech = """<b>«Guión hablado:»</b><br/>
<i>"La solución está desplegada en AWS bajo una arquitectura de <b>Defensa en Profundidad</b> en 3 instancias EC2 dentro de una VPC privada:<br/>
1. <b>Perímetro Web:</b> Nginx con terminación TLS 1.3, encabezados HTTP estrictos (HSTS, CSP) y Rate Limiting agresivo por IP contra ataques de fuerza bruta.<br/>
2. <b>Capa de Aplicación & Sandbox:</b> API en Python con FastAPI. La higienización se ejecuta en un <b>contenedor Docker efímero</b> con usuario sin privilegios, sistema de archivos de solo lectura y <b>sin acceso a red</b>, evitando ataques de ejecución remota de código (RCE).<br/>
3. <b>Persistencia Segura:</b> Base de datos PostgreSQL 17 en subred privada interna, 100% aislada de Internet."</i>"""
    story.append(Paragraph(arch_speech, speech_style))
    story.append(Spacer(1, 4))

    # Tabla CIA + A + NR
    story.append(Paragraph("<b>Cumplimiento de Principios de Seguridad (Rúbrica U4):</b>", h2_style))
    cia_data = [
        [Paragraph("Principio", table_cell_header), Paragraph("Mecanismo Técnico Implementado en MetaGuard", table_cell_header)],
        [Paragraph("<b>Confidencialidad</b>", table_cell_bold), Paragraph("Cookies de sesión opacas (HttpOnly, Secure, SameSite). BD en subred privada. Copias limpias con política de descarga de un solo uso y purga programada.", table_cell)],
        [Paragraph("<b>Integridad</b>", table_cell_bold), Paragraph("Hashing criptográfico SHA-256 para auditar el original y verificar la copia higienizada. Consultas pasivas a VirusTotal por hash.", table_cell)],
        [Paragraph("<b>Disponibilidad</b>", table_cell_bold), Paragraph("Limitación de peticiones (Rate Limiting) en Nginx y FastAPI. Desacoplamiento en 3 capas en AWS para evitar saturación de BD.", table_cell)],
        [Paragraph("<b>Autenticación</b>", table_cell_bold), Paragraph("Hashing de contraseñas con <b>Argon2id</b>, verificación obligatoria por Gmail SMTP TLS y <b>Doble Factor MFA (TOTP RFC 6238)</b> con Google/MS Authenticator + códigos de respaldo.", table_cell)],
        [Paragraph("<b>No Repudio / Auditoría</b>", table_cell_bold), Paragraph("Registro estructurado de eventos de seguridad (intentos fallidos, cambios de clave, enrolamiento MFA) anonimizando IPs para conciliar trazabilidad con privacidad.", table_cell)]
    ]
    cia_table = Table(cia_data, colWidths=[110, 394])
    cia_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
        ('PADDING', (0,0), (-1,-1), 4),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')])
    ]))
    story.append(cia_table)
    story.append(Spacer(1, 8))

    # Bloque 3: Demostración Práctica y PoC de Seguridad (2 a 3 minutos)
    story.append(Paragraph("BLOQUE 3: Demostración Práctica y PoC de Mitigación (2 a 3 minutos)", h1_style))
    story.append(Paragraph("<b>[ESCENA]:</b> Navegador en vivo sobre <code>https://metaguard.duckdns.org</code>.", cue_style))

    demo_pocs = [
        ("Paso 1: Mapeo del Escenario y Login con MFA",
         "Mostrar el acceso seguro. Ingresar usuario y contraseña (hasheada en Argon2id) y validar el segundo factor con <b>Google Authenticator (código TOTP de 6 dígitos)</b>. Destacar que la sesión es inmune a secuestro por tokens expuestos en LocalStorage."),
        
        ("Paso 2: PoC 1 — Fuga de Geolocalización vs. Privacidad por Diseño",
         "Seleccionar una imagen JPEG tomada con smartphone. <b>Demostración de ataque/riesgo:</b> La foto expone la ubicación real de una persona. <b>Mitigación MetaGuard:</b> Se muestra el botón «Revelar GPS en este dispositivo». Al abrir DevTools > Network, se demuestra que <b>hay 0 peticiones de red</b>. El parseo binario y el mapa mundial SVG se procesan en la memoria del cliente."),
        
        ("Paso 3: PoC 2 — Neutralización en Sandbox Docker (Aislamiento de RCE)",
         "Hacer clic en «Subir y analizar». Explicar: <i>'Un atacante podría incrustar un payload malicioso para explotar una vulnerabilidad en los parsers de imagen/PDF. MetaGuard mitiga esto aislando el procesamiento en un contenedor Docker sin red y con permisos mínimos.'</i> El contenedor genera la copia limpia y el reporte."),

        ("Paso 4: PoC 3 — Threat Intelligence (VirusTotal) y Descarga Segura",
         "Mostrar el reporte con los hashes SHA-256 del original y el limpio. Mostrar la detección o ausencia de amenazas consultada a la API de VirusTotal. Descargar la copia limpia y demostrar que una segunda descarga es bloqueada (política de un solo uso)."),

        ("Paso 5: PoC 4 — Defensa Perimetral contra Fuerza Bruta",
         "Cerrar sesión e intentar varios inicios fallidos consecutivos rápidamente. Mostrar cómo el Rate Limiting de Nginx/FastAPI bloquea temporalmente al atacante con código HTTP 429 (Too Many Requests).")
    ]

    for title, text in demo_pocs:
        story.append(KeepTogether([
            Paragraph(f"<b>{title}</b>", h2_style),
            Paragraph(text, body_style)
        ]))

    story.append(Spacer(1, 8))

    # Bloque 4: Conclusión (30 segundos a 1 minuto)
    story.append(Paragraph("BLOQUE 4: Conclusión y Cierre (30 segundos a 1 minuto)", h1_style))
    story.append(Paragraph("<b>[ESCENA]:</b> Integrantes vuelven a salir a cuadro (cámara encendida).", cue_style))

    conc_speech = """<b>«Guión hablado:»</b><br/>
<i>"<b>Alcance logrado:</b> MetaGuard cumplió con éxito el 100% de los requerimientos de la materia. Implementamos una arquitectura en AWS de 3 capas, autenticación robusta con MFA, sandbox Docker aislado, más de 770 pruebas automatizadas con 90% de cobertura y escaneo estático CodeQL en 0 vulnerabilidades críticas.<br/>
<b>Limitaciones actuales:</b> El procesamiento concurrente está acotado al hardware de las instancias actuales (t3.micro/small) y dependemos de la cuota de la API pública de VirusTotal.<br/>
<b>Mejoras futuras:</b> Implementar colas asíncronas con Amazon SQS y workers autoescalables en ECS/Kubernetes, además de incorporar un motor sandbox dinámico propio para análisis de comportamiento de malware.<br/>
Muchas gracias por su atención."</i>"""
    
    quote_table2 = Table([[Paragraph(conc_speech, speech_style)]], colWidths=[504])
    quote_table2.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#10b981')),
        ('PADDING', (0,0), (-1,-1), 7),
    ]))
    story.append(quote_table2)
    story.append(Spacer(1, 10))

    # Checklist antes de subir
    story.append(Paragraph("CHECKLIST OBLIGATORIO ANTES DE ENVIAR (Para asegurar los 100 puntos)", h1_style))
    checklist_data = [
        [Paragraph("&bull; <b>Video en formato horizontal a 1080p:</b> Cámara nítida y pantalla visible a pantalla completa.", table_cell)],
        [Paragraph("&bull; <b>Audio claro y sin música de fondo alta:</b> La voz debe escucharse con total nitidez.", table_cell)],
        [Paragraph("&bull; <b>Duración cronometrada entre 3 y 6 minutos:</b> Ni menos de 3 min ni más de 6 min.", table_cell)],
        [Paragraph("&bull; <b>Todos los integrantes salen a cuadro:</b> Al inicio (presentación) y al final (conclusión).", table_cell)],
        [Paragraph("&bull; <b>Configuración de Google Drive:</b> Subir el archivo .mp4, hacer clic derecho > <i>Compartir</i> > <b>«Cualquier persona con el enlace (Lector)»</b>. (<i>Advertencia del docente: si no hay permiso, la actividad se califica con 0</i>).", table_cell)]
    ]
    check_table = Table(checklist_data, colWidths=[504])
    check_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#fef3c7')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#f59e0b')),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(check_table)

    # Build
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"U4 Video PDF generated at: {filename}")

if __name__ == "__main__":
    out_path = r"C:\Users\jaras\Downloads\MetaGuard_Guion_Video_U4.pdf"
    build_pdf(out_path)
