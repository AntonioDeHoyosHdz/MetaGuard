from io import BytesIO
import json
from pathlib import Path
from xml.sax.saxutils import escape

from pypdf import PdfReader, PdfWriter
from pypdf.generic import ContentStream, FloatObject, NameObject, TextStringObject
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph, Table, TableStyle


ROOT=Path(__file__).resolve().parent
OUT=ROOT.parent/'output/pdf'
source=OUT/'MetaGuard_Reporte_Final_Actualizado.pdf'
destination=OUT/'MetaGuard_Reporte_Final_Blanco_y_Negro.pdf'
team=[('Antonio de Hoyos Hernández','243776','No consignado'),
      ('Binaud Jimenez Jaitovich','243776','No consignado'),
      ('Luis Emilio Jaras Sánchez','243697','243697@ids.upchiapas.edu.mx')]
evidence=json.loads((ROOT/'evidence.json').read_text(encoding='utf-8'))
BE,FE=evidence[1],evidence[0]
assert [FE['results'],BE['results']]==[0,8]

FONTS=Path('C:/Windows/Fonts')
for name, file in {'Georgia':'georgia.ttf','GeorgiaBold':'georgiab.ttf','Cal':'calibri.ttf',
                   'CalBold':'calibrib.ttf','Code':'consola.ttf'}.items():
    pdfmetrics.registerFont(TTFont(name,str(FONTS/file)))
pdfmetrics.registerFontFamily('Georgia',normal='Georgia',bold='GeorgiaBold')
pdfmetrics.registerFontFamily('Cal',normal='Cal',bold='CalBold')
BLACK=colors.HexColor('#1d1d1d'); DARK=colors.HexColor('#353535'); GRAY=colors.HexColor('#555555')
LINE=colors.HexColor('#cfcfcf'); PALE=colors.HexColor('#f3f3f3'); WHITE=colors.white
W,H=A4
L=R=58
CW=W-L-R
STYLE={}
for key,face,size,leading,color in [
    ('title','GeorgiaBold',28,33,BLACK),('cover','GeorgiaBold',59,68,BLACK),
    ('deck','Georgia',19,27,DARK),('section','GeorgiaBold',14,18,BLACK),
    ('body','Georgia',10.5,15.3,BLACK),('small','Cal',9.3,12.6,GRAY),
    ('head','CalBold',10,13,WHITE),('cell','Cal',10,13.2,BLACK),
    ('mono','Code',8.7,12,DARK),('lead','Georgia',12,17,BLACK),
]:
    STYLE[key]=ParagraphStyle(key,fontName=face,fontSize=size,leading=leading,textColor=color,splitLongWords=True)

buf=BytesIO(); c=canvas.Canvas(buf,pagesize=A4,pageCompression=1); y=0


def line(x,yy,x2,yy2,color=LINE,width=.65):
    c.setStrokeColor(color); c.setLineWidth(width); c.line(x,yy,x2,yy2)


def box(x,top,w,h,fill=PALE):
    c.setFillColor(fill);c.rect(x,top-h,w,h,stroke=0,fill=1)


def label(txt,x,yy,fill=DARK):
    c.setFillColor(fill);c.setFont('CalBold',10);c.drawString(x,yy,txt)


def paragraph(txt,x,yy,w,style):
    p=Paragraph(txt,STYLE[style]);_,h=p.wrap(w,H);p.drawOn(c,x,yy-h);return yy-h


def p(txt,style='body',gap=10):
    global y
    y=paragraph(txt,L,y,CW,style)-gap
    assert y>58


def h(txt):
    p(txt,'section',8)


def start(tag,title,detail=None):
    global y
    label('METAGUARD',L,H-42)
    c.setFillColor(GRAY);c.setFont('Cal',9.5);c.drawRightString(W-R,H-42,'REPORTE FINAL DEL PROYECTO')
    line(L,H-53,W-R,H-53)
    label(tag,L,H-79)
    y=H-94
    p(title,'title',14)
    if detail:p(detail,'small',13)


def end(n):
    line(L,44,W-R,44)
    c.setFillColor(GRAY);c.setFont('Cal',9)
    c.drawString(L,29,'Seguridad Informática  ·  Universidad Politécnica de Chiapas')
    c.drawRightString(W-R,29,f'{n:02d} / 12')
    c.showPage()


def table(headers,rows,widths,pad=7):
    global y
    cells=[[Paragraph(x,STYLE['head']) for x in headers]] + [[Paragraph(x,STYLE['cell']) for x in row] for row in rows]
    t=Table(cells,colWidths=widths,repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),DARK),('ROWBACKGROUNDS',(0,1),(-1,-1),[PALE,WHITE]),
        ('LINEBELOW',(0,1),(-1,-1),.4,LINE),('VALIGN',(0,0),(-1,-1),'TOP'),
        ('LEFTPADDING',(0,0),(-1,-1),9),('RIGHTPADDING',(0,0),(-1,-1),9),
        ('TOPPADDING',(0,0),(-1,-1),pad),('BOTTOMPADDING',(0,0),(-1,-1),pad),
    ]))
    _,ht=t.wrap(CW,H); y-=ht
    assert y>58
    t.drawOn(c,L,y);y-=13


def note(title,body):
    global y
    b=Paragraph(body,STYLE['cell']);_,bh=b.wrap(CW-28,H)
    box(L,y,CW,bh+47,PALE);box(L,y,3,bh+47,DARK)
    label(title,L+14,y-17)
    b.drawOn(c,L+14,y-27-bh)
    y-=bh+58


def link(url,label):
    return f'<a href="{escape(url)}" color="#303030"><u>{escape(label)}</u></a>'


# Replacement cover, rendered as a dedicated one-page design.
box(0,H,W,H,WHITE);box(L,H-92,5,63,BLACK)
paragraph('Universidad Politécnica de Chiapas',L+18,H-99,CW-18,'section')
paragraph('Ingeniería en Tecnologías de la Información e Innovación Digital',L+18,H-127,CW-18,'small')
label('SEGURIDAD INFORMÁTICA',L+18,H-155)
label('REPORTE FINAL DEL PROYECTO',L,H-235)
paragraph('MetaGuard',L,H-253,CW,'cover')
paragraph('Protección de la privacidad en fotografías y documentos PDF',L,H-337,CW-20,'deck')
paragraph('Aplicación web y API REST para el análisis y la limpieza de metadatos',L,H-417,CW,'body')
line(L,311,W-R,311)
label('INTEGRANTES',L,286)
for i,(name,id_,_) in enumerate(team):
    paragraph(f'<b>{escape(name)}</b> <font color="#565656">· {id_}</font>',L,270-i*20,CW,'lead')
label('DOCENTE',L,188)
paragraph('M.C. José Alonso Macías Montoya',L,174,CW,'body')
label('CHIAPAS, MÉXICO',L,91)
paragraph('23 de noviembre de 2026',L,77,CW,'body')
c.showPage()

start('FICHA DE IDENTIFICACIÓN  ·  SECCIONES I Y II','Datos de entrega y acceso')
table(['Integrante','Matrícula','Correo institucional','Rol'],[(name,id_,mail,'Integrante') for name,id_,mail in team],[171,60,163,CW-394])
p('<b>Programa:</b> Ingeniería en Tecnologías de la Información e Innovación Digital. '
  '<b>Asignatura:</b> Seguridad Informática. <b>Equipo o grupo:</b> no consignado. '
  '<b>Fecha del reporte:</b> 23 de noviembre de 2026.','small')
h('I. Control de acceso y enlaces')
repo='https://github.com/AntonioDeHoyosHdz/MetaGuard'
table(['Recurso','Acceso','Alcance'],[
  ('Código fuente',link(repo,'Repositorio público de MetaGuard')+'<br/>'+link(repo+'/tree/feat/frontend-visual','Rama feat/frontend-visual'),
   'La rama de trabajo contiene la implementación. Los registros del ensayo complementan al código publicado.'),
  ('Aplicación web',link('https://metaguard.duckdns.org/','metaguard.duckdns.org'),
   'Presentación HTTPS. Procesamiento de archivos y prueba de registro con acceso restringido.'),
  ('Video demostrativo','<b>Anexo MP4</b><br/>MetaGuard_Video_BN.mp4',
   'Interfaz, limpieza de una muestra sintética y resultados observados, con voz y subtítulos en español.'),
],[103,167,CW-270])
h('II. Declaración de licencia')
p('<b>Licencia MIT.</b> El archivo <font face="Code">LICENSE</font> del repositorio establece los avisos del código. '
  'La licencia permite usar, modificar y redistribuir el software conservando los avisos de copyright y permiso. '
  'Se eligió para facilitar la revisión y reutilización académica. Cada dependencia conserva su licencia '
  '(Open Source Initiative, s. f.).')
h('Guía de lectura')
for section in ['III. Resumen y objetivos · 3–4','IV. Arquitectura y API · 5–6','V. Seguridad y evidencias · 7–9',
                'Conclusiones y referencias · 10–11','Anexo. Comprobantes de escaneos y pruebas · 12']:
    p(section,'small',4)
end(2)

start('SECCIÓN V  ·  EVIDENCIAS TÉCNICAS','Resultados de seguridad',
      'El prototipo tiene evidencia de pruebas automatizadas, revisión de código y un recorrido privado de principio a fin con archivos sintéticos.')
h('Ensayos con resultados comprobados')
table(['Evidencia','Resultado','Qué acredita'],[
  ('Backend e interfaz','729 y 87 pruebas aprobadas','Dos cortes distintos de prueba. El registro de backend indica seis pruebas optativas omitidas.'),
  ('Comprobación enfocada','50 pruebas aprobadas','Se repitieron los controles de registro, configuración aislada y límites de intentos.'),
  ('Corpus sintético','61 comprobaciones; 30 huellas','Evaluación de JPG, PNG y PDF inertes; escenarios simulados de política de contraseñas.'),
  ('PNG en AWS privado','Autor retirado; píxeles conservados','La copia limpia preservó la imagen visible. Un segundo intento no consiguió descargar el archivo.'),
  ('Correo real de registro','Recepción confirmada','El participante recibió el correo en el ensayo restringido.'),
],[131,128,CW-259])
h('Análisis estático CodeQL')
note('Frontend sin resultados automáticos en el corte analizado', 'El archivo SARIF registra 12 archivos JavaScript/TypeScript y 0 resultados automáticos. '
     'En Python se registraron 75 archivos y 8 resultados para revisión. El anexo muestra sus huellas y los conteos originales.')
p('<b>Corrección comprobada.</b> La revisión independiente identificó metadatos privados residuales en un PDF sintético. '
  'Se ajustó el limpiador y su verificación. La regla específica pasó de un resultado a cero en ese caso.')
p('<b>Observaciones.</b> Los resultados automáticos no equivalen a vulnerabilidades confirmadas ni a una certificación. '
  'Queda confirmar el canje y el acceso de la cuenta real y completar la evaluación operativa y de dependencias.','small')
end(9)

start('ANEXO  ·  COMPROBANTES','Evidencia de escaneos y pruebas',
      'Extracto de los SARIF originales del corte de CodeQL con historial y alertas. No se reproducen rutas privadas, mensajes ni trazas.')
h('A. Análisis estático de código')
table(['Alcance','Archivos','Resultados automáticos','Corte'],[
   (FE['language'],str(FE['files']),'<b>0</b>',f"{FE['tool']} {FE['version']}"),
   (BE['language'],str(BE['files']),'<b>8</b>',f"{BE['tool']} {BE['version']}"),
],[155,58,151,CW-364])
p('Se analizaron archivos de código con la suite instalada, sin compilar MetaGuard. La revisión técnica explicó los resultados '
  'y registró sus límites. Los conteos se volvieron a extraer de los dos SARIF; no son estimaciones.','body')
for row in evidence:
    p(f'<b>{escape(row["source"])}</b> · SHA-256 del archivo original','cell',4)
    p(row['sha256'].upper(),'mono',11)
h('B. Comprobación local adicional')
table(['Comprobación','Resultado observado'],[
  ('Pruebas de registro, staging y límites','<b>50 aprobadas</b> con servicios simulados.'),
  ('Ruff · análisis de código','<b>Correcto</b> en el backend.'),
  ('Ruff · comprobación de formato','<b>134 archivos</b> ya formateados correctamente.'),
],[232,CW-232],pad=8)
note('Alcance de los comprobantes', 'CodeQL revisa código. Ruff comprueba convenciones y varios problemas de código; no sustituye un escaneo de seguridad. '
     'Los resultados de laboratorio no prueban protección absoluta ni equivalen a pruebas contra el entorno público.')
p('Fuentes: artefactos SARIF del equipo e informe de seguridad CodeQL; repetición local de pruebas enfocadas de MetaGuard.','small')
end(12)
c.save()

patch=PdfReader(BytesIO(buf.getvalue()))
w=PdfWriter(clone_from=source)
for dest,src in zip((0,1,8),patch.pages):
    pg=w.pages[dest]
    for key in ('/Contents','/Resources'):
        pg[NameObject(key)]=src.raw_get(key).clone(w)
    if '/Annots' in src: pg[NameObject('/Annots')]=src.raw_get('/Annots').clone(w)
    elif '/Annots' in pg: del pg[NameObject('/Annots')]
w.add_page(patch.pages[3])
w.add_outline_item('Anexo de escaneos y pruebas',11)
w.add_metadata({'/Title':'MetaGuard | Reporte final y evidencia de seguridad',
                '/Author':', '.join(n for n,_,_ in team)})


def replace_current_folio(ops,page):
    old, target=f'{page:02} / 11',f'{page:02} / 12'
    for a,op in ops:
        if op in (b'Tj',b"'") and a and str(a[-1])==old:
            a[-1]=TextStringObject(target)


for n,pg in enumerate(w.pages,1):
    cs=ContentStream(pg['/Contents'],w)
    ops=[]
    for values,op in cs.operations:
        if op in (b'rg',b'RG') and len(values)==3:
            v=.2126*float(values[0])+.7152*float(values[1])+.0722*float(values[2])
            values=[FloatObject(round(v,6))];op=b'g' if op==b'rg' else b'G'
        elif op in (b'k',b'K') and len(values)==4:
            cyan,magenta,yellow,k=map(float,values)
            v=(1-k)*(1-.2126*cyan-.7152*magenta-.0722*yellow)
            values=[FloatObject(round(v,6))];op=b'g' if op==b'k' else b'G'
        ops.append((values,op))
    replace_current_folio(ops,n)
    cs.operations=ops
    pg.replace_contents(cs)

img=w.pages[7].images[0]
img.replace(img.image.convert('L'),quality=94)
with destination.open('wb') as stream:
    w.write(stream)
chk=PdfReader(destination)
assert len(chk.pages)==12
assert 'Binaud Jimenez Jaitovich' in chk.pages[0].extract_text()
assert chk.pages[1].extract_text().count('243776')==2
assert sum(len(page.images) for page in chk.pages)==1
assert 'Comprobación local adicional' in chk.pages[-1].extract_text()
assert '08 / 12' in chk.pages[7].extract_text()
print('reporte=12_paginas_portada_con_equipo_grises_anexo_SARIF_y_pruebas_locales')
