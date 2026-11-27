from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

root=Path(__file__).resolve().parent
fonts=Path('C:/Windows/Fonts')
regular=lambda size: ImageFont.truetype(str(fonts/'calibri.ttf'),size)
bold=lambda size: ImageFont.truetype(str(fonts/'calibrib.ttf'),size)
base=Image.open(root/'base-12.png').convert('RGB')
team=Image.new('RGBA',base.size,(0,0,0,0)); draw=ImageDraw.Draw(team)
value=base.getpixel((39,581))[0]
draw.rectangle((35,510,662,600),fill=(value,value,value,255))
for i,row in enumerate(['Antonio de Hoyos Hernández','Binaud Jimenez Jaitovich','Luis Emilio Jaras Sánchez']):
    draw.text((57,516+i*25),row,font=regular(22),fill=(245,245,245,255))
team.save(root/'credits.png')

base=Image.open(root/'base-168.png').convert('RGB')
overlay=Image.new('RGBA',base.size,(0,0,0,0)); draw=ImageDraw.Draw(overlay)
value=base.getpixel((35,593))[0]
draw.rectangle((51,526,1232,604),fill=(value,value,value,255))
draw.rounded_rectangle((57,532,1220,599),12,fill=(224,224,224,255),outline=(165,165,165,255),width=1)
draw.text((75,543),'ESCANEO ESTÁTICO · CODEQL 2.27.4',font=bold(18),fill=(32,32,32,255))
draw.text((75,570),'Frontend: 12 archivos, 0 resultados   |   Python: 75 archivos, 8 resultados automáticos',font=regular(22),fill=(32,32,32,255))
overlay.save(root/'scans.png')
