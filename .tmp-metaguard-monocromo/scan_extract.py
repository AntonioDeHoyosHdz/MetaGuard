import hashlib
import json
from pathlib import Path

out=Path(__file__).resolve().parent
temp=Path.home()/'AppData/Local/Temp'
sources=[
 ('JavaScript / TypeScript', 'metaguard-t2-codeql-frontend-2a28e20daadb44ceb5f16305ca70f239/frontend.sarif',
  'b8d26ebf3614fe702f3e3566a6d6251569104069df3c3e2f155540350e86781f'),
 ('Python', 'metaguard-t2-codeql-python-e178c1602e4b40efa6fa35befcc97a47/backend.sarif',
  '0c14171f9aec64ca77a9be70212a7b194d11b3b633fde fd4f2b042f33287225f'.replace(' ','')),
]
evidence=[]
for language,relative,expected in sources:
    p=temp/relative
    payload=p.read_bytes()
    fingerprint=hashlib.sha256(payload).hexdigest()
    assert fingerprint==expected
    runs=json.loads(payload)['runs']
    assert len(runs)==1
    run=runs[0]
    driver=run['tool']['driver']
    item=dict(language=language, tool=driver['name'], version=driver.get('semanticVersion') or driver['version'],
              files=len(run.get('artifacts',[])), results=len(run.get('results',[])),
              rules=len(driver.get('rules',[])), sha256=fingerprint, source=p.name)
    evidence.append(item)
    print({k:v for k,v in item.items() if k not in ('sha256',)})

assert [(e['files'],e['results']) for e in evidence]==[(12,0),(75,8)]
(out/'evidence.json').write_text(json.dumps(evidence,indent=2,ensure_ascii=False),encoding='utf-8')
