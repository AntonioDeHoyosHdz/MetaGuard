from metaguard_api.processing_client import PrivateProcessorClient
import traceback

with open('/tmp/test.pdf', 'rb') as f:
    pdf_bytes = f.read()

client = PrivateProcessorClient('/run/metaguard-staging-ipc/processor.sock', timeout=15)
try:
    res = client.process(pdf_bytes, 'application/pdf')
    print('SUCCESS: cleaned bytes =', len(res.cleaned_bytes))
    print('Categories =', res.metadata.categories)
    print('Links =', res.removed_pdf_links)
except Exception:
    traceback.print_exc()
