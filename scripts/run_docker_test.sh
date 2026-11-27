#!/bin/bash
sudo docker run --rm -v /tmp/test.pdf:/test.pdf metaguard-processor@sha256:028083dbd3c025359280d4075b83f30b5b98012d7bdb7136964898e021c86925 python - << 'EOF'
import sys
try:
    from metaguard_api.file_processing import process_file
    with open('/test.pdf', 'rb') as f:
        data = f.read()
    res = process_file(data, 'application/pdf')
    print("DOCKER PROCESS RESULT:")
    print("Cleaned size:", len(res.cleaned_bytes))
    print("Categories:", res.metadata.categories)
    print("Links:", res.removed_pdf_links)
except Exception as e:
    import traceback
    traceback.print_exc()
EOF
