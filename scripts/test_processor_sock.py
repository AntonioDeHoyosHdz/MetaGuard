import socket
import json
import base64
import sys

sock_path = "/run/metaguard-staging-ipc/processor.sock"
pdf_path = "/home/ubuntu/test.pdf"

with open(pdf_path, "rb") as f:
    data = f.read()

payload = json.dumps({
    "content_type": "application/pdf",
    "data_base64": base64.b64encode(data).decode("ascii")
}).encode("utf-8")

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect(sock_path)
    s.sendall(len(payload).to_bytes(4, "big") + payload)
    
    # Read response
    resp_len_bytes = s.recv(4)
    if not resp_len_bytes:
        print("Empty response from socket")
        sys.exit(1)
    resp_len = int.from_bytes(resp_len_bytes, "big")
    resp_data = bytearray()
    while len(resp_data) < resp_len:
        chunk = s.recv(min(4096, resp_len - len(resp_data)))
        if not chunk:
            break
        resp_data.extend(chunk)
    res = json.loads(resp_data.decode("utf-8"))
    print("PROCESSOR RESPONSE KEYS:", list(res.keys()))
    if "error" in res:
        print("PROCESSOR ERROR:", res["error"])
    else:
        print("SUCCESS! Media type:", res.get("media_type"))
        print("Categories:", res.get("report", {}).get("categories"))
        print("Removed links:", res.get("removed_pdf_links"))
except Exception as e:
    print("EXCEPTION:", e)
finally:
    s.close()
