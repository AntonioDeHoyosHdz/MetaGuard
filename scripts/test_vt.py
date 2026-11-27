import urllib.request
import json
import sys

with open('/etc/metaguard-staging/auth/virustotal_api_key') as f:
    key = f.read().strip()

hashes = [
    ("EICAR_KNOWN_MALWARE", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"),
    ("USER_PHOTO_NEW_HASH", "a071361e5abde35f5d0acdf6f45d37231902233f3b2df4d8e30aac816a66f19d"),
]

for name, h in hashes:
    url = f"https://www.virustotal.com/api/v3/files/{h}"
    req = urllib.request.Request(url, headers={"x-apikey": key, "User-Agent": "MetaGuard/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=8) as res:
            data = json.loads(res.read().decode('utf-8'))
            stats = data['data']['attributes']['last_analysis_stats']
            print(f"{name}: HTTP 200 FOUND -> Malicious={stats.get('malicious')}, Suspicious={stats.get('suspicious')}, Harmless={stats.get('harmless')}")
    except urllib.error.HTTPError as e:
        print(f"{name}: HTTP {e.code} -> {e.read().decode('utf-8')[:120]}")
