#!/bin/bash
set -e
ssh -o StrictHostKeyChecking=no ubuntu@172.31.26.1 'sudo python3 - << "EOF"
p = "/etc/metaguard-staging-db/check-guard"
with open(p) as f:
    c = f.read()

# Replace printf to have 3 newlines
c = c.replace("printf \x27%s\\n%s\x27", "printf \x27%s\\n%s\\n%s\x27")

with open(p, "w") as f:
    f.write(c)
print("UPDATED PRINTF FORMAT")
EOF
sudo /etc/metaguard-staging-db/check-guard install
echo "CHECK GUARD SUCCESSFUL"
sudo systemctl restart metaguard-staging-db-guard
sudo systemctl restart metaguard-staging-db
sudo systemctl status metaguard-staging-db --no-pager
'
