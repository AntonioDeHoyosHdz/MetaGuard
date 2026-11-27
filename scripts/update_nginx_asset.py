with open("/etc/metaguard-public/nginx.conf") as f:
    c = f.read()
target = "location = /assets/index-CrVQpme_.js"
replacement = "location = /assets/index-4Ii527cJ.js { if ($request_method !~ \"^(GET|HEAD)$\") { return 405; } alias /opt/metaguard-public/frontend/assets/index-4Ii527cJ.js; }\n        location = /assets/index-CrVQpme_.js"
if "index-4Ii527cJ.js" not in c:
    c = c.replace(target, replacement)
    with open("/etc/metaguard-public/nginx.conf", "w") as f:
        f.write(c)
    print("Updated nginx.conf")
else:
    print("Already present")
