import imaplib, email, re, sys, time

def fetch_latest_code(target_email, code_type="verify", timeout=35):
    pw = open("/etc/metaguard-mail-smoke/gmail_app_password").read().strip()
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            mail = imaplib.IMAP4_SSL("imap.gmail.com")
            mail.login("jarassanchezl@gmail.com", pw)
            mail.select("INBOX")
            status, data = mail.search(None, "ALL")
            msg_ids = data[0].split()
            for mid in reversed(msg_ids[-20:]):
                status, mdata = mail.fetch(mid, "(RFC822)")
                msg = email.message_from_bytes(mdata[0][1])
                to_hdr = str(msg.get("To", "")).lower()
                subj = str(msg.get("Subject", ""))
                body = ""
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body = part.get_payload(decode=True).decode(errors="ignore")
                
                clean_target = target_email.lower()
                if clean_target in to_hdr or clean_target in body:
                    if code_type == "verify" and ("Verifica tu correo" in subj or "código de verificación" in body.lower()):
                        m = re.search(r"Código de verificación:\s*([A-Za-z0-9_-]{43})", body)
                        if m:
                            mail.logout()
                            return m.group(1)
                    elif code_type == "reset" and ("Restablece tu" in subj or "restablecimiento" in body.lower()):
                        m = re.search(r"\b([0-9a-f]{32})\b", body)
                        if m:
                            mail.logout()
                            return m.group(1)
            mail.logout()
        except Exception:
            pass
        time.sleep(2)
    return None

if __name__ == "__main__":
    email_arg = sys.argv[1]
    type_arg = sys.argv[2] if len(sys.argv) > 2 else "verify"
    code = fetch_latest_code(email_arg, type_arg, timeout=35)
    print("CODE:" + (code or "NONE"))
