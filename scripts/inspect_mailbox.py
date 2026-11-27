import imaplib, email

pw = open("/etc/metaguard-mail-smoke/gmail_app_password").read().strip()
mail = imaplib.IMAP4_SSL("imap.gmail.com")
mail.login("jarassanchezl@gmail.com", pw)
mail.select("INBOX")
status, data = mail.search(None, "ALL")
msg_ids = data[0].split()
for mid in msg_ids[-10:]:
    status, mdata = mail.fetch(mid, "(RFC822)")
    msg = email.message_from_bytes(mdata[0][1])
    subj = msg.get("Subject")
    to = msg.get("To")
    date = msg.get("Date")
    print(f"To: {to} | Subj: {subj} | Date: {date}")
mail.logout()
