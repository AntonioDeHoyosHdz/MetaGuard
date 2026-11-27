import smtplib
import ssl
import traceback
from email import policy
from email.parser import BytesParser
from unittest.mock import patch

import pytest

from metaguard_api.gmail_sender import GmailDeliveryError, GmailSender
from metaguard_api.secrets import SecretStore, SecretUnavailable

SENDER = "metaguard.mailbox@gmail.com"
RECIPIENT = "member+verification@example.net"
APP_PASSWORD = "abcd1234abcd1234"
TOKEN = "aB0-" * 10 + "_23"


@pytest.fixture
def gmail(tmp_path):
    (tmp_path / "gmail_app_password").write_text(f"{APP_PASSWORD}\n", encoding="utf-8")
    with patch("smtplib.SMTP_SSL") as connect:
        transport = connect.return_value.__enter__.return_value
        transport.send_message.return_value = {}
        sender = GmailSender(sender_email=SENDER, secret_store=SecretStore(tmp_path))
        connect.assert_not_called()
        yield sender, connect, transport


def test_sends_verification_email_over_authenticated_tls(gmail):
    sender, connect, transport = gmail

    sender.send_verification(RECIPIENT, TOKEN)

    connect.assert_called_once()
    assert connect.call_args.args == ("smtp.gmail.com", 465)
    assert connect.call_args.kwargs["timeout"] == 10
    context = connect.call_args.kwargs["context"]
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert [name for name, _, _ in transport.method_calls] == ["login", "send_message"]
    transport.login.assert_called_once_with(SENDER, APP_PASSWORD)
    args, kwargs = transport.send_message.call_args
    assert kwargs == {"from_addr": SENDER, "to_addrs": [RECIPIENT]}
    (message,) = args
    assert message["From"] == SENDER
    assert message["To"] == RECIPIENT
    assert APP_PASSWORD not in message.as_string()
    assert APP_PASSWORD not in repr(sender)
    assert SENDER not in repr(sender)


def test_verification_email_offers_matching_spanish_html_and_plain_text(gmail):
    sender, _, transport = gmail

    sender.send_verification(RECIPIENT, TOKEN)

    (outbound,) = transport.send_message.call_args.args
    message = BytesParser(policy=policy.default).parsebytes(outbound.as_bytes(policy=policy.SMTP))
    assert message["Subject"] == "MetaGuard | Verifica tu correo"
    assert message.get_content_type() == "multipart/alternative"
    assert [part.get_content_type() for part in message.iter_parts()] == ["text/plain", "text/html"]
    assert not list(message.iter_attachments())
    plain = message.get_body(preferencelist=("plain",)).get_content()
    html = message.get_body(preferencelist=("html",)).get_content()
    assert TOKEN in plain.splitlines()
    assert f">{TOKEN}</code>" in html
    for content in (plain, html):
        assert content.count(TOKEN) == 1
        assert "Verifica tu correo" in content
        assert "Tengo un código de verificación" in content
        assert "selecciona «Verificar correo»" in content
        assert "temporal y solo se puede usar una vez" in content
        assert "ignora este mensaje" in content
        assert "http" not in content
    for content in (str(message["Subject"]), plain, html):
        for private_value in (APP_PASSWORD, SENDER, RECIPIENT):
            assert private_value not in content
    assert TOKEN not in message["Subject"]
    assert '<html lang="es">' in html
    for external_surface in ("<img", "<script", "<a ", "src=", "href=", "url("):
        assert external_surface not in html


def test_password_reset_email_has_a_distinct_subject_and_a_code_without_links(gmail):
    sender, connect, transport = gmail
    code = "0a" * 16
    with pytest.raises(ValueError, match="Invalid password reset email"):
        sender.send_password_reset(RECIPIENT, f"{code}\n")
    connect.assert_not_called()

    sender.send_password_reset(RECIPIENT, code)

    (outbound,) = transport.send_message.call_args.args
    message = BytesParser(policy=policy.default).parsebytes(outbound.as_bytes(policy=policy.SMTP))
    assert message["Subject"] == "MetaGuard | Restablece tu contraseña"
    assert message.get_content_type() == "text/plain"
    text = message.get_content()
    assert text.count(code) == 1
    assert code in text.splitlines()
    assert "15 minutos" in text
    assert all(value not in text for value in (APP_PASSWORD, SENDER, RECIPIENT, "http"))


@pytest.mark.parametrize("email", ["bad", "Name <a@example.net>", "a@b, c@d", "a@b\r\nCc: c@d"])
def test_rejects_malformed_recipient_without_connecting(gmail, email):
    sender, connect, _ = gmail
    with pytest.raises(ValueError, match="Invalid verification recipient"):
        sender.send_verification(email, TOKEN)
    connect.assert_not_called()


@pytest.mark.parametrize("token", ["invalid", "a" * 42 + "\n", "a" * 42 + "\ud800"])
def test_rejects_malformed_token_without_connecting(gmail, token):
    sender, connect, _ = gmail
    with pytest.raises(ValueError, match="Invalid verification code"):
        sender.send_verification(RECIPIENT, token)
    connect.assert_not_called()


@pytest.mark.parametrize(
    "address", ["member@example.net", "member+tag@gmail.com", "Member@gmail.com", "a..b@gmail.com"]
)
def test_sender_must_be_a_canonical_gmail_account(tmp_path, address):
    with pytest.raises(ValueError, match="Invalid Gmail sender address") as error:
        GmailSender(sender_email=address, secret_store=SecretStore(tmp_path))
    assert address not in str(error.value)


def test_requires_allowlisted_secret_file(tmp_path):
    (tmp_path / "smtp_credentials").write_text(APP_PASSWORD, encoding="utf-8")
    with pytest.raises(SecretUnavailable, match="gmail_app_password"):
        GmailSender(sender_email=SENDER, secret_store=SecretStore(tmp_path))


def test_rejects_invalid_app_password_without_disclosing_it(tmp_path):
    invalid_pass = "not-an-app-password"
    (tmp_path / "gmail_app_password").write_text(invalid_pass, encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid Gmail app password") as error:
        GmailSender(sender_email=SENDER, secret_store=SecretStore(tmp_path))
    assert invalid_pass not in str(error.value)


@pytest.mark.parametrize("stage", ["connection", "login", "submission", "refusal"])
def test_delivery_failure_does_not_retry_or_expose_sensitive_details(gmail, stage, caplog):
    sender, connect, transport = gmail
    provider_reply = f"{SENDER} {RECIPIENT} {APP_PASSWORD} {TOKEN}".encode("ascii")
    if stage == "connection":
        connect.side_effect = OSError(provider_reply)
    if stage == "login":
        transport.login.side_effect = smtplib.SMTPAuthenticationError(535, provider_reply)
    if stage == "submission":
        transport.send_message.side_effect = smtplib.SMTPDataError(554, provider_reply)
    if stage == "refusal":
        transport.send_message.return_value = {RECIPIENT: (550, provider_reply)}

    with pytest.raises(GmailDeliveryError, match="Verification email could not be sent") as error:
        sender.send_verification(RECIPIENT, TOKEN)

    connect.assert_called_once()
    assert transport.login.call_count <= 1
    assert transport.send_message.call_count <= 1
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    rendered_error = "".join(traceback.format_exception(error.value))
    for secret in (SENDER, RECIPIENT, APP_PASSWORD, TOKEN):
        assert secret not in rendered_error
        assert secret not in caplog.text


def test_quit_failure_does_not_undo_accepted_message(gmail):
    sender, connect, transport = gmail
    connect.return_value.__exit__.side_effect = TimeoutError()

    sender.send_verification(RECIPIENT, TOKEN)

    transport.send_message.assert_called_once()


def test_security_alert_is_a_generic_spanish_notice_without_links_or_credentials(gmail):
    sender, connect, transport = gmail
    with pytest.raises(ValueError, match="Invalid security alert recipient"):
        sender.send_security_alert("x@example.net\r\nCc: other@example.net")
    connect.assert_not_called()

    sender.send_security_alert(RECIPIENT)
    (outbound,) = transport.send_message.call_args.args
    assert transport.send_message.call_args.kwargs == {"from_addr": SENDER, "to_addrs": [RECIPIENT]}
    message = BytesParser(policy=policy.default).parsebytes(outbound.as_bytes(policy=policy.SMTP))
    assert message["Subject"] == "MetaGuard | Alerta de seguridad"
    assert message.get_content_type() == "text/plain"
    body = message.get_content()
    assert "actividad inusual" in body
    assert "historial de seguridad" in body
    assert not list(message.iter_attachments())
    assert all(value not in body for value in (SENDER, RECIPIENT, APP_PASSWORD, "http", "<", "@"))


def test_login_challenge_uses_a_distinct_link_free_five_minute_code(gmail):
    sender, connect, transport = gmail
    code = "1b" * 16
    with pytest.raises(ValueError, match="Invalid login challenge email"):
        sender.send_login_challenge(RECIPIENT, f"{code}\n")
    connect.assert_not_called()

    sender.send_login_challenge(RECIPIENT, code)
    (outbound,) = transport.send_message.call_args.args
    assert transport.send_message.call_args.kwargs == {"from_addr": SENDER, "to_addrs": [RECIPIENT]}
    message = BytesParser(policy=policy.default).parsebytes(outbound.as_bytes(policy=policy.SMTP))
    assert message["Subject"] == "MetaGuard | Código de inicio de sesión"
    assert message.get_content_type() == "text/plain"
    body = message.get_content()
    assert body.count(code) == 1 and code in body.splitlines()
    assert "5 minutos" in body and "una vez" in body
    assert all(value not in body for value in (SENDER, RECIPIENT, APP_PASSWORD, "http"))
