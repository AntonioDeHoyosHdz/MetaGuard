"""Opt-in Gmail SMTP implementation of the authentication email sender boundary."""

import re
import smtplib
import ssl
from email.errors import MessageError
from email.headerregistry import Address
from email.message import EmailMessage
from email.utils import formatdate

from metaguard_api.email_verification import _TOKEN_ALPHABET, _TOKEN_LENGTH
from metaguard_api.login_email_challenge import LOGIN_EMAIL_CODE_MINUTES, LOGIN_EMAIL_CODE_PATTERN
from metaguard_api.password_reset import RESET_CODE_MINUTES, RESET_CODE_PATTERN
from metaguard_api.secrets import SecretName, SecretStore
from metaguard_api.security_alerts import SECURITY_ALERT_SUBJECT, SECURITY_ALERT_TEXT
from metaguard_api.verification_email_message import (
    VERIFICATION_SUBJECT,
    render_verification_html,
    render_verification_text,
)

_GMAIL_MAILBOX = re.compile(r"[a-z0-9]+(?:\.[a-z0-9]+)*@gmail\.com")
_APP_PASSWORD = re.compile(r"[A-Za-z0-9]{16}")


class GmailDeliveryError(RuntimeError):
    """SMTP delivery failed without disclosure of provider details or message data."""


def _mailbox(email: str) -> Address | None:
    if (
        not isinstance(email, str)
        or not 3 <= len(email) <= 254
        or email != email.lower()
        or email.count("@") != 1
        or not email.isprintable()
    ):
        return None
    try:
        address = Address(addr_spec=email)
    except (ValueError, MessageError):
        return None
    if not address.username or not address.domain or address.addr_spec != email:
        return None
    return address


class GmailSender:
    """Send authentication emails using one operator-configured Gmail mailbox."""

    __slots__ = ("_app_password", "_sender_email")

    def __init__(self, *, sender_email: str, secret_store: SecretStore) -> None:
        if (
            not isinstance(sender_email, str)
            or len(sender_email) > 74
            or not _GMAIL_MAILBOX.fullmatch(sender_email)
        ):
            raise ValueError("Invalid Gmail sender address")
        password = secret_store.read_text(SecretName.GMAIL_APP_PASSWORD)
        if not _APP_PASSWORD.fullmatch(password):
            raise ValueError("Invalid Gmail app password")
        self._sender_email = sender_email
        self._app_password = password

    def send_verification(self, email: str, token: str) -> None:
        """Submit a verification email to the account's mailbox over implicit TLS."""
        recipient = _mailbox(email)
        if recipient is None:
            raise ValueError("Invalid verification recipient")
        if (
            not isinstance(token, str)
            or len(token) != _TOKEN_LENGTH
            or any(character not in _TOKEN_ALPHABET for character in token)
        ):
            raise ValueError("Invalid verification code")

        message = EmailMessage()
        message["From"] = self._sender_email
        message["To"] = recipient
        message["Subject"] = VERIFICATION_SUBJECT
        message["Date"] = formatdate(usegmt=True)
        message.set_content(render_verification_text(token))
        message.add_alternative(render_verification_html(token), subtype="html")
        self._deliver(message, email, failure="Verification email could not be sent")

    def send_password_reset(self, email: str, code: str) -> None:
        """Send a reset code with no password, sign-in link, or URL token."""
        recipient = _mailbox(email)
        if (
            recipient is None
            or not isinstance(code, str)
            or RESET_CODE_PATTERN.fullmatch(code) is None
        ):
            raise ValueError("Invalid password reset email")
        message = EmailMessage()
        message["From"] = self._sender_email
        message["To"] = recipient
        message["Subject"] = "MetaGuard | Restablece tu contraseña"
        message["Date"] = formatdate(usegmt=True)
        message.set_content(
            "Usa este código en la pantalla de restablecimiento de MetaGuard:\n\n"
            f"{code}\n\n"
            f"El código vence en {RESET_CODE_MINUTES} minutos y solo se puede usar una vez.\n"
            "Si no solicitaste el cambio de contraseña, ignora este mensaje.\n"
        )
        self._deliver(message, email, failure="Password reset email could not be sent")

    def send_security_alert(self, email: str) -> None:
        """Send a generic security notice without event details."""
        recipient = _mailbox(email)
        if recipient is None:
            raise ValueError("Invalid security alert recipient")
        message = EmailMessage()
        message["From"] = self._sender_email
        message["To"] = recipient
        message["Subject"] = SECURITY_ALERT_SUBJECT
        message["Date"] = formatdate(usegmt=True)
        message.set_content(SECURITY_ALERT_TEXT)
        self._deliver(message, email, failure="Security alert email could not be sent")

    def send_login_challenge(self, email: str, code: str) -> None:
        """Send a short-lived login code in a static, link-free message."""
        recipient = _mailbox(email)
        if (
            recipient is None
            or not isinstance(code, str)
            or LOGIN_EMAIL_CODE_PATTERN.fullmatch(code) is None
        ):
            raise ValueError("Invalid login challenge email")
        message = EmailMessage()
        message["From"] = self._sender_email
        message["To"] = recipient
        message["Subject"] = "MetaGuard | Código de inicio de sesión"
        message["Date"] = formatdate(usegmt=True)
        message.set_content(
            "Usa este código en la pantalla de inicio de sesión de MetaGuard:\n\n"
            f"{code}\n\n"
            f"El código vence en {LOGIN_EMAIL_CODE_MINUTES} minutos y solo se puede usar una vez.\n"
            "Si no solicitaste el código, ignora este mensaje y no lo compartas.\n"
        )
        self._deliver(message, email, failure="Login challenge email could not be sent")

    def _deliver(self, message: EmailMessage, email: str, *, failure: str) -> None:
        accepted = False
        try:
            context = ssl.create_default_context()
            context.keylog_filename = None
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=10, context=context) as smtp:
                smtp.login(self._sender_email, self._app_password)
                refused = smtp.send_message(message, from_addr=self._sender_email, to_addrs=[email])
                accepted = not refused
        except Exception:
            # A disconnect after acceptance must not turn a submitted code into a failure.
            pass

        if not accepted:
            # Raise outside the handler: transport errors may contain addresses or message data.
            raise GmailDeliveryError(failure)
