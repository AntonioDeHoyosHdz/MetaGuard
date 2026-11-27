"""Exercise a synthetic login alert with a non-relaying loopback SMTP sink."""

from dataclasses import replace
from email import message_from_bytes, policy
from queue import Queue
from socketserver import StreamRequestHandler, ThreadingTCPServer
from threading import Thread
from time import monotonic

from fastapi.testclient import TestClient
from test_auth_routes import ORIGIN, make_client, preauth
from test_auth_routes import auth_env as auth_env

from metaguard_api.local_runtime import _CaptureEmailSender
from metaguard_api.main import create_app
from metaguard_api.security_alerts import SECURITY_ALERT_SUBJECT


class _Sink(ThreadingTCPServer):
    daemon_threads = True

    def __init__(self):
        self.messages: Queue[bytes] = Queue(maxsize=4)
        super().__init__(("127.0.0.1", 0), _SinkHandler)


class _SinkHandler(StreamRequestHandler):
    timeout = 4

    def handle(self):
        self.wfile.write(b"220 local synthetic capture\r\n")
        for _ in range(12):
            line = self.rfile.readline(1024)
            command = line.upper()
            if command.startswith((b"EHLO ", b"HELO ", b"MAIL FROM:", b"RCPT TO:")):
                self.wfile.write(b"250 accepted locally\r\n")
            elif command == b"DATA\r\n":
                self.wfile.write(b"354 capture message\r\n")
                message = bytearray()
                while len(message) <= 4096:
                    data = self.rfile.readline(1024)
                    if data == b".\r\n":
                        self.server.messages.put_nowait(bytes(message))
                        self.wfile.write(b"250 captured locally\r\n")
                        break
                    if not data:
                        return
                    message.extend(data)
                else:
                    return
            elif command == b"QUIT\r\n":
                self.wfile.write(b"221 ending capture\r\n")
                return
            else:
                return


def test_new_address_activity_reaches_synthetic_smtp_without_personal_payload(auth_env):
    seed, _ = make_client(auth_env)
    with _Sink() as sink:
        listener = Thread(target=sink.serve_forever, daemon=True)
        listener.start()
        try:
            capture = _CaptureEmailSender(sink.server_address[1])
            auth = replace(
                seed.app.state.auth_runtime,
                login_risk_enabled=True,
                email_sender=capture,
            )
            app = create_app(
                seed.app.state.settings, auth_runtime=auth, security_alert_sender=capture
            )
            credentials = {"email": auth_env["email"], "password": auth_env["password"]}

            def login(client):
                return client.post(
                    "/v1/auth/login",
                    headers={"Origin": ORIGIN, "X-CSRF-Token": preauth(client)},
                    json=credentials,
                )

            with TestClient(
                app, base_url="https://api.example", client=("127.0.0.1", 10001)
            ) as first:
                assert login(first).json()["authenticated"] is True
                assert sink.messages.empty()
                second = TestClient(
                    app, base_url="https://api.example", client=("127.0.0.2", 10002)
                )
                try:
                    started = monotonic()
                    result = login(second)
                    assert result.json()["authenticated"] is True
                    history = second.get(
                        "/v1/security/events",
                        headers={"Origin": ORIGIN, "X-CSRF-Token": result.json()["csrf_token"]},
                    )
                    assert [event["kind"] for event in history.json()["events"]] == ["new_ip_login"]
                    message = message_from_bytes(
                        sink.messages.get(timeout=12), policy=policy.default
                    )
                    assert monotonic() - started < 60
                    assert message["Subject"] == SECURITY_ALERT_SUBJECT
                    assert message["To"] == credentials["email"]
                    body = message.get_content()
                    for value in (
                        credentials["email"],
                        credentials["password"],
                        "127.0.0.2",
                        "https://",
                    ):
                        assert value not in body
                finally:
                    second.close()
        finally:
            sink.shutdown()
            listener.join(timeout=2)
            seed.close()
