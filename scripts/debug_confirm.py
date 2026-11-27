import traceback
from datetime import datetime, timezone
from functools import partial
from pathlib import Path
from metaguard_api.database import create_database, DatabaseSettings
from metaguard_api.password_reset import (
    bound_password_reset_transaction,
    confirm_password_reset,
    precheck_password_reset,
)
from metaguard_api.secrets import SecretStore, SecretName
from metaguard_api.account_credentials import hash_password, verify_password

db = create_database(
    DatabaseSettings(
        host="172.31.26.1",
        port=55432,
        name="metaguard_registration_trial",
        user="metaguard_registration_app",
        secret_dir=Path("/etc/metaguard-registration-private")
    ),
    tls_root_cert=Path("/opt/metaguard-registration-preview/db-ca.pem")
)

email = "jarassanchezl+prueba1@gmail.com"
code = "95408d2737541062b6db658054821b31"
new_password = "MetaGuard2026!Nueva1"

totp = open("/etc/metaguard-registration-private/totp_encryption_key", "rb").read()
factor = {"key": totp, "key_version": 1}
clock = lambda: datetime.now(timezone.utc)

try:
    with db.transaction() as session:
        bound_password_reset_transaction(session)
        candidate = precheck_password_reset(
            session, email, code, None, clock=clock, **factor
        )
    print("Candidate:", candidate)

    new_hash = hash_password(new_password)
    with db.transaction() as session:
        bound_password_reset_transaction(session)
        changed = confirm_password_reset(
            session,
            email,
            code,
            None,
            candidate=candidate,
            new_hash=new_hash,
            clock=clock,
            **factor,
        )
    print("Changed:", changed)
except Exception as e:
    traceback.print_exc()
