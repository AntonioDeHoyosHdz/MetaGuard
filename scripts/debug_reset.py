import traceback
from datetime import datetime, timezone
from pathlib import Path
from metaguard_api.database import create_database, DatabaseSettings
from metaguard_api.password_reset import prepare_password_reset

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

with db.transaction() as session:
    try:
        code = prepare_password_reset(session, "jarassanchezl+prueba1@gmail.com", clock=lambda: datetime.now(timezone.utc))
        print("RESULT CODE:", code)
    except Exception as e:
        traceback.print_exc()
