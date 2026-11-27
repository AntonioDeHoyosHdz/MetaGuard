import psycopg

def clean_test_accounts():
    pw = open("/etc/metaguard-registration-private/postgres_password").read().strip()
    conn = psycopg.connect(
        host="172.31.26.1",
        port=55432,
        dbname="metaguard_registration_trial",
        user="metaguard_registration_app",
        password=pw,
        sslmode="verify-full",
        sslrootcert="/opt/metaguard-registration-preview/db-ca.pem"
    )
    with conn.cursor() as cur:
        cur.execute("SELECT id, email, email_verified_at FROM accounts WHERE email LIKE %s", ("%jarassanchezl%",))
        print("Existing accounts:", cur.fetchall())
        cur.execute("DELETE FROM accounts WHERE email IN (%s, %s)", (
            "jarassanchezl+prueba1@gmail.com",
            "jarassanchezl+prueba2@gmail.com"
        ))
        print(f"Deleted {cur.rowcount} test accounts")
    conn.commit()
    conn.close()

if __name__ == "__main__":
    clean_test_accounts()
