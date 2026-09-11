"""
IDShield — customer and employee authentication tests.

Covers the two portals added on top of the existing verification/analyst
system: citizen sign-in at /customer/login and employee sign-in at
/employee/login (with /login kept as a working alias for the original
analyst login). The central property under test throughout is the one
stated in the brief: a fraud score can escalate a CORRECT password to a
challenge or a refusal, but it can never turn a WRONG password into a
valid one.
"""

import config
import database as db
import security


def client():
    import app as application
    application.app.config["TESTING"] = True
    application.app.config["WTF_CSRF_ENABLED"] = False
    return application.app.test_client()


def employee_client():
    handle = client()
    handle.post("/employee/login", data={
        "identifier": config.ANALYST_USERNAME, "password": config.ANALYST_PASSWORD})
    return handle


def session_of(handle):
    with handle.session_transaction() as sess:
        return dict(sess)


# ---------------------------------------------------------------------------
# Customer login
# ---------------------------------------------------------------------------

def test_customer_valid_login_succeeds():
    handle = client()
    response = handle.post("/customer/login", data={
        "identifier": config.CUSTOMER_DEMO_EMAIL, "password": config.CUSTOMER_DEMO_PASSWORD})
    assert response.status_code == 302
    assert response.headers.get("Location", "").endswith("/verify")
    session = session_of(handle)
    assert session.get("role") == "customer"
    assert session.get("user_ref") == "DEMO-CITIZEN"


def test_customer_wrong_password_fails():
    handle = client()
    response = handle.post("/customer/login", data={
        "identifier": config.CUSTOMER_DEMO_EMAIL, "password": "not-the-password"})
    assert response.status_code == 200
    assert b"Invalid credentials" in response.data
    assert "role" not in session_of(handle)


def test_customer_unknown_user_returns_same_generic_error():
    handle = client()
    known = handle.post("/customer/login", data={
        "identifier": config.CUSTOMER_DEMO_EMAIL, "password": "wrong"})
    unknown = handle.post("/customer/login", data={
        "identifier": "nobody@example.com", "password": "wrong"})
    assert known.status_code == unknown.status_code == 200
    assert b"Invalid credentials" in known.data and b"Invalid credentials" in unknown.data
    # Neither response distinguishes "account exists" from "no such account":
    # both render the same static error text and the same empty login form,
    # with nothing account-specific echoed back.
    assert known.data.count(b"Invalid credentials") == unknown.data.count(b"Invalid credentials")
    assert b"DEMO-CITIZEN" not in known.data and config.CUSTOMER_DEMO_EMAIL.encode() not in known.data


def test_customer_failed_login_is_recorded():
    handle = client()
    handle.post("/customer/login", data={
        "identifier": config.CUSTOMER_DEMO_EMAIL, "password": "wrong"})
    conn = db.get_db()
    try:
        row = conn.execute(
            "SELECT * FROM attempts WHERE claimed_user_ref='DEMO-CITIZEN'"
            " ORDER BY id DESC LIMIT 1").fetchone()
        assert row["login_status"] == "FAIL"
        assert row["stage"] == config.STAGE_LOGIN
        failure = conn.execute(
            "SELECT * FROM audit_log WHERE event='CUSTOMER_LOGIN_FAILURE'"
            " ORDER BY id DESC LIMIT 1").fetchone()
        assert failure is not None
    finally:
        conn.close()


def test_customer_step_up_does_not_authenticate_immediately():
    conn = db.get_db()
    db.flag_ip(conn, "127.0.0.1", "test setup")
    db.flag_device(conn, "WEB-DEVICE", "test setup")
    conn.close()

    handle = client()
    response = handle.post("/customer/login", data={
        "identifier": config.CUSTOMER_DEMO_EMAIL, "password": config.CUSTOMER_DEMO_PASSWORD})
    assert response.status_code == 200
    assert b"Step-up authentication required" in response.data
    assert "role" not in session_of(handle)

    conn = db.get_db()
    row = conn.execute(
        "SELECT * FROM attempts WHERE claimed_user_ref='DEMO-CITIZEN'"
        " ORDER BY id DESC LIMIT 1").fetchone()
    assert row["decision"] == "STEP_UP"
    conn.close()


def test_customer_step_up_success_authenticates_correct_customer():
    conn = db.get_db()
    db.flag_ip(conn, "127.0.0.1", "test setup")
    db.flag_device(conn, "WEB-DEVICE", "test setup")
    conn.close()

    handle = client()
    handle.post("/customer/login", data={
        "identifier": config.CUSTOMER_DEMO_EMAIL, "password": config.CUSTOMER_DEMO_PASSWORD})
    conn = db.get_db()
    attempt_ref = conn.execute(
        "SELECT attempt_ref FROM attempts WHERE claimed_user_ref='DEMO-CITIZEN'"
        " ORDER BY id DESC LIMIT 1").fetchone()["attempt_ref"]
    conn.close()

    result = handle.post("/api/step-up", json={"attempt_ref": attempt_ref, "code": "123456"}).get_json()
    # activation_available is always False on a LOGIN-stage step-up - only
    # ONBOARDING-stage attempts (first-time verification) grant activation.
    assert result == {"passed": True, "decision": "ALLOW", "activation_available": False}
    session = session_of(handle)
    assert session.get("role") == "customer"
    assert session.get("user_ref") == "DEMO-CITIZEN"


def test_customer_failed_step_up_does_not_authenticate():
    conn = db.get_db()
    db.flag_ip(conn, "127.0.0.1", "test setup")
    db.flag_device(conn, "WEB-DEVICE", "test setup")
    conn.close()

    handle = client()
    handle.post("/customer/login", data={
        "identifier": config.CUSTOMER_DEMO_EMAIL, "password": config.CUSTOMER_DEMO_PASSWORD})
    conn = db.get_db()
    attempt_ref = conn.execute(
        "SELECT attempt_ref FROM attempts WHERE claimed_user_ref='DEMO-CITIZEN'"
        " ORDER BY id DESC LIMIT 1").fetchone()["attempt_ref"]
    conn.close()

    result = handle.post("/api/step-up", json={"attempt_ref": attempt_ref, "code": "000000"}).get_json()
    assert result == {"passed": False, "decision": "BLOCK", "activation_available": False}
    assert "role" not in session_of(handle)


def test_customer_expired_step_up_cannot_authenticate():
    conn = db.get_db()
    db.flag_ip(conn, "127.0.0.1", "test setup")
    db.flag_device(conn, "WEB-DEVICE", "test setup")
    conn.close()

    handle = client()
    handle.post("/customer/login", data={
        "identifier": config.CUSTOMER_DEMO_EMAIL, "password": config.CUSTOMER_DEMO_PASSWORD})
    conn = db.get_db()
    attempt_ref = conn.execute(
        "SELECT attempt_ref FROM attempts WHERE claimed_user_ref='DEMO-CITIZEN'"
        " ORDER BY id DESC LIMIT 1").fetchone()["attempt_ref"]
    conn.execute("UPDATE step_up_challenges SET expires_at='2000-01-01 00:00:00'")
    conn.commit()
    conn.close()

    response = handle.post("/api/step-up", json={"attempt_ref": attempt_ref, "code": "123456"})
    assert response.status_code == 410
    assert "role" not in session_of(handle)


def test_customer_block_never_authenticates_even_with_the_correct_password():
    """A correct password cannot override a hard control (here: a velocity floor)."""
    conn = db.get_db()
    stamp = db.utcnow()
    for _ in range(10):
        db.insert_attempt(conn, {
            "attempt_ref": db.next_attempt_ref(conn), "timestamp": stamp,
            "ip_address": "127.0.0.1", "device_id": "WEB-DEVICE",
            "claimed_user_ref": "PRIOR", "decision": "ALLOW",
        })
    conn.close()

    handle = client()
    response = handle.post("/customer/login", data={
        "identifier": config.CUSTOMER_DEMO_EMAIL, "password": config.CUSTOMER_DEMO_PASSWORD})
    assert b"Invalid credentials" in response.data
    assert "role" not in session_of(handle)

    conn = db.get_db()
    row = conn.execute(
        "SELECT * FROM attempts WHERE claimed_user_ref='DEMO-CITIZEN'"
        " ORDER BY id DESC LIMIT 1").fetchone()
    assert row["decision"] == "BLOCK"
    assert row["login_status"] == "PASS"          # the password itself was correct
    blocked = conn.execute(
        "SELECT * FROM audit_log WHERE event='CUSTOMER_LOGIN_BLOCKED'"
        " ORDER BY id DESC LIMIT 1").fetchone()
    assert blocked is not None
    conn.close()


def test_customer_logout_clears_session():
    handle = client()
    handle.post("/customer/login", data={
        "identifier": config.CUSTOMER_DEMO_EMAIL, "password": config.CUSTOMER_DEMO_PASSWORD})
    assert session_of(handle).get("role") == "customer"
    handle.post("/customer/logout")
    assert "role" not in session_of(handle)
    assert "user_id" not in session_of(handle)


# ---------------------------------------------------------------------------
# Employee login
# ---------------------------------------------------------------------------

def test_employee_valid_login_succeeds():
    handle = employee_client()
    assert handle.get("/dashboard").status_code == 200


def test_employee_wrong_password_fails():
    handle = client()
    response = handle.post("/employee/login", data={
        "identifier": config.ANALYST_USERNAME, "password": "wrong"})
    assert b"Invalid credentials" in response.data
    assert handle.get("/dashboard").status_code == 302


def test_employee_unknown_identifier_fails():
    handle = client()
    response = handle.post("/employee/login", data={
        "identifier": "nobody@idshield.demo", "password": "whatever"})
    assert b"Invalid credentials" in response.data


def test_inactive_employee_cannot_sign_in():
    conn = db.get_db()
    conn.execute("UPDATE employees SET is_active=0 WHERE email=?", (config.ANALYST_USERNAME,))
    conn.commit()
    conn.close()

    handle = client()
    response = handle.post("/employee/login", data={
        "identifier": config.ANALYST_USERNAME, "password": config.ANALYST_PASSWORD})
    assert b"Invalid credentials" in response.data
    assert handle.get("/dashboard").status_code == 302


def test_employee_logout_clears_session():
    handle = employee_client()
    assert handle.get("/dashboard").status_code == 200
    handle.post("/employee/logout")
    assert handle.get("/dashboard").status_code == 302
    assert "role" not in session_of(handle)


def test_legacy_login_and_logout_alias_still_work():
    """/login and /logout (username field) are kept working, unchanged, for compatibility."""
    handle = client()
    handle.post("/login", data={"username": config.ANALYST_USERNAME,
                                "password": config.ANALYST_PASSWORD})
    assert handle.get("/dashboard").status_code == 200
    handle.get("/logout")
    assert handle.get("/dashboard").status_code == 302


# ---------------------------------------------------------------------------
# Authorization / role separation
# ---------------------------------------------------------------------------

EMPLOYEE_ONLY = ["/dashboard", "/simulator", "/api/stats", "/api/attempts",
                 "/api/metrics", "/api/security", "/api/export.csv"]


def test_anonymous_cannot_reach_employee_only_surfaces():
    handle = client()
    for path in EMPLOYEE_ONLY:
        assert handle.get(path).status_code in (302, 401, 403), path


def test_customer_cannot_reach_employee_only_surfaces():
    handle = client()
    handle.post("/customer/login", data={
        "identifier": config.CUSTOMER_DEMO_EMAIL, "password": config.CUSTOMER_DEMO_PASSWORD})
    assert session_of(handle).get("role") == "customer"
    for path in EMPLOYEE_ONLY:
        assert handle.get(path).status_code in (302, 401, 403), path


def test_customer_cannot_run_the_simulator_api_directly():
    handle = client()
    handle.post("/customer/login", data={
        "identifier": config.CUSTOMER_DEMO_EMAIL, "password": config.CUSTOMER_DEMO_PASSWORD})
    response = handle.post("/api/simulate/legitimate")
    assert response.status_code in (302, 401, 403)


def test_employee_can_reach_the_dashboard_and_simulator():
    handle = employee_client()
    assert handle.get("/dashboard").status_code == 200
    assert handle.get("/simulator").status_code == 200


# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------

def test_no_plaintext_password_is_ever_stored():
    conn = db.get_db()
    customer = db.get_user_by_email(conn, config.CUSTOMER_DEMO_EMAIL)
    employee = db.get_employee_by_identifier(conn, config.ANALYST_USERNAME)
    conn.close()
    assert config.CUSTOMER_DEMO_PASSWORD not in customer["password_hash"]
    assert config.ANALYST_PASSWORD not in employee["password_hash"]
    assert customer["password_hash"].startswith("pbkdf2:")
    assert employee["password_hash"].startswith("pbkdf2:")


def test_csrf_is_enforced_on_customer_and_employee_login(monkeypatch, application):
    monkeypatch.setitem(application.app.config, "WTF_CSRF_ENABLED", True)
    # Deliberately not the local client() helper: it forces WTF_CSRF_ENABLED
    # back off, which is exactly the setting this test needs on.
    handle = application.app.test_client()
    assert handle.post("/customer/login", data={
        "identifier": config.CUSTOMER_DEMO_EMAIL, "password": config.CUSTOMER_DEMO_PASSWORD
    }).status_code == 400
    assert handle.post("/employee/login", data={
        "identifier": config.ANALYST_USERNAME, "password": config.ANALYST_PASSWORD
    }).status_code == 400


def test_sql_injection_style_identifier_is_harmless():
    handle = client()
    payload = "' OR '1'='1"
    response = handle.post("/customer/login", data={"identifier": payload, "password": "x"})
    assert response.status_code == 200
    assert b"Invalid credentials" in response.data
    conn = db.get_db()
    assert conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"] > 0
    conn.close()


def test_xss_in_customer_identifier_is_not_reflected_as_markup():
    handle = client()
    payload = "<script>alert(1)</script>"
    response = handle.post("/customer/login", data={"identifier": payload, "password": "x"})
    assert b"<script>alert(1)</script>" not in response.data


def test_authenticate_customer_never_validates_a_wrong_password_regardless_of_score():
    """Direct unit check on the credential layer, independent of the fraud engine."""
    conn = db.get_db()
    user, ok = security.authenticate_customer(conn, config.CUSTOMER_DEMO_EMAIL, "wrong")
    assert user is not None and ok is False
    user, ok = security.authenticate_customer(conn, "no-such-account@example.com", "wrong")
    assert user is None and ok is False
    user, ok = security.authenticate_customer(conn, config.CUSTOMER_DEMO_EMAIL,
                                              config.CUSTOMER_DEMO_PASSWORD)
    assert user is not None and ok is True
    conn.close()
