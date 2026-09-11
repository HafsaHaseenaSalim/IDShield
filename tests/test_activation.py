"""
IDShield — first-time citizen account activation tests.

Covers the new path from a fresh, unauthenticated /verify submission to a
usable /customer/login account: the ALLOW and STEP_UP-then-ALLOW cases can
activate, BLOCK never can, and the activation token behaves like every other
one-time, session-owned, expiring token in this codebase (see
tests/test_verification.py's step-up tests for the analogous coverage on
/api/step-up itself).
"""

import io

from pypdf import PdfWriter

import config
import database as db
from helpers import verification_data


def _distinct_document(width=301, height=201):
    """A PDF that hashes differently from helpers.verification_data()'s
    default blank page, so two separate identities in one test are not
    scored as presenting the exact same document (DOCUMENT_REUSE)."""
    writer = PdfWriter()
    writer.add_blank_page(width=width, height=height)
    stream = io.BytesIO()
    writer.write(stream)
    stream.seek(0)
    return (stream, "identity-2.pdf")


def client():
    import app as application
    application.app.config["TESTING"] = True
    application.app.config["WTF_CSRF_ENABLED"] = False
    return application.app.test_client()


def session_of(handle):
    with handle.session_transaction() as sess:
        return dict(sess)


def set_session(handle, **kwargs):
    with handle.session_transaction() as sess:
        sess.update(kwargs)


# ---------------------------------------------------------------------------
# Happy path: ALLOW -> activate -> log in
# ---------------------------------------------------------------------------

def test_new_citizen_can_complete_verification_and_activate_account():
    handle = client()
    verified = handle.post("/api/verify", data=verification_data(user_ref="NEWCIT-001")).get_json()
    assert verified["decision"] == "ALLOW"
    assert verified["activation_available"] is True
    assert session_of(handle).get("pending_activation_attempt_ref") == verified["attempt_ref"]

    page = handle.get("/customer/activate")
    assert page.status_code == 200
    assert b"Activate Account" in page.data
    assert b"Identity verified" in page.data
    assert b"Activation link expired" not in page.data

    response = handle.post("/customer/activate", data={
        "identifier": "newcitizen@example.com",
        "password": "CorrectHorse9!",
        "confirm_password": "CorrectHorse9!",
    })
    assert response.status_code == 302
    assert response.headers.get("Location", "").endswith("/verify")
    session = session_of(handle)
    assert session.get("role") == "customer"
    assert session.get("user_ref") == "NEWCIT-001"

    conn = db.get_db()
    row = db.get_user_by_email(conn, "newcitizen@example.com")
    assert row is not None and row["user_ref"] == "NEWCIT-001" and row["is_active"]
    audit = conn.execute(
        "SELECT * FROM audit_log WHERE event='CUSTOMER_ACCOUNT_ACTIVATED'").fetchone()
    assert audit is not None
    conn.close()


def test_activated_citizen_can_later_log_in():
    handle = client()
    verified = handle.post("/api/verify", data=verification_data(user_ref="NEWCIT-002")).get_json()
    handle.post("/customer/activate", data={
        "identifier": "later.login@example.com",
        "password": "AnotherPass8!",
        "confirm_password": "AnotherPass8!",
    })

    fresh = client()
    response = fresh.post("/customer/login", data={
        "identifier": "later.login@example.com", "password": "AnotherPass8!"})
    assert response.status_code == 302
    assert response.headers.get("Location", "").endswith("/verify")
    assert session_of(fresh).get("role") == "customer"


# ---------------------------------------------------------------------------
# BLOCK must never allow activation
# ---------------------------------------------------------------------------

def test_block_decision_cannot_activate_account():
    conn = db.get_db()
    stamp = db.utcnow()
    for _ in range(10):
        db.insert_attempt(conn, {
            "attempt_ref": db.next_attempt_ref(conn), "timestamp": stamp,
            "ip_address": "127.0.0.1", "device_id": "WEB-DEVICE",
            "claimed_user_ref": "PRIOR-BLOCK", "decision": "ALLOW",
        })
    conn.close()

    handle = client()
    verified = handle.post("/api/verify", data=verification_data(user_ref="BLOCKED-001")).get_json()
    assert verified["decision"] == "BLOCK"
    assert verified["activation_available"] is False
    assert "pending_activation_attempt_ref" not in session_of(handle)

    page = handle.get("/customer/activate")
    assert b"Activation link expired" in page.data

    response = handle.post("/customer/activate", data={
        "identifier": "shouldnotexist@example.com",
        "password": "WontWork9!", "confirm_password": "WontWork9!",
    })
    assert b"Activation link expired" in response.data
    conn = db.get_db()
    assert db.get_user_by_email(conn, "shouldnotexist@example.com") is None
    conn.close()


# ---------------------------------------------------------------------------
# STEP_UP: pending cannot activate, resolved-to-ALLOW can
# ---------------------------------------------------------------------------

def _step_up_data(**overrides):
    return verification_data(liveness="fail", email="test@mailinator.com",
                             phone="+447700900123", **overrides)


def test_pending_step_up_cannot_activate_account():
    handle = client()
    verified = handle.post("/api/verify", data=_step_up_data(user_ref="STEPPING-001")).get_json()
    assert verified["decision"] == "STEP_UP"
    assert verified["activation_available"] is False

    page = handle.get("/customer/activate")
    assert b"Activation link expired" in page.data


def test_successful_step_up_can_activate_account():
    handle = client()
    verified = handle.post("/api/verify", data=_step_up_data(user_ref="STEPPING-002")).get_json()
    resolved = handle.post("/api/step-up", json={
        "attempt_ref": verified["attempt_ref"], "code": "123456"}).get_json()
    assert resolved["decision"] == "ALLOW" and resolved["activation_available"] is True

    response = handle.post("/customer/activate", data={
        "identifier": "stepped.up@example.com",
        "password": "StepUpPass9!", "confirm_password": "StepUpPass9!",
    })
    assert response.status_code == 302
    conn = db.get_db()
    assert db.get_user_by_email(conn, "stepped.up@example.com") is not None
    conn.close()


def test_failed_step_up_cannot_activate_account():
    handle = client()
    verified = handle.post("/api/verify", data=_step_up_data(user_ref="STEPPING-003")).get_json()
    resolved = handle.post("/api/step-up", json={
        "attempt_ref": verified["attempt_ref"], "code": "000000"}).get_json()
    assert resolved["decision"] == "BLOCK" and resolved["activation_available"] is False

    page = handle.get("/customer/activate")
    assert b"Activation link expired" in page.data


# ---------------------------------------------------------------------------
# Session ownership, expiry, replay
# ---------------------------------------------------------------------------

def test_activation_belongs_to_the_verifying_session_only():
    owner = client()
    verified = owner.post("/api/verify", data=verification_data(user_ref="OWNED-001")).get_json()
    assert verified["activation_available"] is True

    stranger = client()   # a separate browser/session, no cookies shared
    page = stranger.get("/customer/activate")
    assert b"Activation link expired" in page.data
    response = stranger.post("/customer/activate", data={
        "identifier": "stranger@example.com", "password": "StrangerPass9!",
        "confirm_password": "StrangerPass9!",
    })
    assert b"Activation link expired" in response.data
    conn = db.get_db()
    assert db.get_user_by_email(conn, "stranger@example.com") is None
    conn.close()


def test_expired_activation_fails_safely():
    handle = client()
    verified = handle.post("/api/verify", data=verification_data(user_ref="EXPIRED-001")).get_json()
    conn = db.get_db()
    conn.execute("UPDATE activation_tokens SET expires_at='2000-01-01 00:00:00'")
    conn.commit()
    conn.close()

    page = handle.get("/customer/activate")
    assert b"Activation link expired" in page.data
    response = handle.post("/customer/activate", data={
        "identifier": "toolate@example.com", "password": "TooLatePass9!",
        "confirm_password": "TooLatePass9!",
    })
    assert b"Activation link expired" in response.data
    conn = db.get_db()
    assert db.get_user_by_email(conn, "toolate@example.com") is None
    conn.close()


def test_replayed_activation_fails_safely():
    handle = client()
    verified = handle.post("/api/verify", data=verification_data(user_ref="REPLAY-001")).get_json()
    first = handle.post("/customer/activate", data={
        "identifier": "onceonly@example.com", "password": "OnceOnly9!",
        "confirm_password": "OnceOnly9!",
    })
    assert first.status_code == 302

    # Simulate a stale/replayed session that still points at the (now
    # consumed) token, as if a captured cookie were reused.
    set_session(handle, pending_activation_attempt_ref=verified["attempt_ref"])
    response = handle.post("/customer/activate", data={
        "identifier": "second-account@example.com", "password": "SecondTry9!",
        "confirm_password": "SecondTry9!",
    })
    assert b"Activation link expired" in response.data
    conn = db.get_db()
    assert db.get_user_by_email(conn, "second-account@example.com") is None
    conn.close()


# ---------------------------------------------------------------------------
# Form validation and password storage
# ---------------------------------------------------------------------------

def test_password_mismatch_fails():
    handle = client()
    handle.post("/api/verify", data=verification_data(user_ref="MISMATCH-001"))
    response = handle.post("/customer/activate", data={
        "identifier": "mismatch@example.com",
        "password": "FirstPassword9!", "confirm_password": "DifferentPassword9!",
    })
    assert response.status_code == 200
    assert b"do not match" in response.data
    conn = db.get_db()
    assert db.get_user_by_email(conn, "mismatch@example.com") is None
    conn.close()


def test_password_is_stored_as_a_hash_not_plaintext():
    handle = client()
    handle.post("/api/verify", data=verification_data(user_ref="HASHED-001"))
    handle.post("/customer/activate", data={
        "identifier": "hashed@example.com",
        "password": "PlainTextPass9!", "confirm_password": "PlainTextPass9!",
    })
    conn = db.get_db()
    row = db.get_user_by_email(conn, "hashed@example.com")
    conn.close()
    assert row is not None
    assert "PlainTextPass9!" not in row["password_hash"]
    assert row["password_hash"].startswith("pbkdf2:")


def test_activating_an_already_registered_email_fails_without_overwriting_it():
    handle = client()
    handle.post("/api/verify", data=verification_data(user_ref="DUP-001"))
    handle.post("/customer/activate", data={
        "identifier": "duplicate@example.com", "password": "FirstAccount9!",
        "confirm_password": "FirstAccount9!",
    })

    second = client()
    # Distinct phone/address/device/email from the first submission -
    # otherwise the two "different" verifications would share every
    # attribute and legitimately look like a synthetic-identity ring to the
    # fraud engine, which is not what this test is about.
    second.post("/api/verify", data=verification_data(
        user_ref="DUP-002", phone="+971501112222", address="99 Other Street",
        device_id="OTHER-DEVICE", email="dup002@example.com",
        document=_distinct_document()))
    response = second.post("/customer/activate", data={
        "identifier": "duplicate@example.com", "password": "SecondAccount9!",
        "confirm_password": "SecondAccount9!",
    })
    assert b"already registered" in response.data

    conn = db.get_db()
    row = db.get_user_by_email(conn, "duplicate@example.com")
    conn.close()
    assert row["user_ref"] == "DUP-001"

    # The first account's password still works; the rejected second
    # attempt's password was never stored against this email.
    still_first = client()
    ok = still_first.post("/customer/login", data={
        "identifier": "duplicate@example.com", "password": "FirstAccount9!"})
    assert ok.status_code == 302
    rejected = client()
    bad = rejected.post("/customer/login", data={
        "identifier": "duplicate@example.com", "password": "SecondAccount9!"})
    assert bad.status_code == 200 and b"Invalid credentials" in bad.data


# ---------------------------------------------------------------------------
# Everything else keeps working
# ---------------------------------------------------------------------------

def test_existing_seeded_citizen_login_still_works():
    handle = client()
    response = handle.post("/customer/login", data={
        "identifier": config.CUSTOMER_DEMO_EMAIL, "password": config.CUSTOMER_DEMO_PASSWORD})
    assert response.status_code == 302
    assert session_of(handle).get("role") == "customer"


def test_employee_login_still_works():
    handle = client()
    response = handle.post("/employee/login", data={
        "identifier": config.ANALYST_USERNAME, "password": config.ANALYST_PASSWORD})
    assert response.status_code == 302
    assert handle.get("/dashboard").status_code == 200
