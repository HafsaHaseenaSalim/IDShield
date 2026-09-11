"""
IDShield — verification input-validation and phone/residence consistency
regression tests.

Two fixes covered here:

  ISSUE 1: required identity fields (full name in particular) must be
  rejected before FraudEngine ever runs - no attempt row, no decision, no
  activation token. Empirically, security.validate_verification() already
  rejected an empty or whitespace-only full_name before this change (it is
  in the required-fields loop and every value is `.strip()`-checked); these
  tests lock that behaviour in as an explicit regression guard rather than
  leaving it implicit.

  ISSUE 3: the phone/geography plausibility check no longer references
  nationality at all. It now looks for a country name inside the declared
  residential address and compares THAT against the phone's country code -
  and only when the address actually names a country. It stays a single,
  low-weight rule (PHONE_RESIDENCE_MISMATCH) that never blocks and never
  crosses STEP_UP on its own.
"""

import sqlite3

import config
import database as db
import graph_engine
from fraud_engine import FraudEngine
from helpers import verification_data


def client():
    import app as application
    application.app.config["TESTING"] = True
    application.app.config["WTF_CSRF_ENABLED"] = False
    return application.app.test_client()


def session_of(handle):
    with handle.session_transaction() as sess:
        return dict(sess)


def _evaluate(attempt):
    """Score one attempt directly through FraudEngine, bypassing the web
    layer entirely - for the attribute-consistency tests, which are about
    the rule itself, not the HTTP boundary."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    db.init_db(conn)
    engine = FraudEngine(conn, graph=graph_engine.IdentityGraph())
    attempt.setdefault("timestamp", db.utcnow())
    attempt.setdefault("claimed_user_ref", "RES-TEST")
    result = engine.evaluate(attempt)
    conn.close()
    return result


# ---------------------------------------------------------------------------
# ISSUE 1 — required fields validated before FraudEngine
# ---------------------------------------------------------------------------

def test_missing_full_name_is_rejected_before_fraud_scoring():
    conn = db.get_db()
    before = conn.execute("SELECT COUNT(*) AS c FROM attempts").fetchone()["c"]
    conn.close()

    response = client().post("/api/verify", data=verification_data(full_name=""))
    assert response.status_code == 400
    payload = response.get_json()
    assert payload["fields"]["full_name"] == "This field is required."
    # No fraud outcome of any kind is present on a validation failure.
    assert "decision" not in payload
    assert "risk_score" not in payload
    assert "activation_available" not in payload

    conn = db.get_db()
    after = conn.execute("SELECT COUNT(*) AS c FROM attempts").fetchone()["c"]
    conn.close()
    assert after == before, "a rejected submission must not create an attempt row"


def test_whitespace_only_full_name_is_rejected():
    response = client().post("/api/verify", data=verification_data(full_name="    "))
    assert response.status_code == 400
    assert response.get_json()["fields"]["full_name"] == "This field is required."


def test_whitespace_only_address_is_rejected():
    response = client().post("/api/verify", data=verification_data(address="   \t  "))
    assert response.status_code == 400
    assert "address" in response.get_json()["fields"]


def test_missing_document_is_rejected():
    data = verification_data()
    del data["document"]
    response = client().post("/api/verify", data=data)
    assert response.status_code == 400
    assert "document" in response.get_json()["fields"]


def test_invalid_liveness_value_is_rejected():
    response = client().post("/api/verify", data=verification_data(liveness="maybe"))
    assert response.status_code == 400
    assert "liveness" in response.get_json()["fields"]


def test_failed_validation_creates_no_activation_token_or_pending_session():
    handle = client()
    response = handle.post("/api/verify", data=verification_data(full_name="  "))
    assert response.status_code == 400
    assert "pending_activation_attempt_ref" not in session_of(handle)
    assert "verification_owner" not in session_of(handle)

    conn = db.get_db()
    assert conn.execute("SELECT COUNT(*) FROM activation_tokens").fetchone()[0] == 0
    conn.close()


def test_failed_validation_never_reaches_a_decision_via_the_http_api():
    """Same property as above, stated the way the brief phrases it: no
    ALLOW/STEP_UP/BLOCK is ever produced for a rejected submission."""
    response = client().post("/api/verify", data=verification_data(full_name=""))
    payload = response.get_json()
    assert payload.get("decision") not in (
        config.DECISION_ALLOW, config.DECISION_STEP_UP, config.DECISION_BLOCK)


# ---------------------------------------------------------------------------
# ISSUE 3 — phone vs. declared residence, not nationality
# ---------------------------------------------------------------------------

def test_indian_nationality_uae_address_and_uae_phone_is_not_flagged():
    """The brief's own example: nationality=India, resident in the UAE, a
    UAE phone number. Completely ordinary - must not be flagged."""
    result = _evaluate({
        "nationality": "India",
        "address": "12 Marina Walk, Dubai, UAE",
        "phone": "+971501234567",
    })
    rules = {r["rule"] for r in result["reasons"]}
    assert "PHONE_RESIDENCE_MISMATCH" not in rules
    assert "PHONE_NATIONALITY_MISMATCH" not in rules  # the rule no longer exists under this name


def test_mismatched_nationality_and_phone_alone_is_not_flagged():
    """Nationality must not be used as the reference point at all: an
    address that names no country gives the check nothing to compare
    against, even when nationality and phone country visibly differ."""
    result = _evaluate({
        "nationality": "India",
        "address": "45 Riverside Lane, Springfield",   # no country named
        "phone": "+971501234567",                       # would mismatch India under the OLD rule
    })
    rules = {r["rule"] for r in result["reasons"]}
    assert "PHONE_RESIDENCE_MISMATCH" not in rules
    assert result["decision"] == config.DECISION_ALLOW


def test_uae_address_with_foreign_phone_is_a_weak_signal_only():
    result = _evaluate({
        "nationality": "UAE",
        "address": "1 Downtown Boulevard, UAE",
        "phone": "+919812345678",   # India prefix, address names the UAE
    })
    reasons = {r["rule"]: r for r in result["reasons"]}
    assert "PHONE_RESIDENCE_MISMATCH" in reasons
    assert reasons["PHONE_RESIDENCE_MISMATCH"]["points"] == config.POINTS["PHONE_RESIDENCE_MISMATCH"]
    assert config.POINTS["PHONE_RESIDENCE_MISMATCH"] < config.THRESHOLD_STEP_UP
    # On its own (no other signal) it neither steps up nor blocks.
    assert result["decision"] == config.DECISION_ALLOW
    assert result["risk_score"] < config.THRESHOLD_STEP_UP


def test_phone_residence_reason_text_is_neutral_and_never_mentions_nationality():
    result = _evaluate({
        "nationality": "UAE",
        "address": "1 Downtown Boulevard, UAE",
        "phone": "+919812345678",
    })
    reason = next(r for r in result["reasons"] if r["rule"] == "PHONE_RESIDENCE_MISMATCH")
    assert "nationality" not in reason["description"].lower()
    assert "Phone country differs from declared residence" in reason["description"]


def test_no_rule_compares_email_username_to_legal_name():
    """Issue 2: confirm no such rule was introduced. The only email-based
    check is the disposable-domain rule, which is domain-only."""
    result = _evaluate({
        "full_name": "Completely Different Name",
        "email": "totallyunrelatedhandle@gmail.com",
        "address": "1 Somewhere Street",
    })
    rules = {r["rule"] for r in result["reasons"]}
    assert not any("EMAIL_NAME" in rule or "NAME_EMAIL" in rule for rule in rules)


# ---------------------------------------------------------------------------
# Regression: everything else keeps working
# ---------------------------------------------------------------------------

def test_default_legitimate_verification_still_allows():
    response = client().post("/api/verify", data=verification_data())
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["decision"] == config.DECISION_ALLOW
    assert payload["activation_available"] is True


def test_step_up_path_still_reachable_with_valid_required_fields():
    response = client().post("/api/verify", data=verification_data(
        liveness="fail", email="test@mailinator.com", phone="+447700900123",
        address="12 Test Street, UAE"))
    assert response.status_code == 200
    assert response.get_json()["decision"] == config.DECISION_STEP_UP
