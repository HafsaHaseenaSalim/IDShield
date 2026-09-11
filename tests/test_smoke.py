"""
IDShield — smoke and robustness tests.

Run with:   python -m pytest tests/ -v
       or:  python tests/test_smoke.py

These target the things the brief actually grades: that the system runs end to
end, that it survives a second run, and that it does not fall over on
unexpected input.
"""

import io
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config                                                   # noqa: E402
import database as db                                           # noqa: E402
import graph_engine                                             # noqa: E402
import security                                                 # noqa: E402
from fraud_engine import FraudEngine                             # noqa: E402


def temp_db():
    path = tempfile.mktemp(suffix=".db")
    conn = db.get_db(path)
    db.init_db(conn)
    return conn, path


# ---------------------------------------------------------------------------
# Schema and persistence
# ---------------------------------------------------------------------------

def test_schema_creates_every_table():
    conn, path = temp_db()
    try:
        names = {row["name"] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        for table in ("users", "attempts", "reasons", "audit_log",
                      "flagged_ips", "flagged_devices", "documents"):
            assert table in names, "missing table: %s" % table
    finally:
        conn.close()
        os.unlink(path)


def test_init_db_is_idempotent():
    """A second run must not fail or destroy anything."""
    conn, path = temp_db()
    try:
        db.upsert_user(conn, {"user_ref": "T-1", "full_name": "Test"})
        db.init_db(conn)                       # run it again
        row = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()
        assert row["c"] == 1
    finally:
        conn.close()
        os.unlink(path)


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def test_clean_attempt_is_allowed():
    conn, path = temp_db()
    try:
        engine = FraudEngine(conn, graph=graph_engine.IdentityGraph())
        result = engine.evaluate({
            "claimed_user_ref": "SIM-1", "full_name": "Sara Haddad",
            "date_of_birth": "1994-05-11", "nationality": "UAE",
            "phone": "+971501234567", "email": "sara@gmail.com",
            "ip_address": "198.51.100.5", "device_id": "DEV-1",
            "timestamp": db.utcnow(), "liveness_status": "PASS",
            "login_status": "PASS",
        })
        assert result["decision"] == config.DECISION_ALLOW
        assert result["risk_score"] < config.THRESHOLD_STEP_UP
    finally:
        conn.close()
        os.unlink(path)


def test_credential_stuffing_burst_is_blocked():
    """Many attempts from one IP inside the window must reach BLOCK."""
    conn, path = temp_db()
    try:
        graph = graph_engine.IdentityGraph()
        engine = FraudEngine(conn, graph=graph)
        stamp = db.utcnow()
        result = None
        for index in range(14):
            attempt = {
                "claimed_user_ref": "VICTIM-%d" % index,
                "ip_address": "203.0.113.9", "device_id": "DEV-ATTACK",
                "timestamp": stamp, "login_status": "FAIL",
                "attempt_ref": db.next_attempt_ref(conn),
            }
            graph.add_attempt(attempt)
            result = engine.evaluate(attempt)
            db.insert_attempt(conn, result)
        assert result["decision"] == config.DECISION_BLOCK, result["risk_score"]
        assert any(r["rule"] == "CREDENTIAL_STUFFING_BURST"
                   for r in result["reasons"])
    finally:
        conn.close()
        os.unlink(path)


def test_decision_bands_match_thresholds():
    assert FraudEngine.decide(0) == config.DECISION_ALLOW
    assert FraudEngine.decide(config.THRESHOLD_STEP_UP) == config.DECISION_STEP_UP
    assert FraudEngine.decide(config.THRESHOLD_BLOCK) == config.DECISION_BLOCK
    assert FraudEngine.decide(100) == config.DECISION_BLOCK


def test_score_is_always_in_range():
    """Even absurd input must not produce a score outside 0-100."""
    conn, path = temp_db()
    try:
        engine = FraudEngine(conn, graph=graph_engine.IdentityGraph())
        result = engine.evaluate({
            "claimed_user_ref": "X", "date_of_birth": "1700-01-01",
            "nationality": "UAE", "phone": "+1555", "email": "a@mailinator.com",
            "ip_address": "203.0.113.1", "device_id": "D",
            "timestamp": db.utcnow(), "liveness_status": "FAIL",
            "login_status": "FAIL",
        })
        assert 0 <= result["risk_score"] <= 100
    finally:
        conn.close()
        os.unlink(path)


# ---------------------------------------------------------------------------
# Unexpected input
# ---------------------------------------------------------------------------

def test_engine_survives_empty_and_partial_attempts():
    """Missing fields must degrade gracefully, not raise."""
    conn, path = temp_db()
    try:
        engine = FraudEngine(conn, graph=graph_engine.IdentityGraph())
        for attempt in ({}, {"claimed_user_ref": "A"},
                        {"ip_address": None, "timestamp": None},
                        {"date_of_birth": "not-a-date", "phone": None},
                        {"full_name": "x" * 5000}):
            result = engine.evaluate(dict(attempt))
            assert result["decision"] in (config.DECISION_ALLOW,
                                          config.DECISION_STEP_UP,
                                          config.DECISION_BLOCK)
    finally:
        conn.close()
        os.unlink(path)


def test_sql_injection_style_input_is_inert():
    """Parameterised queries mean this is stored as text, never executed."""
    conn, path = temp_db()
    try:
        payload = "'; DROP TABLE attempts; --"
        engine = FraudEngine(conn, graph=graph_engine.IdentityGraph())
        result = engine.evaluate({
            "claimed_user_ref": payload, "ip_address": payload,
            "device_id": payload, "timestamp": db.utcnow(),
        })
        result["attempt_ref"] = db.next_attempt_ref(conn)
        db.insert_attempt(conn, result)
        assert conn.execute("SELECT COUNT(*) AS c FROM attempts").fetchone()["c"] == 1
    finally:
        conn.close()
        os.unlink(path)


# ---------------------------------------------------------------------------
# Upload validation
# ---------------------------------------------------------------------------

class FakeUpload:
    def __init__(self, filename, data):
        self.filename = filename
        self.stream = io.BytesIO(data)

    def save(self, path):
        with open(path, "wb") as handle:
            handle.write(self.stream.getvalue())


def test_upload_rejects_bad_extension_empty_and_oversize():
    directory = tempfile.mkdtemp()

    for upload, label in (
        (FakeUpload("evil.exe", b"MZ"), "executable"),
        (FakeUpload("empty.jpg", b""), "empty file"),
        (FakeUpload("big.jpg", b"x" * (config.MAX_UPLOAD_BYTES + 1)), "oversize"),
        (FakeUpload("", b"data"), "no filename"),
        (FakeUpload("notreally.jpg", b"this is not an image"), "fake image"),
    ):
        try:
            security.validate_and_store_upload(upload, upload_dir=directory)
            raise AssertionError("should have rejected: %s" % label)
        except security.UploadRejected:
            pass


def test_pii_is_masked_and_stable():
    masked = security.mask_pii("+971501234567")
    assert "501234567" not in masked
    assert masked == security.mask_pii("+971501234567")     # correlatable
    assert masked != security.mask_pii("+971509999999")     # distinguishable
    assert security.mask_pii(None) is None


def test_password_hashing_roundtrip():
    digest = security.hash_password("correct horse")
    assert digest != "correct horse"
    assert security.verify_password(digest, "correct horse")
    assert not security.verify_password(digest, "wrong")
    assert not security.verify_password(None, "anything")


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------

def test_shared_device_alone_does_not_create_a_strong_cluster():
    """A family sharing one laptop must not look like a ring."""
    graph = graph_engine.IdentityGraph()
    for index in range(4):
        graph.add_attempt({
            "claimed_user_ref": "FAM-%d" % index,
            "device_id": "DEV-HOME",
            "address": "%d Different Street" % index,
            "phone": "+97150000000%d" % index,
        })
    shared = graph.shared_attributes("FAM-0")
    kinds = {item["attribute"] for item in shared}
    assert kinds == {"device_id"}, kinds


def test_ring_sharing_several_attributes_is_strongly_bound():
    graph = graph_engine.IdentityGraph()
    for index in range(4):
        graph.add_attempt({
            "claimed_user_ref": "RING-%d" % index,
            "device_id": "DEV-RING", "address": "1 Same Street",
            "document_hash": "abc123",
        })
    kinds = {item["attribute"] for item in graph.shared_attributes("RING-0")}
    assert len(kinds) >= 3, kinds
    assert len(graph.cluster("RING-0")) == 4


def test_graph_handles_unknown_identity():
    graph = graph_engine.IdentityGraph()
    assert graph.cluster("nobody") == set()
    assert graph.shared_attributes("nobody") == []
    assert graph.device_identity_count(None) == 0


# ---------------------------------------------------------------------------

def _run_all():
    """Minimal runner so the file works without pytest installed."""
    tests = [(name, obj) for name, obj in sorted(globals().items())
             if name.startswith("test_") and callable(obj)]
    failures = 0
    for name, test in tests:
        try:
            test()
            print("  PASS  %s" % name)
        except Exception as exc:                # noqa: BLE001
            failures += 1
            print("  FAIL  %s -> %s: %s" % (name, type(exc).__name__, exc))
    print("\n%d passed, %d failed" % (len(tests) - failures, failures))
    return 1 if failures else 0


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
