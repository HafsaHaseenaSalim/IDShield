import json

import config
import database as db
import graph_engine
import ml_engine
import seed
from fraud_engine import FraudEngine


def test_historical_replay_matches_original_rule_scores():
    conn = db.get_db()
    graph = graph_engine.build_from_db(conn)
    engine = FraudEngine(conn, graph=graph)
    for i in range(3):
        attempt = {"attempt_ref": db.next_attempt_ref(conn), "timestamp": "2026-01-02 12:00:00",
                   "claimed_user_ref": "REPLAY-%d" % i, "ip_address": "192.0.2.10",
                   "document_hash": "shared", "document_name": "Different Name",
                   "full_name": "Original Name", "date_of_birth": "1994-01-01",
                   "forensics": {"doc_hash": "shared", "ela_score": 0, "metadata_flags": []}}
        graph.add_attempt(attempt)
        result = engine.evaluate(attempt)
        db.record_document(conn, attempt["forensics"])
        db.insert_attempt(conn, result)
        from fraud_engine import apply_post_decision_reputation
        apply_post_decision_reputation(conn, graph, result)
    def snapshot():
        return [tuple(row) for row in conn.execute(
            "SELECT attempt_ref, risk_score, decision, features FROM attempts WHERE claimed_user_ref LIKE 'REPLAY-%' ORDER BY id")]
    before = snapshot()
    seed.rescore_with_model(conn, None, verbose=False)
    assert snapshot() == before
    seed.rescore_with_model(conn, None, verbose=False)
    assert snapshot() == before
    first = json.loads(before[0][3])
    assert first["velocity_ip_count"] == 0
    assert first["document_reuse_count"] == 0
    assert json.loads(before[1][3])["document_reuse_count"] == 1
    conn.close()


def test_graph_masks_sensitive_values_and_excludes_ip_only_links():
    graph = graph_engine.IdentityGraph()
    graph.add_attempt({"claimed_user_ref": "A", "phone": "+971501234567", "address": "12 Private Street", "ip_address": "192.0.2.1"})
    graph.add_attempt({"claimed_user_ref": "B", "phone": "+971501234567", "address": "12 Private Street"})
    graph.add_attempt({"claimed_user_ref": "C", "ip_address": "192.0.2.1"})
    payload = graph.to_vis_payload("A")
    assert payload["identity_count"] == 2
    assert {node["label"] for node in payload["nodes"] if node["group"] == "identity"} == {"A", "B"}
    serialised = json.dumps(payload)
    assert "+971501234567" not in serialised and "12 Private Street" not in serialised
    assert {link["strength"] for link in payload["links"]} == {"strong", "weak"}
    assert "not a snapshot" in payload["explanation"]
    limited = graph.to_vis_payload("B", limit=1)
    assert limited["truncated"] and limited["nodes"][0]["focus"]


def test_histogram_includes_score_100():
    conn = db.get_db()
    conn.execute("UPDATE attempts SET risk_score=100")
    assert db.get_score_histogram(conn)[-1] == {"label": "90-100", "count": 1, "band": "BLOCK"}
    conn.close()


def test_age_is_computed_at_attempt_time():
    assert FraudEngine._age_from_dob("2010-06-01", "2026-05-01 12:00:00") == 15
    assert FraudEngine._age_from_dob("2010-06-01", "2026-07-01 12:00:00") == 16


def test_dashboard_document_count_uses_submissions_not_analysis_calls(application):
    conn = db.get_db()
    db.record_document(conn, {"doc_hash": "shared-doc", "metadata_flags": []})
    for i in range(2):
        db.insert_attempt(conn, {"attempt_ref": db.next_attempt_ref(conn),
                               "timestamp": db.utcnow(), "document_hash": "shared-doc",
                               "claimed_user_ref": "COUNT-%d" % i, "decision": "ALLOW"})
    reference = conn.execute("SELECT attempt_ref FROM attempts ORDER BY id DESC LIMIT 1").fetchone()[0]
    conn.close()
    handle = application.app.test_client()
    with handle.session_transaction() as session:
        session["analyst_authenticated"] = True
    assert handle.get("/api/attempt/" + reference).get_json()["document"]["seen_count"] == 2
