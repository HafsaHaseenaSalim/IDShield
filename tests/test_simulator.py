import database as db
import graph_engine
import simulator as sim
from fraud_engine import FraudEngine
import config
import seed
from pathlib import Path


def test_simulator_resumes_clock_and_stuffing_does_not_advance_twice():
    conn = db.get_db()
    conn.execute("UPDATE attempts SET timestamp='2026-03-01 12:00:00'")
    conn.commit()
    graph = graph_engine.build_from_db(conn)
    generator = sim.TrafficSimulator(conn, graph=graph, engine=FraudEngine(conn, graph))
    assert generator.clock.strftime("%Y-%m-%d %H:%M:%S") == "2026-03-01 12:00:00"
    stamp = generator._advance(3)
    generator.submit({"timestamp": stamp, "claimed_user_ref": "SIM-00001"})
    assert generator.clock.strftime("%Y-%m-%d %H:%M:%S") == stamp
    assert sim.next_identity_index(conn) == 2
    conn.close()


def test_repeated_scenarios_allocate_new_identities_and_move_forward(monkeypatch, application):
    monkeypatch.setattr(sim, "ensure_document_pool", lambda **kw: {"clean": [], "tampered": []})
    monkeypatch.setattr(sim.TrafficSimulator, "_unique_document", lambda *args, **kw: None)
    handle = application.app.test_client()
    # The simulator is an employee-only surface (analyst console); authenticate
    # directly against the session rather than exercising the login form here.
    with handle.session_transaction() as sess:
        sess["analyst_authenticated"] = True
        sess["role"] = "employee"
    first = handle.post("/api/simulate/legitimate").get_json()
    second = handle.post("/api/simulate/legitimate").get_json()
    assert first["attempts"][0]["identity"] != second["attempts"][0]["identity"]
    conn = db.get_db()
    one = db.get_attempt(conn, first["attempts"][0]["attempt_ref"])
    two = db.get_attempt(conn, second["attempts"][0]["attempt_ref"])
    assert two["timestamp"] > one["timestamp"]
    conn.close()


def test_reset_clears_persistent_and_in_memory_state(application):
    handle = application.app.test_client()
    handle.get("/")
    application.get_graph().mark_blocked("OLD")
    application.DOC_CACHE["old"] = {}
    db.reset_db()
    assert handle.get("/").status_code == 200
    assert application.DOC_CACHE == {}
    assert not application.get_graph().blocked_identities
    conn = db.get_db()
    assert db.get_stats(conn)["total"] == 0
    assert db.next_attempt_ref(conn) == "ATT-01001"
    conn.close()


def test_seeding_maintenance_state_is_visible(application):
    conn = db.get_db()
    conn.execute("INSERT OR REPLACE INTO runtime_state VALUES ('seed_status', 'building')")
    conn.commit()
    assert application.app.test_client().get("/").status_code == 503
    conn.close()


def stub_seed(monkeypatch):
    monkeypatch.setattr(seed, "build_demo_documents", lambda: None)
    monkeypatch.setattr(seed, "calibrate_ela", lambda pool: None)
    monkeypatch.setattr(sim, "ensure_document_pool", lambda **kw: {"clean": [], "tampered": []})
    def generate(generator, **kwargs):
        index = sim.next_identity_index(generator.conn)
        identity = generator._identity(index)
        db.upsert_user(generator.conn, identity)
        generator.submit({"claimed_user_ref": identity["user_ref"]})
    monkeypatch.setattr(sim.TrafficSimulator, "generate_mixed_traffic", generate)


def test_keep_preserves_decisions_metrics_and_invalidates_runtime(monkeypatch):
    stub_seed(monkeypatch)
    Path(config.MODEL_DIR).mkdir(parents=True)
    Path(config.METRICS_PATH).write_text('{"accuracy": 0.5}')
    conn = db.get_db()
    old = dict(db.get_attempt(conn, "ATT-01001"))
    generation = conn.execute("SELECT value FROM runtime_state WHERE key='generation'").fetchone()[0]
    conn.close()
    monkeypatch.setattr("sys.argv", ["seed.py", "--keep", "--small"])
    assert seed.main() == 0
    conn = db.get_db()
    assert dict(db.get_attempt(conn, "ATT-01001")) == old
    assert db.get_stats(conn)["total"] == 2
    assert conn.execute("SELECT value FROM runtime_state WHERE key='generation'").fetchone()[0] != generation
    assert Path(config.METRICS_PATH).read_text() == '{"accuracy": 0.5}'
    conn.close()


def test_no_model_reset_removes_stale_artifacts_and_repeats(monkeypatch):
    stub_seed(monkeypatch)
    Path(config.MODEL_DIR).mkdir(parents=True)
    Path(config.MODEL_PATH).write_bytes(b"old model")
    Path(config.METRICS_PATH).write_text('{}')
    monkeypatch.setattr("sys.argv", ["seed.py", "--small", "--no-model"])
    for _ in range(2):
        assert seed.main() == 0
        conn = db.get_db()
        assert db.get_stats(conn)["total"] == 1
        assert db.get_attempt(conn, "ATT-01001")["claimed_user_ref"] == "SIM-00001"
        conn.close()
    assert not Path(config.MODEL_PATH).exists()
    assert not Path(config.METRICS_PATH).exists()


def test_failed_reset_is_reported_and_can_be_retried(monkeypatch, application):
    import pytest
    stub_seed(monkeypatch)
    def fail():
        raise RuntimeError("generation failed")
    monkeypatch.setattr(seed, "build_demo_documents", fail)
    monkeypatch.setattr("sys.argv", ["seed.py", "--no-model"])
    with pytest.raises(RuntimeError):
        seed.main()
    assert application.app.test_client().get("/").status_code == 503
    monkeypatch.setattr(seed, "build_demo_documents", lambda: None)
    assert seed.main() == 0
    assert application.app.test_client().get("/").status_code == 200
