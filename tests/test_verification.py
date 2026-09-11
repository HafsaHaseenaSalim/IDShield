import io
import json
import re
from pathlib import Path

import pytest
from pypdf import PdfWriter
import config
import database as db
from helpers import verification_data


def client():
    import app as application
    return application.app.test_client()


def create_challenge(handle):
    response = handle.post("/api/verify", data=verification_data(liveness="fail", email="test@mailinator.com", phone="+447700900123"))
    assert response.status_code == 200, response.get_json()
    assert response.get_json()["decision"] == "STEP_UP"
    return response.get_json()["attempt_ref"]


def test_step_up_owner_replay_and_original_evidence():
    owner, stranger = client(), client()
    reference = create_challenge(owner)
    payload = {"attempt_ref": reference, "code": "123456"}
    assert stranger.post("/api/step-up", json=payload).status_code == 404
    assert owner.post("/api/step-up", json=payload).get_json()["decision"] == "ALLOW"
    assert owner.post("/api/step-up", json=payload).status_code == 409
    conn = db.get_db()
    row = db.get_attempt(conn, reference)
    assert row["initial_decision"] == "STEP_UP"
    assert row["decision"] == "ALLOW" and row["step_up_result"] == "PASS"
    assert row["risk_score"] >= 30 and db.get_reasons(conn, row["id"])
    assert len([x for x in db.get_audit_log(conn, row["id"]) if x["event"] == "STEP_UP_PASSED"]) == 1
    conn.close()


def test_step_up_wrong_code_is_final_and_updates_reputation(application):
    owner = client()
    reference = create_challenge(owner)
    assert owner.post("/api/step-up", json={"attempt_ref": reference, "code": "000000"}).get_json()["decision"] == "BLOCK"
    assert owner.post("/api/step-up", json={"attempt_ref": reference, "code": "123456"}).status_code == 409
    conn = db.get_db()
    row = db.get_attempt(conn, reference)
    assert db.is_device_flagged(conn, row["device_id"])
    assert row["claimed_user_ref"] in application.get_graph().blocked_identities
    conn.close()


def test_step_up_expired_and_non_pending_cannot_be_allowed():
    owner = client()
    reference = create_challenge(owner)
    conn = db.get_db()
    conn.execute("UPDATE step_up_challenges SET expires_at='2000-01-01 00:00:00'")
    conn.commit()
    assert owner.post("/api/step-up", json={"attempt_ref": reference, "code": "123456"}).status_code == 410
    assert db.get_attempt(conn, reference)["decision"] == "STEP_UP"
    conn.execute("UPDATE step_up_challenges SET expires_at='2099-01-01 00:00:00'")
    conn.execute("UPDATE attempts SET decision='BLOCK' WHERE attempt_ref=?", (reference,))
    conn.commit()
    assert owner.post("/api/step-up", json={"attempt_ref": reference, "code": "123456"}).status_code == 409
    assert owner.post("/api/step-up", json={"attempt_ref": "ATT-01001", "code": "123456"}).status_code == 404
    conn.close()


def test_pdf_is_accepted_without_image_heatmap():
    response = client().post("/api/verify", data=verification_data())
    assert response.status_code == 200, response.get_json()
    assert response.get_json()["ela_image"] is False
    conn = db.get_db()
    document = conn.execute("SELECT * FROM documents").fetchone()
    assert document["ela_score"] is None
    assert Path(document["path"]).read_bytes().startswith(b"%PDF-")
    conn.close()


@pytest.mark.parametrize("kind", ["fake", "encrypted", "empty", "too_many"])
def test_invalid_pdf_is_rejected_and_removed(kind):
    stream = io.BytesIO()
    if kind == "fake":
        stream.write(b"not a pdf")
    else:
        writer = PdfWriter()
        for _ in range(21 if kind == "too_many" else (0 if kind == "empty" else 1)):
            writer.add_blank_page(width=100, height=100)
        if kind == "encrypted":
            writer.encrypt("password")
        writer.write(stream)
    stream.seek(0)
    response = client().post("/api/verify", data=verification_data(document=(stream, "identity.pdf")))
    assert response.status_code == 400
    assert list(Path(config.UPLOAD_DIR).glob("*")) == []


@pytest.mark.parametrize("overrides,field", [
    ({"full_name": ""}, "full_name"), ({"date_of_birth": "2025-02-30"}, "date_of_birth"),
    ({"date_of_birth": "2999-01-01"}, "date_of_birth"), ({"phone": "wrong"}, "phone"),
    ({"email": "wrong"}, "email"), ({"liveness": "maybe"}, "liveness"),
    ({"user_ref": "../bad"}, "user_ref"), ({"address": "a" * 301}, "address"),
    ({"document": None}, "document"),
])
def test_invalid_input_has_no_side_effects(overrides, field):
    data = verification_data(**overrides)
    if data.get("document") is None:
        del data["document"]
    response = client().post("/api/verify", data=data)
    assert response.status_code == 400
    assert field in response.get_json()["fields"]
    conn = db.get_db()
    assert db.get_stats(conn)["total"] == 1
    assert conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0] == 0
    conn.close()


def test_csrf_on_all_mutations(monkeypatch, application):
    monkeypatch.setitem(application.app.config, "WTF_CSRF_ENABLED", True)
    handle = client()
    for route in ("/api/verify", "/api/step-up", "/api/simulate/legitimate"):
        assert handle.post(route).status_code == 400
    html = handle.get("/verify").get_data(as_text=True)
    token = re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)
    response = handle.post("/api/verify", data=verification_data(), headers={"X-CSRFToken": token})
    assert response.status_code == 200


@pytest.mark.parametrize("query", ["limit=x", "limit=0", "offset=-1", "offset=foo"])
def test_bad_pagination_returns_400(query):
    handle = client()
    with handle.session_transaction() as session:
        session["analyst_authenticated"] = True
    assert handle.get("/api/attempts?" + query).status_code == 400
