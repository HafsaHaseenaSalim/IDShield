"""Every test owns its database, files, model state and rate-limit counters."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
import config
import database as db


@pytest.fixture
def application(isolated_app):
    import app
    return app


@pytest.fixture(autouse=True)
def isolated_app(tmp_path, monkeypatch):
    for name, relative in {
        "DATABASE_PATH": "database/fraud.db", "UPLOAD_DIR": "uploads",
        "ASSET_DOC_DIR": "documents", "MODEL_DIR": "models",
        "MODEL_PATH": "models/risk_model.joblib", "METRICS_PATH": "models/metrics.json",
        "ELA_CALIBRATION_PATH": "models/ela_calibration.json",
    }.items():
        monkeypatch.setattr(config, name, str(tmp_path / relative))
    db.init_db()
    conn = db.get_db()
    db.insert_attempt(conn, {
        "attempt_ref": "ATT-01001", "timestamp": "2026-01-01 00:00:00",
        "claimed_user_ref": "SIM-00001", "full_name": "Fixture Citizen",
        "phone": "+971501234567", "email": "fixture@example.com",
        "decision": "ALLOW", "scenario": "LEGITIMATE", "features": {"ela_score": 0},
    })
    db.upsert_user(conn, {"user_ref": "SIM-00001", "full_name": "Fixture Citizen"})
    db.seed_demo_accounts(conn)
    conn.commit()
    conn.close()
    import app as application
    application.GRAPH = None
    application.RUNTIME_VERSION = None
    application.DOC_CACHE.clear()
    monkeypatch.setitem(application.app.config, "TESTING", True)
    monkeypatch.setitem(application.app.config, "WTF_CSRF_ENABLED", False)
    if application.limiter:
        application.limiter.reset()
    yield
    application.GRAPH = None
    application.DOC_CACHE.clear()
