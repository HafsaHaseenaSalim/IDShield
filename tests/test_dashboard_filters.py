"""
IDShield — analyst dashboard filter regression tests.

Root cause of the reported bug: the risk-score histogram ("bar graph") and
the attempts table are two separate pieces of UI, fed by two separate
endpoints. The filter <select> change listeners only ever called
loadAttempts() (the table), never loadStats() (the histogram) - and even if
they had, /api/stats and database.get_score_histogram() accepted no filter
parameters at all, so the histogram always described every attempt
regardless of the controls next to it. Both layers are covered here: the
database helper directly, the HTTP endpoint, and (implicitly, since the
table filter was already correct and unchanged) the existing attempts-table
behaviour.
"""

from pathlib import Path

import config
import database as db


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


def _seed_attempts(conn):
    # The isolated test fixture already inserts one demo attempt
    # (ATT-01001); clear it so these tests describe an exact, self-contained
    # count instead of "the fixture row plus N more".
    conn.execute("DELETE FROM attempts")
    conn.commit()
    rows = [
        ("FILT-A1", "ALLOW", "LEGITIMATE", 5),
        ("FILT-A2", "ALLOW", "LEGITIMATE", 15),
        ("FILT-A3", "STEP_UP", "CREDENTIAL_STUFFING", 45),
        ("FILT-A4", "BLOCK", "CREDENTIAL_STUFFING", 95),
    ]
    for ref, decision, scenario, score in rows:
        db.insert_attempt(conn, {
            "attempt_ref": ref, "timestamp": db.utcnow(), "claimed_user_ref": ref,
            "decision": decision, "scenario": scenario, "risk_score": score,
        })


def _histogram_total(payload):
    return sum(bucket["count"] for bucket in payload["score_histogram"])


# ---------------------------------------------------------------------------
# database.get_score_histogram() — the layer that previously ignored filters
# ---------------------------------------------------------------------------

def test_score_histogram_helper_supports_decision_and_scenario_filters():
    conn = db.get_db()
    _seed_attempts(conn)

    everything = db.get_score_histogram(conn)
    allow_only = db.get_score_histogram(conn, decision="ALLOW")
    step_only = db.get_score_histogram(conn, decision="STEP_UP")
    block_only = db.get_score_histogram(conn, decision="BLOCK")
    stuffing_only = db.get_score_histogram(conn, scenario="CREDENTIAL_STUFFING")
    combined = db.get_score_histogram(conn, decision="BLOCK", scenario="CREDENTIAL_STUFFING")
    conn.close()

    assert sum(b["count"] for b in everything) == 4
    assert sum(b["count"] for b in allow_only) == 2
    assert sum(b["count"] for b in step_only) == 1
    assert sum(b["count"] for b in block_only) == 1
    assert sum(b["count"] for b in stuffing_only) == 2
    assert sum(b["count"] for b in combined) == 1


def test_score_histogram_helper_returns_zero_state_for_no_matches():
    conn = db.get_db()
    _seed_attempts(conn)
    histogram = db.get_score_histogram(conn, decision="BLOCK", scenario="LEGITIMATE")
    conn.close()
    assert len(histogram) == 10                       # still every bucket, not an empty list
    assert sum(b["count"] for b in histogram) == 0     # but all of them empty


# ---------------------------------------------------------------------------
# /api/stats — the endpoint the dashboard's histogram actually calls
# ---------------------------------------------------------------------------

def test_api_stats_with_no_filter_returns_the_full_histogram():
    conn = db.get_db()
    _seed_attempts(conn)
    conn.close()
    handle = employee_client()
    payload = handle.get("/api/stats").get_json()
    assert _histogram_total(payload) == payload["total"] == 4


def test_api_stats_filters_histogram_by_decision_allow():
    conn = db.get_db()
    _seed_attempts(conn)
    conn.close()
    handle = employee_client()
    payload = handle.get("/api/stats?decision=ALLOW").get_json()
    assert _histogram_total(payload) == 2


def test_api_stats_filters_histogram_by_decision_step_up():
    conn = db.get_db()
    _seed_attempts(conn)
    conn.close()
    handle = employee_client()
    payload = handle.get("/api/stats?decision=STEP_UP").get_json()
    assert _histogram_total(payload) == 1


def test_api_stats_filters_histogram_by_decision_block():
    conn = db.get_db()
    _seed_attempts(conn)
    conn.close()
    handle = employee_client()
    payload = handle.get("/api/stats?decision=BLOCK").get_json()
    assert _histogram_total(payload) == 1


def test_api_stats_filters_histogram_by_attack_type():
    conn = db.get_db()
    _seed_attempts(conn)
    conn.close()
    handle = employee_client()
    payload = handle.get("/api/stats?scenario=CREDENTIAL_STUFFING").get_json()
    assert _histogram_total(payload) == 2


def test_api_stats_nonexistent_filter_combination_is_an_explicit_zero_not_stale_data():
    conn = db.get_db()
    _seed_attempts(conn)
    conn.close()
    handle = employee_client()
    payload = handle.get("/api/stats?decision=BLOCK&scenario=LEGITIMATE").get_json()
    assert _histogram_total(payload) == 0
    assert len(payload["score_histogram"]) == 10


def test_api_stats_selecting_all_again_restores_the_full_histogram():
    conn = db.get_db()
    _seed_attempts(conn)
    conn.close()
    handle = employee_client()
    filtered = handle.get("/api/stats?decision=BLOCK").get_json()
    assert _histogram_total(filtered) == 1
    restored = handle.get("/api/stats").get_json()
    assert _histogram_total(restored) == restored["total"] == 4


def test_summary_stat_cards_remain_unfiltered_by_design():
    """The four top cards ("Total attempts" etc.) intentionally describe
    every attempt regardless of the filter, matching the existing
    "Summary totals cover all attempts" caption next to the table - only the
    histogram is filter-scoped."""
    conn = db.get_db()
    _seed_attempts(conn)
    conn.close()
    handle = employee_client()
    filtered = handle.get("/api/stats?decision=ALLOW").get_json()
    unfiltered = handle.get("/api/stats").get_json()
    assert filtered["total"] == unfiltered["total"] == 4
    assert filtered["allowed"] == unfiltered["allowed"] == 2


def test_dashboard_filter_selects_are_still_wired_to_the_attempts_table():
    """Unchanged behaviour: /api/attempts filtering, which was already
    correct, must keep working exactly as before."""
    conn = db.get_db()
    _seed_attempts(conn)
    conn.close()
    handle = employee_client()
    rows = handle.get("/api/attempts?decision=BLOCK").get_json()
    assert [r["attempt_ref"] for r in rows] == ["FILT-A4"]


def test_anonymous_users_cannot_read_filtered_stats():
    response = client().get("/api/stats?decision=BLOCK")
    assert response.status_code in (302, 401, 403)


# ---------------------------------------------------------------------------
# The actual client-side wiring: change listeners call loadStats too
# ---------------------------------------------------------------------------

def test_dashboard_javascript_refreshes_the_histogram_on_filter_change():
    """Lightest possible check that the fix is actually wired up client-side,
    without pulling in a browser-automation framework: the filter change
    handler in app.js must call loadStats() (which renders the histogram),
    not only loadAttempts() (which renders the table)."""
    app_js = Path(__file__).resolve().parents[1] / "static" / "app.js"
    source = app_js.read_text(encoding="utf-8")
    start = source.index('"filter-decision", "filter-scenario"')
    handler = source[start:start + 400]
    assert "loadStats()" in handler
    assert "loadAttempts()" in handler
