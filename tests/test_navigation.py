"""
IDShield — navbar / Simulator vs. Analyst console routing regression tests.

Covers the reported "Analyst console keeps me on the Simulator page" bug.
Investigation: /simulator and /dashboard were already distinct Flask routes
(app.py) with distinct hrefs in the shared nav (base.html); a live browser
check confirmed clicking each link does navigate to the correct page. These
tests lock that in as an explicit regression guard, and also cover the
genuine gap found alongside it: the nav had no "current page" indication at
all, so nothing distinguished Simulator-active from Analyst-console-active
in the markup - see the data-page-scoped CSS rule in style.css.
"""

import re

import config
from helpers import verification_data


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


def _nav_hrefs(html):
    """The two nav links' hrefs, keyed by their visible label."""
    hrefs = {}
    for label, pattern in (
        ("Simulator", r'<a href="([^"]+)">Simulator</a>'),
        ("Analyst console", r'<a href="([^"]+)">Analyst console</a>'),
    ):
        match = re.search(pattern, html)
        assert match, "nav link for %r not found in rendered page" % label
        hrefs[label] = match.group(1)
    return hrefs


# ---------------------------------------------------------------------------
# 1 & 2 & 3 — distinct routes, each nav link resolves to its own page
# ---------------------------------------------------------------------------

def test_simulator_and_dashboard_are_different_routes():
    import app as application
    simulator_rule = application.app.url_map.bind("localhost").match("/simulator", method="GET")
    dashboard_rule = application.app.url_map.bind("localhost").match("/dashboard", method="GET")
    assert simulator_rule != dashboard_rule
    assert simulator_rule[0] != dashboard_rule[0]  # different endpoint/view function


def test_nav_links_point_to_distinct_hrefs_on_every_page():
    handle = employee_client()
    for path in ("/", "/simulator", "/dashboard"):
        html = handle.get(path).get_data(as_text=True)
        hrefs = _nav_hrefs(html)
        assert hrefs["Simulator"] == "/simulator"
        assert hrefs["Analyst console"] == "/dashboard"
        assert hrefs["Simulator"] != hrefs["Analyst console"]


def test_following_the_analyst_console_link_opens_the_dashboard_not_the_simulator():
    handle = employee_client()
    # Start on the Simulator page, then follow the href the nav actually has.
    on_simulator = handle.get("/simulator")
    hrefs = _nav_hrefs(on_simulator.get_data(as_text=True))

    response = handle.get(hrefs["Analyst console"])
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Analyst console" in body
    assert "Fraud simulator" not in body


def test_following_the_simulator_link_opens_the_simulator_not_the_dashboard():
    handle = employee_client()
    on_dashboard = handle.get("/dashboard")
    hrefs = _nav_hrefs(on_dashboard.get_data(as_text=True))

    response = handle.get(hrefs["Simulator"])
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Fraud simulator" in body
    assert "Original risk score distribution" not in body   # dashboard-only content


def test_active_nav_link_matches_the_current_page_only():
    handle = employee_client()
    simulator_html = handle.get("/simulator").get_data(as_text=True)
    dashboard_html = handle.get("/dashboard").get_data(as_text=True)
    assert 'data-page="simulator"' in simulator_html
    assert 'data-page="dashboard"' in dashboard_html
    assert 'data-page="simulator"' not in dashboard_html
    assert 'data-page="dashboard"' not in simulator_html


# ---------------------------------------------------------------------------
# 4 & 5 — both routes remain employee-protected, auth still works
# ---------------------------------------------------------------------------

def test_simulator_and_dashboard_both_reject_anonymous_users():
    handle = client()
    for path in ("/simulator", "/dashboard"):
        response = handle.get(path)
        assert response.status_code in (302, 401, 403), path
        if response.status_code == 302:
            assert "/login" in response.headers.get("Location", "")


def test_simulator_and_dashboard_both_open_for_a_logged_in_employee():
    handle = employee_client()
    assert handle.get("/simulator").status_code == 200
    assert handle.get("/dashboard").status_code == 200


def test_employee_authentication_still_works():
    handle = client()
    response = handle.post("/employee/login", data={
        "identifier": config.ANALYST_USERNAME, "password": config.ANALYST_PASSWORD})
    assert response.status_code == 302
    assert handle.get("/dashboard").status_code == 200
    bad = client().post("/employee/login", data={
        "identifier": config.ANALYST_USERNAME, "password": "wrong"})
    assert b"Invalid credentials" in bad.data


# ---------------------------------------------------------------------------
# 6 — existing simulator behaviour still works
# ---------------------------------------------------------------------------

def test_simulator_api_still_scores_traffic_for_a_logged_in_employee(monkeypatch):
    import simulator as sim
    monkeypatch.setattr(sim, "ensure_document_pool", lambda **kw: {"clean": [], "tampered": []})
    monkeypatch.setattr(sim.TrafficSimulator, "_unique_document", lambda *args, **kw: None)
    handle = employee_client()
    response = handle.post("/api/simulate/legitimate")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["scenario"] == "legitimate"
    assert payload["generated"] >= 1


# ---------------------------------------------------------------------------
# 7 — the disclaimer footer text is gone from normal pages
# ---------------------------------------------------------------------------

def test_disclaimer_text_is_not_rendered_on_normal_pages():
    handle = employee_client()
    disclaimer = b"Simulated data only"
    for path in ("/", "/verify", "/simulator", "/dashboard", "/employee/login", "/customer/login"):
        body = handle.get(path).data
        assert disclaimer not in body, path


def test_default_legitimate_verification_still_works():
    """Unrelated flow, still exercised end to end as a broad sanity check."""
    response = client().post("/api/verify", data=verification_data())
    assert response.status_code == 200
    assert response.get_json()["decision"] == config.DECISION_ALLOW
