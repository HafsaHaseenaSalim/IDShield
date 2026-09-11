"""
IDShield — web layer and security tests.

These cover the things a reviewer should actually check on a system that holds
identity data, and each one corresponds to a control described in the README:

  * the analyst console cannot be read without authenticating;
  * attacker-controlled text cannot become markup (stored XSS);
  * the Content-Security-Policy is strict enough to matter;
  * the ELA endpoint cannot be walked out of its directory;
  * contact details are masked wherever they are displayed;
  * malformed and hostile requests get an error, not a stack trace.

Run:  python tests/test_web_security.py
  or: python -m pytest tests/test_web_security.py -v
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config                                                   # noqa: E402
import database as db                                           # noqa: E402
from helpers import verification_data


def client():
    """A Flask test client with a signed-out session."""
    import app as application
    application.app.config["TESTING"] = True
    application.app.config["WTF_CSRF_ENABLED"] = False   # exercised separately
    return application.app.test_client()


def authed_client():
    handle = client()
    handle.post("/login", data={"username": config.ANALYST_USERNAME,
                                "password": config.ANALYST_PASSWORD})
    return handle


# ---------------------------------------------------------------------------
# Access control
# ---------------------------------------------------------------------------

ANALYST_ONLY = [
    "/dashboard", "/api/stats", "/api/attempts", "/api/metrics",
    "/api/security", "/api/export.csv", "/api/attempt/ATT-01001",
    "/api/graph/SIM-00001", "/api/document/deadbeef/ela",
]


def test_analyst_endpoints_reject_anonymous_users():
    """Every analyst surface must redirect or refuse when signed out."""
    handle = client()
    for path in ANALYST_ONLY:
        response = handle.get(path)
        assert response.status_code in (302, 401, 403), \
            "%s was reachable while signed out (%d)" % (path, response.status_code)
        if response.status_code == 302:
            assert "/login" in response.headers.get("Location", "")


def test_analyst_endpoints_open_after_login():
    handle = authed_client()
    for path in ("/dashboard", "/api/stats", "/api/attempts", "/api/metrics",
                 "/api/security", "/api/export.csv"):
        assert handle.get(path).status_code == 200, path


def test_bad_credentials_are_refused():
    handle = client()
    for username, password in (("analyst", "wrong"), ("wrong", config.ANALYST_PASSWORD),
                               ("", ""), ("analyst", "")):
        handle.post("/login", data={"username": username, "password": password})
        assert handle.get("/api/stats").status_code in (302, 401, 403)


def test_logout_clears_the_session():
    handle = authed_client()
    assert handle.get("/api/stats").status_code == 200
    handle.get("/logout")
    assert handle.get("/api/stats").status_code in (302, 401, 403)


# ---------------------------------------------------------------------------
# Injection
# ---------------------------------------------------------------------------

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg/onload=alert(1)>",
]


def test_submitted_values_are_never_reflected_as_markup():
    """
    A name field containing a script tag must come back as data, never as HTML.

    The API returns JSON and the front end writes every value with textContent,
    so a payload should survive as literal text with its angle brackets JSON-
    escaped, and must never appear raw inside an HTML response body.
    """
    handle = client()
    for payload in XSS_PAYLOADS:
        response = handle.post("/api/verify", data=verification_data(full_name=payload, user_ref="XSS-TEST"))
        assert response.status_code == 200
        assert response.mimetype == "application/json", \
            "verification must answer with JSON, not a rendered page"
        assert b"<script>" not in response.data

    authed = authed_client()
    listing = authed.get("/api/attempts?limit=200")
    assert listing.mimetype == "application/json"
    assert b"<script>alert(1)</script>" not in listing.data


def test_sql_injection_in_query_parameters_is_inert():
    handle = authed_client()
    for payload in ("' OR '1'='1", "'; DROP TABLE attempts; --", "%27%20OR%201=1"):
        response = handle.get("/api/attempts?decision=" + payload)
        assert response.status_code == 200
        assert response.get_json() == []          # matches nothing, executes nothing

    conn = db.get_db()
    try:
        assert conn.execute(
            "SELECT COUNT(*) AS c FROM attempts").fetchone()["c"] > 0, \
            "the attempts table should still exist and be populated"
    finally:
        conn.close()


def test_path_traversal_on_the_document_endpoint_is_refused():
    """
    The ELA path comes from our own database, never from the URL, but the
    endpoint is probed anyway - a lookup that silently accepted '../' would be
    a file-read primitive.
    """
    handle = authed_client()
    for candidate in ("../../etc/passwd", "..%2f..%2fetc%2fpasswd",
                      "....//....//etc/passwd", "/etc/passwd", "%2e%2e%2f",
                      "%2e%2e%2f%2e%2e%2fetc%2fpasswd"):
        # Redirects are followed rather than accepted as a pass: Werkzeug
        # normalises some encoded traversals into a 308, and what matters is
        # where that chain ENDS, not that the first hop was not a 200.
        response = handle.get("/api/document/" + candidate + "/ela",
                              follow_redirects=True)
        assert response.status_code in (400, 403, 404), \
            "traversal candidate %r ended at %d" % (candidate, response.status_code)
        assert b"root:" not in response.data
        assert b"/bin/" not in response.data


# ---------------------------------------------------------------------------
# Headers
# ---------------------------------------------------------------------------

def test_security_headers_are_present_and_strict():
    response = client().get("/")
    csp = response.headers.get("Content-Security-Policy", "")

    assert csp, "no Content-Security-Policy header"
    # The two directives that decide whether CSP can stop an injected script.
    assert "script-src 'self'" in csp
    assert "'unsafe-inline'" not in csp, \
        "'unsafe-inline' defeats the policy: %s" % csp
    assert "'unsafe-eval'" not in csp
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "base-uri 'self'" in csp
    # No third-party origin may serve script to this page.
    assert "http://" not in csp and "https://" not in csp

    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert "no-referrer" in response.headers.get("Referrer-Policy", "")


def test_no_inline_script_in_any_template():
    """
    A strict script-src is only true if no page needs inline script. This
    asserts the property directly rather than trusting the header.
    """
    handle = client()
    for path in ("/", "/verify", "/simulator", "/login"):
        body = handle.get(path).data.decode()
        lowered = body.lower()
        start = 0
        while True:
            start = lowered.find("<script", start)
            if start == -1:
                break
            end = lowered.find("</script>", start)
            tag_end = lowered.find(">", start)
            inner = body[tag_end + 1:end].strip() if end != -1 else ""
            assert not inner, "inline script found on %s: %r" % (path, inner[:80])
            assert "src=" in lowered[start:tag_end], \
                "script tag without src on %s" % path
            start = tag_end + 1
        assert " onclick=" not in lowered and " onerror=" not in lowered, \
            "inline event handler on %s" % path


def test_session_cookie_is_hardened():
    handle = client()
    response = handle.post("/login", data={"username": config.ANALYST_USERNAME,
                                           "password": config.ANALYST_PASSWORD})
    cookies = response.headers.getlist("Set-Cookie")
    session_cookie = next((c for c in cookies if c.startswith("session=")), None)
    assert session_cookie, "no session cookie issued on login"
    assert "HttpOnly" in session_cookie, "session cookie readable from JavaScript"
    assert "SameSite" in session_cookie


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

def test_rate_limits_are_actually_attached_to_the_views():
    """
    Regression guard for a security bug that reported itself as fixed.

    An earlier version called limiter.limit(...)(view) AFTER @app.route had
    registered the view. Flask had already stored the undecorated function, so
    the wrapper was discarded: the limit existed in the source, the dashboard
    listed the control as active, and nothing was ever throttled. The code
    looked right, which is what made it dangerous.

    So this asserts the endpoints are genuinely registered with the limiter
    rather than trusting that the call was written somewhere.
    """
    import app as application
    if application.limiter is None:
        return                                     # Flask-Limiter not installed

    marked = application.limiter._marked_for_limiting
    for endpoint in ("api_verify", "analyst_login", "api_step_up"):
        assert any(endpoint in entry for entry in marked), \
            "%s carries no rate limit; the decorator is not taking effect" % endpoint


def test_rate_limiting_actually_returns_429():
    """The functional half: flood the endpoint and require it to start refusing."""
    import app as application
    if application.limiter is None:
        return

    handle = client()
    codes = []
    # Well past the configured 20/minute, from one client address.
    for _ in range(30):
        response = handle.post("/api/verify", data={
            "full_name": "Flood", "liveness": "pass"})
        codes.append(response.status_code)

    assert 429 in codes, "no request was ever throttled: %s" % sorted(set(codes))
    first_429 = codes.index(429)
    assert first_429 >= 5, "throttled implausibly early (at request %d)" % first_429
    # Once throttled it must stay throttled, not flap open again.
    assert codes[-1] == 429

    # Reset so the limit does not leak into other tests in this process.
    try:
        application.limiter.reset()
    except Exception:                              # noqa: BLE001
        pass


# ---------------------------------------------------------------------------
# Data minimisation
# ---------------------------------------------------------------------------

def test_contact_details_are_masked_in_the_analyst_view():
    """An analyst needs to know two records share a number, not what it is."""
    handle = authed_client()
    conn = db.get_db()
    try:
        row = conn.execute(
            "SELECT attempt_ref, phone FROM attempts"
            " WHERE phone IS NOT NULL AND phone != '' LIMIT 1"
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return                                    # nothing to assert against

    payload = handle.get("/api/attempt/" + row["attempt_ref"]).get_json()
    shown = payload["attempt"]["phone"] or ""
    assert row["phone"] not in shown, "raw phone number exposed"
    assert shown.startswith("***")


def test_export_does_not_leak_contact_details():
    """
    The export carries operational fields only.

    Columns are compared exactly rather than by substring: 'ip_address' is a
    legitimate investigative field and contains the word 'address', so a loose
    match reports a leak that is not there.
    """
    body = authed_client().get("/api/export.csv").data.decode()
    lines = body.splitlines()
    columns = {name.strip().lower() for name in lines[0].split(",")}

    for forbidden in ("phone", "email", "address", "date_of_birth",
                      "full_name", "password_hash"):
        assert forbidden not in columns, "%s exported in the CSV" % forbidden

    # And check the data itself, not only the header: a real phone number from
    # the database must not appear anywhere in the file.
    conn = db.get_db()
    try:
        row = conn.execute(
            "SELECT phone, email FROM attempts"
            " WHERE phone IS NOT NULL AND phone != '' LIMIT 1"
        ).fetchone()
    finally:
        conn.close()
    if row:
        assert row["phone"] not in body
        if row["email"]:
            assert row["email"] not in body


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------

def test_malformed_requests_do_not_return_stack_traces():
    handle = client()
    probes = [
        ("post", "/api/verify", {}),
        ("post", "/api/simulate/../../etc", None),
        ("post", "/api/simulate/does-not-exist", None),
        ("get", "/api/attempt/../../etc/passwd", None),
        ("get", "/nope", None),
    ]
    for method, path, data in probes:
        response = getattr(handle, method)(path, data=data)
        assert response.status_code < 500, "%s %s -> %d" % (method, path, response.status_code)
        assert b"Traceback" not in response.data
        assert b"Werkzeug" not in response.data


def test_step_up_rejects_wrong_and_missing_codes():
    handle = client()
    # Address names a country so the phone/residence check has something to
    # compare against - see PHONE_RESIDENCE_MISMATCH in fraud_engine.py.
    created = handle.post("/api/verify", data=verification_data(
        liveness="fail", email="test@mailinator.com", phone="+447700900123",
        address="12 Test Street, UAE")).get_json()
    assert created["decision"] == "STEP_UP"

    assert handle.post("/api/step-up", json={
        "attempt_ref": created["attempt_ref"]}).status_code == 400

    assert handle.post("/api/step-up", json={
        "attempt_ref": created["attempt_ref"], "code": "000000"}).get_json()["passed"] is False
    assert handle.post("/api/step-up", json={}).status_code == 400
    assert handle.post("/api/step-up", data="not json").status_code == 400


def test_oversized_upload_is_refused():
    import io
    handle = client()
    payload = b"x" * (config.MAX_UPLOAD_BYTES + 2048)
    response = handle.post("/api/verify", data={
        "full_name": "Big File", "liveness": "pass",
        "document": (io.BytesIO(payload), "big.jpg"),
    }, content_type="multipart/form-data")
    assert response.status_code in (400, 413)
    assert b"Traceback" not in response.data


# ---------------------------------------------------------------------------

def _run_all():
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
