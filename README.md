# IDShield

Explainable fraud detection for a **simulated** digital identity workflow.
The existing Flask application, rule engine and Random Forest are retained.
There is no OCR, real biometric liveness, external identity service or cloud dependency.

## Run locally

Python 3.12 is supported. From this folder on Windows:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe seed.py
.\.venv\Scripts\python.exe app.py
```

Open http://127.0.0.1:5000. The home page links to two portals:

- **Citizen portal** (`/customer/login`) — demo account `citizen@idshield.demo` / `Citizen123!`.
- **Employee portal** (`/employee/login`, alias `/login`) — demo account
  `analyst@idshield.demo` / `Analyst123!`. Environment overrides are
  `IDSHIELD_ANALYST_USER`, `IDSHIELD_ANALYST_PASSWORD` and `IDSHIELD_SECRET_KEY`.

Both demo accounts are seeded idempotently by `seed.py` and by the app itself on
startup (`database.seed_demo_accounts`), so they exist even on a fresh checkout.

This checkout already has a `.venv`; use its Python executable if `python` is not on PATH.
A full seed generates the training corpus, calibrates ELA, fits the existing model,
replays the dashboard corpus, and evaluates separate synthetic traffic. It can take
several minutes, especially without cached images.

## Reset and simulator behavior

| Command | Behavior |
|---|---|
| `python seed.py` | Clear demo attempts, users, reasons, audit, challenges and reputation; clear generated uploads; rebuild model and metrics |
| `python seed.py --small` | Same reset with a smaller training and evaluation corpus |
| `python seed.py --no-model` | Fresh rule-only demo; remove stale model and metrics files |
| `python seed.py --keep` | Append traffic using the existing model and calibration; preserve earlier decisions, challenges and evaluation metrics |

`--keep --no-model` is rejected because the options conflict. Full and small document
pools have separate manifests; individual document caches include their generation
inputs. Repeated runs continue timestamps and allocate new identity references.
Credential-stuffing gaps advance once per attempt, preserving the intended burst.

An open app temporarily returns a clear maintenance response during seeding. It reloads
its model, graph, forensic cache, calibration and limiter state when the generation
changes. If seeding fails, rerun `seed.py`; partial state is not presented as a completed
demo. A fresh reset clears earlier step-up ownership, even when attempt references repeat.

Simulator buttons append traffic to the same demo database. Earlier activity affects
later decisions. Credential stuffing needs a population: seed first or generate a
legitimate citizen. The simulator page and its API sit behind employee
authentication, the same as the analyst console.

## Verification and step-up

`/verify` requires name, a valid birth date, nationality, international phone number,
email, address, device ID, document and an explicit simulated liveness result.
Backend validation runs before upload storage or scoring and returns field errors.
Identity/device references accept letters, digits, underscores and hyphens. Requests
with invalid pagination also return 400 rather than a server error.

- JPG/JPEG/PNG: structurally validated, analysed before re-encoding, then sanitised.
- PDF: parsed with pypdf; 1–20 pages, unencrypted, with a valid PDF signature.
  Invalid files are removed. PDFs receive metadata and exact-file-hash analysis only;
  no PDF ELA heatmap is claimed. They remain private and are not served as active content.
- Upload/request size limit: 5 MB.
- Liveness and password input remain simulated; neither proves identity or authenticates a citizen.

Scores below 30 allow, 30–69 request step-up, and 70 or above block. Step-up uses the
published demo code `123456`; no SMS or email is sent. A challenge is tied to the browser
session and attempt, expires after five minutes, and can be resolved once. Only a pending
step-up can change outcome. A correct code allows; a wrong six-digit code blocks and
updates reputation. Missing/malformed codes do not consume it. Expired challenges require
a fresh verification. Other sessions cannot resolve it, and blocked/allowed decisions
cannot be overridden through this endpoint.

The original risk score, initial decision and reason chain remain intact. Current outcome
and step-up result are stored separately. Browser POST requests, including verification,
simulation and step-up, send CSRF tokens.

## Authentication

Two separate, non-overlapping session types:

- **Customer** (`/customer/login`, `/customer/logout`) — citizens signing in to an
  existing digital ID. Credential check and fraud scoring are separate controls: a
  wrong password is always refused, full stop, regardless of risk score. A correct
  password then runs through the same rule/model engine as `/verify` (stage
  `LOGIN`) and resolves to ALLOW (session created), STEP_UP (the existing `123456`
  challenge, session created only after it passes) or BLOCK (refused). Failed and
  blocked logins are recorded and feed the same velocity/reputation rules as
  onboarding attempts.
- **Employee** (`/employee/login`, `/employee/logout`, alias `/login`/`/logout`) —
  fraud analysts, checked against a separate `employees` table (email or employee
  ID + password, active flag). This is the only session type `security.login_required`
  accepts, so it gates `/dashboard`, all `/api/*` analyst endpoints, and the
  simulator (`/simulator`, `/api/simulate/*`). A customer session can never satisfy
  it.

Both flows log outcome events to the existing audit log (`CUSTOMER_LOGIN_SUCCESS`,
`CUSTOMER_LOGIN_FAILURE`, `CUSTOMER_LOGIN_BLOCKED`, `CUSTOMER_STEP_UP_REQUIRED`,
`CUSTOMER_LOGOUT`, `EMPLOYEE_LOGIN_SUCCESS`, `EMPLOYEE_LOGIN_FAILURE`,
`EMPLOYEE_LOGOUT`) and never log a plaintext password, a password hash, the OTP
value, a session ID or a CSRF token.

## Architecture

A modular monolith: Jinja templates and dependency-free JavaScript call Flask JSON routes.
SQLite stores attempts and evidence. The NetworkX graph, model and caches are process-local.

```text
Browser / simulator -> Flask orchestration -> FraudEngine
                                            | rules and reputation
                                            | document forensics
                                            | NetworkX identity links
                                            | existing Random Forest
                                            -> score + reasons -> SQLite
```

| File | Responsibility |
|---|---|
| `app.py` | Routes, input boundary, step-up state transitions, runtime refresh |
| `database.py` | SQLite schema/migrations, persistence, reset |
| `fraud_engine.py` | Rules, 15 features, blend and decision |
| `forensics.py` | Metadata, SHA-256, perceptual hash calculation, image ELA |
| `graph_engine.py` | Shared attributes, clusters and masked dashboard payloads |
| `ml_engine.py` | Existing Random Forest training and separate evaluation |
| `simulator.py`, `docgen.py` | Synthetic traffic and document generation |
| `seed.py` | Reproducible bootstrap, historical replay, independent evaluation |
| `security.py` | Validation, uploads, CSRF, headers, rate limits, masking |
| `static/app.js`, `static/style.css`, `templates/` | Verification, simulator, dashboard |

With a model: `score = 0.70 * rule_points + 0.30 * fraud_probability * 100`,
followed by policy floors, rounding and clipping to 0–100. Without a model, rule points
and the same floors determine the score. Model contribution labels are approximate
global feature-importance context, not exact per-attempt attribution.

## Corrected metrics

`models/metrics.json` is the source for the dashboard. The previous README figures and
random attempt-level 70/30 evaluation have been superseded.

1. Calibrate ELA on the training document pool only.
2. Generate training traffic and fit the **same Random Forest configuration**.
3. Replay the dashboard corpus against an empty historical database, adding each attempt
   only after scoring it. Future document reuse and the current attempt cannot leak into
   history counts. Ages use the attempt date. Previous decisions do not enter the graph
   before they have been recomputed.
4. Freeze the model and ELA threshold. Generate an independent evaluation replay with
   seed `10042`, a separate database/graph/reputation state, separate document files and
   `EVAL-` identity references. Assert no exact document hashes overlap training.
5. Report classifier accuracy, class precision/recall/F1 and AUC separately from the
   engine's legitimate-block rate, legitimate-step-up rate and attack challenge/block rate.

No simulated document-name mismatch feature is injected: there is no OCR in the live
path. The ELA calibration fit is labelled as a fit, not held-out accuracy. Missing AUC
is displayed as unavailable. Live `UNKNOWN` traffic is excluded from labelled evaluation.
A `--keep` run does not silently overwrite the saved evaluation report.

These remain **synthetic, same-simulator-distribution results**. A different seed and
separate state remove the old split/replay problems but do not establish real-world
performance. Dashboard totals describe the displayed corpus; evaluation metrics describe
the separate evaluation corpus, so their counts are intentionally different.

## Dashboard and graph

The dashboard distinguishes current outcomes from original score bands and shows when a
step-up was resolved. Filters apply to the latest 150 matching attempts; summary totals
cover all attempts. The histogram includes 100 in its final bucket. Late responses cannot
replace a more recently selected record. Empty results and expired analyst sessions are
reported clearly.

Graph circles are identities; attribute diamonds show shared values. Dashed device/address
links are weak on their own; solid phone/exact-document links carry stronger policy weight.
IP-only connections are omitted, matching the scoring cluster. Phones/addresses are masked
and node IDs are opaque. The focused identity remains visible even when the 180-node cap
is reached, and truncation is disclosed.

The graph shows **current accumulated links**, not a historical snapshot. The stored reason
chain explains the original assessment. Shared values are evidence to inspect, not proof
that the connected people committed fraud.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest tests -q
```

Tests use temporary databases, upload directories and model paths, and reset application
caches/rate limits between cases. They do not require a seeded demo or alter its records.
Coverage includes step-up ownership, replay, expiry, immutable original evidence, PDF
acceptance/rejection, backend validation, CSRF, original security checks, simulator clock,
reset/append semantics, historical replay, graph masking and the score-100 histogram bucket.
The two original test-file entry points also invoke pytest with these isolated fixtures.

## External Dataset Evaluation

`evaluate_dataset.py` scores a CSV/JSON/JSONL dataset that did **not** come from
the simulator, using the exact same `FraudEngine` the live app uses — no
scoring logic is duplicated. It does not start Flask and never touches
`database/fraud.db`: everything runs against a disposable in-memory database.

```powershell
.\.venv\Scripts\python.exe evaluate_dataset.py sample_datasets/sample_unlabeled.csv
.\.venv\Scripts\python.exe evaluate_dataset.py sample_datasets/sample_labeled.csv --output results.csv
.\.venv\Scripts\python.exe evaluate_dataset.py data.jsonl --documents-dir path/to/documents
```

**Formats**: `.csv`, `.json` (a top-level array, or `{"records": [...]}`), `.jsonl`
(one JSON object per line). A malformed file is reported as a clean one-line
error, never a traceback; one bad *row* inside an otherwise-valid file is
marked `status=ERROR` with a reason and does not stop the rest of the batch.

**Only required field**: an identity/account identifier (`user_ref`). Every
other field is optional — missing signals are simply not scored on.

**Column aliases** (case/spacing-insensitive, first match wins):

| Canonical field | Accepted aliases |
|---|---|
| `user_ref` | `user_id`, `customer_id`, `identity_id`, `account`, `account_id`, `username` |
| `ip_address` | `ip`, `source_ip`, `client_ip` |
| `device_id` | `device`, `device_fingerprint` |
| `date_of_birth` | `dob`, `birth_date` |
| `timestamp` | `time`, `datetime`, `event_time` |
| `login_success` | `login_result`, `success`, `authentication_success` |
| `email` | `email_address`, `mail` |
| `liveness_status` | `liveness`, `liveness_result` |
| `document_hash` / `document_phash` / `document_anomaly` | `doc_hash` / `doc_phash`, `phash` / `ela_score`, `anomaly_score` |
| `label` (metrics only, never scored on) | `is_fraud`, `fraud`, `attack_type`, `scenario` |

**Timestamps**: `YYYY-MM-DD HH:MM:SS`, ISO 8601 with or without `T`/`Z`/an
offset, or a Unix epoch (seconds or milliseconds). All are normalized to
timezone-aware UTC. Records are **sorted chronologically before scoring**,
regardless of file order, and each one is scored using only records that
happened strictly before it — velocity, document reuse, device/IP
reputation and identity-graph links can never see a future event. A record
with no parseable timestamp sorts after every timestamped one (it can never
appear to precede something) and keeps its original file order among ties.

**Booleans** (`login_success`, `liveness_status`): `true/false`, `1/0`,
`yes/no`, `success/failure`, `pass/fail`, `allow/block` all normalize
consistently; anything unrecognized is treated as not submitted.

**Documents**: if `document_path` is given, it is only read when it resolves
inside an explicitly allowed directory (`--documents-dir`, default: the
dataset file's own folder) — no path traversal. Without a file, `document_hash`
/ `document_phash` / `document_anomaly` (an ELA-style score) are used directly
if present. No document reference at all is fine; the document rule set is
simply not scored.

**Output** — `results.csv` (or `--output`) always, one row per input record:
`record_id, user_ref, normalized_timestamp, risk_score, decision,
predicted_attack, fraud_probability, rule_score, top_reasons, status,
error_reason`. `decision` is always `ALLOW` / `STEP_UP` / `BLOCK` — the same
three outcomes as everywhere else. `predicted_attack`
(`LEGITIMATE` / `CREDENTIAL_STUFFING` / `SYNTHETIC_IDENTITY` / `DOCUMENT_FRAUD`
/ `SUSPICIOUS` / `UNKNOWN`) is derived only from which of the engine's own
rules fired — never from a ground-truth label.

**Labeled metrics**: if a `label`/`is_fraud`/`fraud`/`attack_type`/`scenario`
column is present, it is detected and used **only after** scoring to write
`metrics.json` next to the results file — `accuracy`, `precision`, `recall`,
`f1`, `roc_auc` (when both classes and probabilities are available),
`false_positive_rate`, `false_negative_rate`, `legitimate_block_rate`,
`legitimate_step_up_rate`, `attack_detection_rate` and per-attack-type
detection. A recognized "legitimate" spelling (`legitimate`, `benign`,
`normal`, `0`, `false`, `no`, ...) is the negative class; any other non-empty
value is treated as a fraud/attack label, whatever its exact spelling. If no
label column is found, no `metrics.json` is written and no accuracy is
claimed — only the predictions themselves.

`sample_datasets/sample_unlabeled.csv` and `sample_datasets/sample_labeled.csv`
are small, hand-built illustrations of the input format (legitimate traffic,
a credential-stuffing burst, a synthetic-identity ring, a document-fraud
signal, and missing optional fields) — **not** a benchmark. As with the rest
of this project: synthetic/demo metrics are not evidence of production
performance.

## Limits of this demo

Run on localhost with simulated documents. Default credentials and the development secret
are intentional demo defaults. SQLite, process-local graphs/caches and in-memory rate
limits are not a multi-worker deployment design. Upload validation is not antivirus scanning.
Pinned dependencies are not evidence of a completed vulnerability audit. Exact SHA-256
reuse is scored; perceptual hashes are computed but near-duplicate matching is not implemented.
No new models, OCR, cloud migration or additional product features were added.
