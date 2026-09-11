# IDShield adversarial benchmark — failure analysis

Generated from `benchmark_results/baseline.json` (the system **before** any
change described here) and `benchmark_results/after_improvements.json` (the
one generic fix in section 6). All numbers below are read directly from those
files, not estimated. The benchmark itself is `adversarial_datasets/`, built
by `adversarial_benchmark.py` — deliberately different traffic shapes from
`simulator.py`'s own three attack patterns (see that file's module docstring
for exactly how). These are synthetic demo figures, not evidence of
real-world performance.

## 1. Headline numbers (combined `adversarial_labeled.csv`, 444 records: 201 legitimate / 243 attack)

| | baseline (rules+ML) | rules-only |
|---|---|---|
| precision | 0.913 | 1.000 |
| recall | 0.778 | 0.226 |
| F1 | 0.840 | 0.369 |
| false-positive rate | 0.090 | 0.000 |
| attack detection rate (STEP_UP+BLOCK) | 0.778 | 0.226 |
| legitimate block rate | 0.000 | 0.000 |
| legitimate step-up rate | 0.090 | 0.000 |

## 2. Three biggest weaknesses

### 2.1 Synthetic-identity rings with pairwise/sparse overlap are the weakest category

Baseline per-attack-type recall: **SYNTHETIC_IDENTITY 0.163**, vs.
CREDENTIAL_STUFFING 0.955 and DOCUMENT_FRAUD 0.667. On the hard tier, 4 of 7
synthetic-identity campaigns (`SYN-ADDR`, `SYN-DEVICE`, `SYN-ROTATE`,
`SYN-SPARSE`) were never flagged at all — every member stayed `ALLOW`.

**Why:** `_check_cross_records` scored `CROSS_RECORD_CLUSTER_*` from
`graph.shared_attributes(identity)`, which only reports what THIS identity
directly shares with someone else — a one-hop view. A ring built from
pairwise overlap (A↔B share a phone, B↔C share a device, C↔D share an
address) is one connected cluster of four, but no single member's own direct
shares reveal more than one binding type, so every member scored as a "weak,
single-attribute" cluster regardless of the ring's real size or diversity.
`SYN-ADDR`/`SYN-DEVICE` (one shared attribute across the whole ring, by
design) and `SYN-SPARSE`/`SYN-ROTATE` (deliberately thin connectivity) fail
for the same underlying reason plus weaker connectivity.

**Signals unavailable:** none — the graph already had every edge it needed
(`graph.cluster()` correctly reports all 4 members as one connected
component). The gap was in how the *rule* read the graph, not missing data.

**Fix applied** (see section 4): aggregate binding-kind diversity across the
whole connected cluster (`IdentityGraph.cluster_binding_kinds`) instead of
per-identity. Verified safe against every legitimate benchmark case (section
5) and against all 121 existing tests.

**Residual gap, left alone:** `SYN-ADDR`, `SYN-DEVICE`, `SYN-ROTATE`,
`SYN-SPARSE` are still undetected after the fix (SYNTHETIC_IDENTITY recall
0.163 → 0.245 — real, but partial). Each of those rings is bound by
genuinely only **one** attribute type in total, even measured cluster-wide.
That is indistinguishable, on the evidence available, from a household or a
public kiosk sharing one thing — the exact case the current design already
protects (see `fraud_engine.py`'s own comment on `LINKED_TO_BLOCKED_WEAK`).
Lowering the bar further would very likely raise `legitimate_step_up_rate`
on shared-address/shared-device legitimate traffic; the benchmark does not
currently show that this trade is worth it, so it was not made.

### 2.2 The rule layer alone does not generalize to unseen attack shapes

Rules-only recall on the combined set is **0.226** vs. **0.778** with the
model attached — the rule layer misses roughly 3 out of 4 attacks it does
not see a matching hard threshold for. On the `hard` tier specifically,
rules-only recall drops to **0.158** (`benchmark_results/baseline.json` →
`datasets.hard.rules_only.row_metrics.recall`). Rules-only precision is a
perfect 1.000 with zero false positives throughout — the rule layer is not
wrong when it fires, it simply stays silent on genuinely novel shapes
(distributed/slow/rotating credential stuffing, pairwise synthetic rings,
transformed forged documents).

**Why:** every velocity rule is windowed and keyed on a single field
(`ip_address`, or `claimed_user_ref` for failed logins). Any campaign that
changes IP, device or timing enough per event falls outside all of those
windows simultaneously, and no rule aggregates "many distinct accounts
targeted from many distinct IPs over a longer horizon" on its own.

**What is actually catching these today:** the trained Random Forest, via
`CREDENTIAL_FAILED`/attribute-completeness features generalizing from
"looks like a bare, anonymous login attempt" rather than from the specific
velocity pattern. That is a real, currently load-bearing dependency: if the
model were ever absent or untrained, unseen-shape credential stuffing would
mostly sail through as `ALLOW`. No change was made for this in this task —
extending velocity windows or adding a distinct-IP-count-per-account rule
(section 17) would need its own benchmark pass to confirm it does not raise
legitimate friction on travelling/mobile-network users (section 3), which
this benchmark also exercises and which already contributes to the 9%
legitimate step-up rate below.

### 2.3 Document reuse detection is trivially evaded by ANY file transform, and pHash is not currently a safe substitute

Measured directly (`forensics.file_sha256` / `forensics.perceptual_hash` /
`forensics.phash_distance` over `adversarial_datasets/documents/`):

- **Exact-hash reuse detection: 0 of 15** transformed copies of the same
  forged document matched its own base file's SHA-256 — a resize, a PNG
  conversion, or even a lossless re-save is enough to evade
  `DOCUMENT_REUSE` entirely, since it is keyed on an exact byte hash.
- **pHash distance, same document transformed** (should be small): 0 for
  resize/format-conversion/recompression/screenshot-like re-encoding; 2–6
  for brightness/contrast; 14–16 for cropping. Generally separable.
- **pHash distance, genuinely different documents** (should be large): also
  **0–6** between unrelated synthetic ID cards (`legit_base_easy.jpg` vs.
  `legit_base_medium.jpg` → 0; vs. `forged_base_medium.jpg` → 0).

**Conclusion, per the brief's explicit instruction not to implement a rule
the benchmark cannot justify:** pHash similarity is **not** currently a
safe basis for a cross-record rule on this template family, because our
synthetic ID cards share a near-identical coarse layout across different,
unrelated identities (same header bar, same photo-box position, same
colour blocks) — exactly the coarse structure pHash is designed to match on
and ignore fine detail for. A distance threshold tight enough to catch the
transformed-forgery cases would also match unrelated genuine documents that
merely use the same standardized template, which is common for real national
ID cards. **No pHash-based rule was added.** This is reported as a finding,
not fixed — see section 1's "potential improvements are not automatically
implemented" instruction. A real deployment would need to re-run this same
measurement against real document imagery (varied real photos, not one
generator's coarse template) before trusting any pHash threshold.

**Secondary effect:** DOCUMENT_FRAUD recall (0.667 baseline) is still
noticeably below CREDENTIAL_STUFFING's 0.955 even with reuse detection
aside — the `hard`-tier `double_recompressed` and `screenshot_like`
transforms (multiple extra JPEG generations after the edit) measurably
reduce the surviving Error Level Analysis signal, which is the documented,
expected behaviour of ELA against anti-forensic re-saving
(`docgen.py`'s own `polish` parameter models exactly this) rather than a
bug.

## 3. False positives observed (legitimate traffic)

`legitimate_block_rate` is **0.0 on every tier** — no legitimate benchmark
record was ever hard-`BLOCK`ed, including the deliberately hard cases
(shared household/corporate IPs, common surnames, travelling users, a
same-address-only "roommates" case, and users with several optional fields
missing). `legitimate_step_up_rate` is **0.065 (easy) / 0.077 (medium) /
0.122 (hard) / 0.090 (combined)** — some friction, concentrated in the
`hard` tier's noisier, more incomplete records, but never an outright block.
No specific legitimate case was isolated as a standalone false-positive
trigger strong enough to reach `BLOCK` in this benchmark; the closest
recurring contributor to `STEP_UP` on legitimate rows is the model's
`MODEL_RISK` reason on the more attribute-sparse "missing optional fields"
and "roommate" rows, consistent with the model reacting to profile
incompleteness rather than to any one hard rule misfiring.

## 4. Threshold-band placement (combined `adversarial_labeled.csv`, baseline)

| band | legitimate (n=201) | attack (n=243) |
|---|---|---|
| ALLOW (0–29) | 183 (91.0%) | 54 (22.2%) |
| STEP_UP (30–69) | 18 (9.0%) | 163 (67.1%) |
| BLOCK (70–100) | 0 (0.0%) | 26 (10.7%) |

Reading this honestly: **22.2% of attack records on this adversarial
benchmark remain fully `ALLOW`** — too many, by the brief's own framing —
concentrated in exactly the synthetic-identity and evaded-credential-
-stuffing patterns discussed above. On the legitimate side, thresholds are
not the bottleneck: 91% of legitimate traffic clears cleanly, 9% is
challenged, and none is hard-blocked. This benchmark does not support moving
`THRESHOLD_STEP_UP`/`THRESHOLD_BLOCK` themselves — the miss is concentrated
in specific evidence gaps (sections 2.1–2.3), not in where the existing
score happens to land, and thresholds were not changed.

## 5. Generic improvement made — and why it is safe

`fraud_engine.py::_check_cross_records` and the new
`graph_engine.py::IdentityGraph.cluster_binding_kinds` (see the code
comments there for the full rationale) — CROSS_RECORD_CLUSTER now scores on
the binding-attribute diversity of the identity's **whole connected
cluster**, not just what that one identity directly shares. This is generic
(pure graph-structure logic, no benchmark-specific values, IDs, IPs, hashes
or labels anywhere in it) and satisfies all five conditions in the brief:

1. Real weakness demonstrated — section 2.1.
2. Generic, not dataset-specific — a graph-connectivity aggregation, nothing
   about this dataset's specific names/IPs/campaign IDs is referenced.
3. Defensible rationale — the existing rule's own docstring already states
   the intent ("scored by how many INDEPENDENT identifiers bind the
   cluster"); this fix makes the code match that stated intent for
   multi-hop clusters, it does not change the intent.
4. No legitimate-traffic harm: `legitimate_block_rate` and
   `legitimate_step_up_rate` are **byte-for-byte identical** before and
   after, on every tier (compare `baseline.json` and
   `after_improvements.json`) — every legitimate benchmark case in this
   suite (household, corporate/NAT, common surname, travelling, roommate,
   partial-data) is either IP-only-linked (already excluded from
   clustering) or shares only one attribute type cluster-wide, so its
   binding-kind count is unchanged by this fix either way.
5. All 121 existing tests still pass (`python -m pytest tests -q`).

## 6. Remaining risks / not addressed here

- No fix was made for the credential-stuffing generalization gap (2.2) or
  the document-transform-evasion gap (2.3) — both would need their own
  targeted benchmark iteration to confirm a fix does not raise legitimate
  friction, per the brief's explicit "only tune with evidence" instruction.
- `adversarial_datasets/documents/` uses the same synthetic card generator
  as the rest of the demo (`docgen.py`); the pHash finding in particular is
  specific to that generator's coarse visual template and may not transfer
  to real document imagery in either direction.
- This benchmark is still synthetic, generated data. It is a genuinely
  different distribution from `simulator.py`'s training/demo traffic, which
  is the point of it, but it is not real unseen data and should not be
  read as one.
