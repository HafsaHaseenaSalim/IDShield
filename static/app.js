/* =========================================================================
   IDShield front-end.

   Two deliberate constraints shape this file:

   1. NO EXTERNAL LIBRARIES. The identity graph is drawn with a small
      force-directed layout written below rather than pulling vis-network or
      d3 from a CDN. Three reasons, in order of importance:
        - a security tool should not load executable code from a third party
          it does not control;
        - it lets the Content-Security-Policy stay 'self' only, with no
          script CDN allowlisted;
        - it works with no internet, which matters when the demo is being
          judged on venue wifi.

   2. NO INLINE SCRIPT. Page controllers are dispatched from the body's
      data-page attribute, so script-src needs no 'unsafe-inline'. That is
      what makes the CSP actually able to stop an injected <script>.

   Everything written into the DOM goes through textContent, never innerHTML,
   so attacker-controlled values (a name field, an attempt reference) are
   inserted as text and can never become markup.
   ========================================================================= */

"use strict";

/* ---------------------------------------------------------------- helpers */

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function decisionPill(decision) {
  const label = String(decision || "").replace("_", "-");
  return el("span", "pill " + String(decision || ""), label);
}

function humanise(value) {
  return String(value || "").replace(/_/g, " ").toLowerCase();
}

async function getJSON(url, options) {
  options = options || {};
  if (options.method && options.method !== "GET") {
    const token = document.querySelector('meta[name="csrf-token"]');
    options.headers = Object.assign({}, options.headers, { "X-CSRFToken": token ? token.content : "" });
  }
  const response = await fetch(url, options);
  if (response.redirected && new URL(response.url).pathname === "/login") {
    throw new Error("Your analyst session has ended. Sign in again.");
  }
  let payload = null;
  try {
    payload = await response.json();
  } catch (err) {
    payload = null;
  }
  if (!response.ok) {
    const fields = payload && payload.fields ? " " + Object.entries(payload.fields)
      .map(function (pair) { return humanise(pair[0]) + ": " + pair[1]; }).join(" ") : "";
    const message = ((payload && payload.error) || ("Request failed (" + response.status + ")")) + fields;
    throw new Error(message);
  }
  return payload;
}

function showError(container, message) {
  clear(container);
  container.appendChild(el("p", "notice error", message));
}

/* Renders the reason chain. This is the heart of the product: a risk score
   with no visible evidence is not something a government body can act on. */
function renderReasons(container, reasons) {
  if (!reasons || !reasons.length) {
    container.appendChild(el("p", "muted", "No risk signals fired."));
    return;
  }
  const list = el("div", "reasons");
  reasons.forEach(function (reason) {
    const isModel = reason.layer === "MODEL";
    const row = el("div", "reason" + (isModel ? " model" : ""));
    row.appendChild(el("b", null, reason.points > 0 ? "+" + reason.points : "·"));
    const body = el("div", "reason-body");
    body.appendChild(el("p", null, reason.description));
    body.appendChild(el("code", null, reason.rule));
    row.appendChild(body);
    list.appendChild(row);
  });
  container.appendChild(list);
}

/* ------------------------------------------------- animated score display */

/* Counts the score up and sweeps a gauge arc to match.

   The animation is not decoration. A score that simply appears invites the
   question "where did that come from?"; a score that climbs while the reason
   rows arrive underneath makes the point that the number is assembled from
   evidence rather than produced by an oracle. */
function renderScoreGauge(container, score, decision) {
  const wrap = el("div", "gauge-wrap");
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 120 76");
  svg.setAttribute("class", "gauge");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", "Risk score " + score + " of 100, decision " + decision);

  const RADIUS = 46;
  const CX = 60;
  const CY = 62;

  function arcPath(fraction) {
    const angle = Math.PI * (1 - Math.max(0, Math.min(1, fraction)));
    const x = CX + RADIUS * Math.cos(angle);
    const y = CY - RADIUS * Math.sin(angle);
    // large-arc-flag is always 0: this gauge is a semicircle, so the sweep
    // from the left end to any point on it is at most 180 degrees. Setting the
    // flag to 1 past the halfway mark asks SVG for the OTHER arc between the
    // same two points - the long way round the bottom - which drew a stray
    // stub under the dial for every score above 50.
    return "M " + (CX - RADIUS) + " " + CY + " A " + RADIUS + " " + RADIUS +
           " 0 0 1 " + x + " " + y;
  }

  const track = document.createElementNS(NS, "path");
  track.setAttribute("d", arcPath(1));
  track.setAttribute("class", "gauge-track");
  svg.appendChild(track);

  // Band separators at the two decision thresholds, so the reader can see
  // which side of ALLOW / STEP-UP / BLOCK the needle landed on.
  [0.30, 0.70].forEach(function (mark) {
    const angle = Math.PI * (1 - mark);
    const tick = document.createElementNS(NS, "line");
    tick.setAttribute("x1", CX + (RADIUS - 9) * Math.cos(angle));
    tick.setAttribute("y1", CY - (RADIUS - 9) * Math.sin(angle));
    tick.setAttribute("x2", CX + (RADIUS + 5) * Math.cos(angle));
    tick.setAttribute("y2", CY - (RADIUS + 5) * Math.sin(angle));
    tick.setAttribute("class", "gauge-tick");
    svg.appendChild(tick);
  });

  const value = document.createElementNS(NS, "path");
  value.setAttribute("class", "gauge-value " + decision);
  value.setAttribute("d", arcPath(0));
  svg.appendChild(value);

  wrap.appendChild(svg);
  const readout = el("div", "gauge-readout");
  const number = el("strong", "gauge-number", "0");
  readout.appendChild(number);
  readout.appendChild(el("span", "gauge-max", "/ 100"));
  wrap.appendChild(readout);
  container.appendChild(wrap);

  const reduceMotion = window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (reduceMotion) {
    number.textContent = String(score);
    value.setAttribute("d", arcPath(score / 100));
    return;
  }

  const DURATION = 700;
  const start = performance.now();
  function step(now) {
    const t = Math.min(1, (now - start) / DURATION);
    const eased = 1 - Math.pow(1 - t, 3);
    number.textContent = String(Math.round(score * eased));
    value.setAttribute("d", arcPath((score * eased) / 100));
    if (t < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

/* --------------------------------------------------- identity graph (SVG) */

/* A small force-directed layout.

   Physics: every pair of nodes repels (inverse square), every edge acts as a
   spring, and a weak centring force stops disconnected pieces drifting away.
   The simulation is run to completion before anything is drawn - these graphs
   are a few dozen nodes, so solving upfront is instant and avoids a permanent
   animation loop burning CPU behind the dashboard. */
function renderIdentityGraph(container, payload, focusIdentity) {
  clear(container);

  const nodes = (payload && payload.nodes) || [];
  const edges = (payload && payload.edges) || [];
  if (!nodes.length) {
    container.appendChild(el("p", "muted small", "No linked records."));
    return;
  }

  const WIDTH = 520;
  // Taller frame for busier clusters, so a large ring is not squeezed flat.
  const HEIGHT = nodes.length > 18 ? 400 : 320;
  const index = {};

  // Deterministic starting positions: same graph draws the same way twice,
  // which matters when a screenshot has to match what the judge sees live.
  nodes.forEach(function (node, i) {
    const angle = (i / nodes.length) * Math.PI * 2;
    index[node.id] = {
      id: node.id,
      label: node.label,
      group: node.group,
      blocked: node.blocked,
      focus: node.focus,
      x: WIDTH / 2 + Math.cos(angle) * 110,
      y: HEIGHT / 2 + Math.sin(angle) * 90,
      vx: 0,
      vy: 0
    };
  });

  const links = edges
    .map(function (edge) { return { a: index[edge.from], b: index[edge.to] }; })
    .filter(function (link) { return link.a && link.b; });

  const points = Object.keys(index).map(function (key) { return index[key]; });

  const ITERATIONS = 320;
  const REPULSION = 5200;
  const SPRING = 0.012;
  const REST_LENGTH = 68;

  for (let step = 0; step < ITERATIONS; step++) {
    const cooling = 1 - step / ITERATIONS;

    for (let i = 0; i < points.length; i++) {
      for (let j = i + 1; j < points.length; j++) {
        const a = points[i];
        const b = points[j];
        let dx = b.x - a.x;
        let dy = b.y - a.y;
        let distSq = dx * dx + dy * dy;
        if (distSq < 0.01) {           // identical positions would divide by zero
          dx = (i % 2 ? 1 : -1) * 0.7;
          dy = 0.7;
          distSq = 1;
        }
        const dist = Math.sqrt(distSq);
        const force = REPULSION / distSq;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        a.vx -= fx; a.vy -= fy;
        b.vx += fx; b.vy += fy;
      }
    }

    links.forEach(function (link) {
      const dx = link.b.x - link.a.x;
      const dy = link.b.y - link.a.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const force = (dist - REST_LENGTH) * SPRING;
      const fx = (dx / dist) * force * dist;
      const fy = (dy / dist) * force * dist;
      link.a.vx += fx; link.a.vy += fy;
      link.b.vx -= fx; link.b.vy -= fy;
    });

    points.forEach(function (point) {
      point.vx += (WIDTH / 2 - point.x) * 0.006;
      point.vy += (HEIGHT / 2 - point.y) * 0.006;
      point.x += Math.max(-14, Math.min(14, point.vx * 0.06 * cooling));
      point.y += Math.max(-14, Math.min(14, point.vy * 0.06 * cooling));
      point.vx *= 0.82;
      point.vy *= 0.82;
      point.x = Math.max(26, Math.min(WIDTH - 26, point.x));
      point.y = Math.max(22, Math.min(HEIGHT - 22, point.y));
    });
  }

  /* Fit the settled layout to the canvas.

     In a fraud cluster every identity connects to every shared attribute, so
     the springs pull all the attribute nodes into a knot at the centre and
     leave two thirds of the frame empty - the labels then overlap and the
     picture stops being readable. Rescaling the bounding box to fill the
     viewport separates them without changing the relationships the layout
     found, and one pass of label nudging clears the remaining collisions. */
  (function fitToCanvas() {
    const PAD = 34;
    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    points.forEach(function (p) {
      minX = Math.min(minX, p.x); maxX = Math.max(maxX, p.x);
      minY = Math.min(minY, p.y); maxY = Math.max(maxY, p.y);
    });
    const spanX = Math.max(maxX - minX, 1);
    const spanY = Math.max(maxY - minY, 1);
    const scale = Math.min((WIDTH - PAD * 2) / spanX, (HEIGHT - PAD * 2) / spanY, 2.6);
    const offsetX = (WIDTH - spanX * scale) / 2;
    const offsetY = (HEIGHT - spanY * scale) / 2;
    points.forEach(function (p) {
      p.x = offsetX + (p.x - minX) * scale;
      p.y = offsetY + (p.y - minY) * scale;
    });
  }());

  /* Push apart any two labels still close enough to overwrite each other. */
  (function separateLabels() {
    const MIN_Y = 32;
    const MIN_X = 100;
    for (let pass = 0; pass < 3; pass++) {
      for (let i = 0; i < points.length; i++) {
        for (let j = i + 1; j < points.length; j++) {
          const a = points[i], b = points[j];
          if (Math.abs(a.x - b.x) < MIN_X && Math.abs(a.y - b.y) < MIN_Y) {
            const shift = (MIN_Y - Math.abs(a.y - b.y)) / 2 + 1;
            if (a.y <= b.y) { a.y -= shift; b.y += shift; }
            else { a.y += shift; b.y -= shift; }
            a.y = Math.max(22, Math.min(HEIGHT - 26, a.y));
            b.y = Math.max(22, Math.min(HEIGHT - 26, b.y));
          }
        }
      }
    }
  }());

  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 " + WIDTH + " " + HEIGHT);
  svg.setAttribute("class", "graph");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label",
    "Identity link graph: " + nodes.filter(function (n) { return n.group === "identity"; }).length +
    " identities and the attributes connecting them");

  links.forEach(function (link) {
    const line = document.createElementNS(NS, "line");
    line.setAttribute("x1", link.a.x);
    line.setAttribute("y1", link.a.y);
    line.setAttribute("x2", link.b.x);
    line.setAttribute("y2", link.b.y);
    // Weak links (device, address, IP) are dashed: things people legitimately
    // share should not look like the same evidence as a shared passport.
    const weak = link.a.group === "device_id" || link.b.group === "device_id" ||
                 link.a.group === "ip_address" || link.b.group === "ip_address" ||
                 link.a.group === "address" || link.b.group === "address";
    line.setAttribute("class", "graph-edge" + (weak ? " weak" : " strong"));
    svg.appendChild(line);
  });

  points.forEach(function (point) {
    const group = document.createElementNS(NS, "g");
    const isIdentity = point.group === "identity";

    if (isIdentity) {
      const circle = document.createElementNS(NS, "circle");
      circle.setAttribute("cx", point.x);
      circle.setAttribute("cy", point.y);
      circle.setAttribute("r", point.focus ? 11 : 8);
      circle.setAttribute("class", "graph-node identity" +
        (point.blocked ? " blocked" : "") + (point.focus ? " focus" : ""));
      group.appendChild(circle);
    } else {
      const size = 7;
      const rect = document.createElementNS(NS, "rect");
      rect.setAttribute("x", point.x - size);
      rect.setAttribute("y", point.y - size);
      rect.setAttribute("width", size * 2);
      rect.setAttribute("height", size * 2);
      rect.setAttribute("transform", "rotate(45 " + point.x + " " + point.y + ")");
      rect.setAttribute("class", "graph-node attr " + point.group);
      group.appendChild(rect);
    }

    const title = document.createElementNS(NS, "title");
    title.textContent = (isIdentity ? "Identity " : humanise(point.group) + ": ") +
      point.label + (point.blocked ? " (previously blocked)" : "");
    group.appendChild(title);

    // Labels are dropped as the graph grows. Past roughly a dozen nodes the
    // attribute captions overlap each other and the picture becomes less
    // readable than no captions at all; the values stay available on hover
    // through the <title> above, and identity labels survive longest because
    // they are what an analyst actually needs to read off the chart.
    const identityTotal = points.filter(function (p) {
      return p.group === "identity";
    }).length;
    const showLabel = isIdentity ? identityTotal <= 12 : points.length <= 14;
    if (showLabel) {
      const label = document.createElementNS(NS, "text");
      label.setAttribute("x", point.x);
      label.setAttribute("y", point.y + (isIdentity ? 23 : 20));
      label.setAttribute("class", "graph-label" + (point.focus ? " focus" : ""));
      const caption = isIdentity ? point.label :
        ({device_id: "Device", document_hash: "Document", phone: "Phone", address: "Address"}[point.group] || humanise(point.group));
      label.textContent = caption.length > 18 ? caption.slice(0, 17) + "…" : caption;
      group.appendChild(label);
    }

    svg.appendChild(group);
  });

  container.appendChild(svg);

  const legend = el("div", "graph-legend");
  [["identity", "identity"], ["blocked", "previously blocked"],
   ["focus", "this attempt"], ["attr", "shared attribute"]]
    .forEach(function (pair) {
      const item = el("span", "legend-item");
      item.appendChild(el("i", "legend-dot " + pair[0]));
      item.appendChild(el("span", null, pair[1]));
      legend.appendChild(item);
    });
  legend.appendChild(el("span", "legend-item muted small",
    "dashed = device/address (weak alone); solid = phone/exact document"));
  container.appendChild(legend);

  const identityCount = points.filter(function (p) { return p.group === "identity"; }).length;
  const attributeCount = points.length - identityCount;
  container.appendChild(el("p", "muted small",
    identityCount + " identities bound by " + attributeCount +
    " shared attribute" + (attributeCount === 1 ? "" : "s") +
    (points.length > 14 ? " — hover any node to read its value." : "")));
}

/* ------------------------------------------------------ confusion matrix */

function renderConfusionMatrix(container, metrics) {
  const labels = metrics.labels || [];
  const matrix = metrics.confusion_matrix || [];
  if (!labels.length || !matrix.length) return;

  let max = 1;
  matrix.forEach(function (row) {
    row.forEach(function (cell) { if (cell > max) max = cell; });
  });

  const table = el("table", "matrix");
  const head = el("tr");
  head.appendChild(el("th", null, "actual \\ predicted"));
  labels.forEach(function (label) {
    head.appendChild(el("th", null, humanise(label)));
  });
  table.appendChild(head);

  matrix.forEach(function (row, i) {
    const tr = el("tr");
    tr.appendChild(el("th", "row-label", humanise(labels[i])));
    row.forEach(function (cell, j) {
      const td = el("td", "matrix-cell" + (i === j ? " diagonal" : (cell > 0 ? " error" : "")), cell);
      // Opacity encodes magnitude. Set through CSSOM, not an inline style
      // attribute, so it is unaffected by the style-src policy.
      td.style.setProperty("--weight", (cell / max).toFixed(3));
      td.title = cell + " " + humanise(labels[i]) + " predicted as " + humanise(labels[j]);
      tr.appendChild(td);
    });
    table.appendChild(tr);
  });

  container.appendChild(table);
  container.appendChild(el("p", "muted small",
    "Diagonal is correct. Off-diagonal cells are the mistakes, on held-out data only."));
}

function renderScoreHistogram(container, buckets) {
  if (!buckets || !buckets.length) return;
  const max = buckets.reduce(function (acc, b) { return Math.max(acc, b.count); }, 1);
  const chart = el("div", "histogram");
  buckets.forEach(function (bucket) {
    const column = el("div", "hist-col");
    const bar = el("div", "hist-bar " + bucket.band);
    bar.style.setProperty("--height", ((bucket.count / max) * 100).toFixed(1) + "%");
    bar.title = bucket.count + " attempts scoring " + bucket.label;
    column.appendChild(bar);
    column.appendChild(el("span", "hist-label", bucket.label));
    chart.appendChild(column);
  });
  container.appendChild(chart);
}

/* =========================================================================
   Verification flow
   ========================================================================= */

const VERIFY_STAGES = ["Identity", "Document", "Liveness", "Decision"];

function initVerify() {
  const form = document.getElementById("verify-form");
  const result = document.getElementById("result");
  const stepUp = document.getElementById("stepup");
  const activatePrompt = document.getElementById("activate-prompt");
  const stages = document.getElementById("stages");
  const preview = document.getElementById("doc-preview");
  const fileInput = form.querySelector('input[type="file"]');
  let currentRef = null;

  function setStage(activeIndex) {
    clear(stages);
    VERIFY_STAGES.forEach(function (name, i) {
      const stage = el("div", "stage" +
        (i < activeIndex ? " done" : "") + (i === activeIndex ? " active" : ""));
      stage.appendChild(el("span", "stage-dot", i < activeIndex ? "✓" : String(i + 1)));
      stage.appendChild(el("span", "stage-name", name));
      stages.appendChild(stage);
    });
  }
  setStage(0);

  /* Document preview is rendered from the local file with FileReader. The
     file is not uploaded until the form is submitted, so the applicant can
     check they picked the right document without sending it anywhere. */
  fileInput.addEventListener("change", function () {
    clear(preview);
    preview.className = "doc-preview hidden";
    const file = fileInput.files && fileInput.files[0];
    if (!file) { setStage(0); return; }

    const sizeMB = file.size / (1024 * 1024);
    const info = el("div", "doc-meta");
    info.appendChild(el("strong", null, file.name));
    info.appendChild(el("span", "muted small", sizeMB.toFixed(2) + " MB"));

    if (sizeMB > 5) {
      info.appendChild(el("span", "notice error",
        "Over the 5 MB limit — the server will reject this."));
    }

    if (/^image\//.test(file.type)) {
      const reader = new FileReader();
      reader.onload = function (event) {
        const img = el("img", "doc-thumb");
        img.src = event.target.result;      // a local data: URL, never remote
        img.alt = "Preview of the selected document";
        preview.insertBefore(img, preview.firstChild);
      };
      reader.readAsDataURL(file);
    }
    preview.appendChild(info);
    preview.className = "doc-preview";
    setStage(1);
  });

  form.addEventListener("submit", async function (event) {
    event.preventDefault();
    setStage(2);
    stepUp.className = "panel hidden";
    activatePrompt.className = "panel hidden";
    result.className = "panel";
    clear(result);
    result.appendChild(el("p", "muted", "Scoring against velocity, reputation, "
      + "attribute consistency, cross-record links and document forensics…"));

    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;

    try {
      const data = await getJSON("/api/verify", {
        method: "POST",
        body: new FormData(form)
      });
      currentRef = data.attempt_ref;
      setStage(3);
      clear(result);

      const header = el("div", "result-head");
      const meta = el("div");
      meta.appendChild(el("h3", null, "Decision"));
      meta.appendChild(el("p", "muted small", "Attempt " + data.attempt_ref));
      meta.appendChild(decisionPill(data.decision));
      header.appendChild(meta);
      renderScoreGauge(header, data.risk_score, data.decision);
      result.appendChild(header);

      const bands = el("p", "muted small",
        "Allow 0–29 · Step-up 30–69 · Block 70–100");
      result.appendChild(bands);

      result.appendChild(el("h3", null, "Why"));
      renderReasons(result, data.reasons);

      if (data.decision === "STEP_UP") {
        stepUp.className = "panel";
        document.getElementById("otp-submit").disabled = false;
        clear(document.getElementById("otp-result"));
        const otp = document.getElementById("otp");
        otp.value = "";
        otp.focus();
      } else if (data.activation_available) {
        activatePrompt.className = "panel";
      }
    } catch (err) {
      setStage(1);
      showError(result, err.message);
    } finally {
      button.disabled = false;
    }
  });

  document.getElementById("otp-submit").addEventListener("click", async function () {
    const button = this;
    button.disabled = true;
    const output = document.getElementById("otp-result");
    clear(output);
    try {
      const data = await getJSON("/api/step-up", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          attempt_ref: currentRef,
          code: document.getElementById("otp").value
        })
      });
      output.appendChild(el("p", data.passed ? "notice ok" : "notice error",
        data.passed
          ? "Code accepted — the attempt is allowed and the challenge is recorded."
          : "Code rejected — the attempt is blocked."));
      const pill = result.querySelector(".pill");
      if (pill) pill.replaceWith(decisionPill(data.decision));
      result.appendChild(el("p", "notice", "Step-up " + (data.passed ? "passed" : "failed")
        + ". The risk score and evidence above describe the original assessment."));
      if (data.activation_available) {
        activatePrompt.className = "panel";
      }
    } catch (err) {
      output.appendChild(el("p", "notice error", err.message));
      button.disabled = false;
    }
  });
}

/* =========================================================================
   Customer login step-up
   ========================================================================= */

function initCustomerLogin() {
  const panel = document.getElementById("customer-stepup");
  if (!panel) return;
  const button = document.getElementById("otp-submit");

  button.addEventListener("click", async function () {
    button.disabled = true;
    const output = document.getElementById("otp-result");
    clear(output);
    try {
      const data = await getJSON("/api/step-up", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          attempt_ref: panel.dataset.attemptRef,
          code: document.getElementById("otp").value
        })
      });
      if (data.passed) {
        output.appendChild(el("p", "notice ok", "Code accepted — signing you in…"));
        window.location.href = "/verify";
      } else {
        output.appendChild(el("p", "notice error",
          "Code rejected — this sign-in attempt is blocked."));
      }
    } catch (err) {
      output.appendChild(el("p", "notice error", err.message));
      button.disabled = false;
    }
  });
}

/* =========================================================================
   Simulator
   ========================================================================= */

function initSimulator() {
  const output = document.getElementById("sim-output");

  document.querySelectorAll(".sim").forEach(function (button) {
    button.addEventListener("click", async function () {
      document.querySelectorAll(".sim").forEach(function (b) { b.disabled = true; });
      output.className = "panel";
      clear(output);
      output.appendChild(el("p", "muted", "Generating traffic and scoring it…"));

      try {
        const data = await getJSON("/api/simulate/" + button.dataset.scenario,
                                   { method: "POST" });
        clear(output);

        const counts = { ALLOW: 0, STEP_UP: 0, BLOCK: 0 };
        data.attempts.forEach(function (a) { counts[a.decision] = (counts[a.decision] || 0) + 1; });

        const head = el("div", "row-between");
        head.appendChild(el("h3", null,
          data.generated + " attempt" + (data.generated === 1 ? "" : "s") + " scored"));
        const summary = el("div", "count-pills");
        ["ALLOW", "STEP_UP", "BLOCK"].forEach(function (key) {
          if (counts[key]) {
            const pill = decisionPill(key);
            pill.textContent = counts[key] + " " + key.replace("_", "-").toLowerCase();
            summary.appendChild(pill);
          }
        });
        head.appendChild(summary);
        output.appendChild(head);

        data.attempts.forEach(function (attempt) {
          const block = el("div", "sim-attempt");
          const row = el("div", "row-between");
          const left = el("div");
          left.appendChild(el("strong", null, attempt.attempt_ref));
          left.appendChild(el("span", "muted small",
            "  " + (attempt.identity || "") + "  ·  score " + attempt.risk_score));
          row.appendChild(left);
          row.appendChild(decisionPill(attempt.decision));
          block.appendChild(row);
          renderReasons(block, attempt.reasons);
          output.appendChild(block);
        });

        output.appendChild(el("p", "muted small",
          "Open the analyst console to see these in context, with the identity "
          + "graph and document forensics."));
      } catch (err) {
        showError(output, err.message);
      } finally {
        document.querySelectorAll(".sim").forEach(function (b) { b.disabled = false; });
      }
    });
  });
}

/* =========================================================================
   Analyst console
   ========================================================================= */

function initDashboard() {
  const statsBox = document.getElementById("stats");
  const tbody = document.querySelector("#attempts tbody");
  const detail = document.getElementById("detail");
  const metricsBox = document.getElementById("metrics");
  let selectedRow = null;
  let listRequest = 0;
  let detailRequest = 0;

  async function loadStats() {
    try {
      const filters = new URLSearchParams({
        decision: document.getElementById("filter-decision").value,
        scenario: document.getElementById("filter-scenario").value,
      });
      const stats = await getJSON("/api/stats?" + filters.toString());
      clear(statsBox);
      [["Total attempts", stats.total, ""],
       ["Allowed", stats.allowed, "ALLOW"],
       ["Awaiting step-up", stats.stepped_up, "STEP_UP"],
       ["Blocked", stats.blocked, "BLOCK"]]
        .forEach(function (item) {
          const card = el("div", "stat " + item[2]);
          card.appendChild(el("span", null, item[0]));
          card.appendChild(el("strong", null, item[1]));
          if (stats.total && item[2]) {
            card.appendChild(el("span", "stat-pct",
              ((item[1] / stats.total) * 100).toFixed(1) + "%"));
          }
          statsBox.appendChild(card);
        });

      const histBox = document.getElementById("histogram");
      clear(histBox);
      if (stats.score_histogram && stats.score_histogram.length) {
        const isFiltered = filters.get("decision") || filters.get("scenario");
        histBox.appendChild(el("h3", null, "Original risk score distribution"));
        histBox.appendChild(el("p", "muted small",
          (isFiltered ? "Matching the current filter." : "All attempts.")
          + " Scores stay unchanged when a step-up is resolved; outcome totals above show the current state."));
        renderScoreHistogram(histBox, stats.score_histogram);
      }
    } catch (err) {
      showError(statsBox, err.message);
    }
  }

  async function loadAttempts() {
    const requestId = ++listRequest;
    ++detailRequest;
    try {
      const params = new URLSearchParams({
        decision: document.getElementById("filter-decision").value,
        scenario: document.getElementById("filter-scenario").value,
        limit: "150"
      });
      const rows = await getJSON("/api/attempts?" + params.toString());
      if (requestId !== listRequest) return;
      clear(tbody);
      selectedRow = null;
      clear(detail);
      detail.appendChild(el("p", "muted", "Select an attempt to inspect its assessment and current outcome."));
      document.getElementById("attempt-count").textContent = "Showing " + rows.length
        + " most recent matching attempts (up to 150). Summary totals cover all attempts.";

      if (!rows.length) {
        const tr = el("tr");
        const td = el("td", "muted", "No attempts match this filter.");
        td.colSpan = 5;
        tr.appendChild(td);
        tbody.appendChild(tr);
        return;
      }

      rows.forEach(function (row) {
        const tr = el("tr");
        tr.appendChild(el("td", "mono", row.attempt_ref));
        tr.appendChild(el("td", null, row.identity || "—"));

        const scoreCell = el("td", "score");
        const bar = el("span", "score-bar " + (row.initial_decision || row.decision));
        bar.style.setProperty("--fill", row.risk_score + "%");
        scoreCell.appendChild(el("span", "score-num", row.risk_score));
        scoreCell.appendChild(bar);
        tr.appendChild(scoreCell);

        const decisionCell = el("td");
        decisionCell.appendChild(decisionPill(row.decision));
        if (row.step_up_result) decisionCell.appendChild(el("div", "muted small", "Step-up " + row.step_up_result.toLowerCase()));
        tr.appendChild(decisionCell);
        tr.appendChild(el("td", "muted small", humanise(row.scenario)));

        tr.tabIndex = 0;
        function open() {
          if (selectedRow) selectedRow.classList.remove("selected");
          tr.classList.add("selected");
          selectedRow = tr;
          loadDetail(row.attempt_ref);
        }
        tr.addEventListener("click", open);
        tr.addEventListener("keydown", function (event) {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            open();
          }
        });
        tbody.appendChild(tr);
      });
    } catch (err) {
      if (requestId !== listRequest) return;
      clear(tbody);
      const tr = el("tr");
      const td = el("td", "notice error", err.message);
      td.colSpan = 5;
      tr.appendChild(td);
      tbody.appendChild(tr);
    }
  }

  async function loadDetail(reference) {
    const requestId = ++detailRequest;
    clear(detail);
    detail.appendChild(el("p", "muted", "Loading…"));
    try {
      const data = await getJSON("/api/attempt/" + encodeURIComponent(reference));
      if (requestId !== detailRequest) return;
      const attempt = data.attempt;
      clear(detail);

      const head = el("div", "row-between");
      const left = el("div");
      left.appendChild(el("h3", null, attempt.attempt_ref));
      left.appendChild(el("p", "muted small",
        attempt.timestamp + "  ·  " + (attempt.identity || "")));
      head.appendChild(left);
      const right = el("div", "detail-score");
      right.appendChild(el("span", "muted small", "Original risk score"));
      right.appendChild(el("strong", "big-score " + (attempt.initial_decision || attempt.decision), attempt.risk_score));
      right.appendChild(decisionPill(attempt.decision));
      head.appendChild(right);
      detail.appendChild(head);
      if (attempt.step_up_result) {
        detail.appendChild(el("p", "notice", "Originally " + humanise(attempt.initial_decision)
          + "; step-up " + attempt.step_up_result.toLowerCase() + ". Current outcome: "
          + humanise(attempt.decision) + ". The original score and reasons are preserved."));
      }

      const kv = el("div", "kv");
      [["IP address", attempt.ip_address],
       ["Device", attempt.device_id],
       ["Phone", attempt.phone || "—"],
       ["Email", attempt.email || "—"],
       ["Document", attempt.document_status],
       ["Liveness", attempt.liveness_status],
       ["Rule points", attempt.rule_points],
       ["Model probability", attempt.ml_probability == null
          ? "—" : (attempt.ml_probability * 100).toFixed(1) + "%"]]
        .forEach(function (pair) {
          kv.appendChild(el("span", null, pair[0]));
          kv.appendChild(el("div", null, pair[1]));
        });
      detail.appendChild(kv);
      detail.appendChild(el("p", "muted small",
        "Phone and email are masked. An analyst needs to know two records share "
        + "a number, not what the number is."));

      detail.appendChild(el("h3", null, "Why this score"));
      renderReasons(detail, data.reasons);

      if (data.document) {
        detail.appendChild(el("h3", null, "Document forensics"));
        const summary = el("p", "small");
        summary.textContent = "Compression anomaly score "
          + (data.document.ela_score == null ? "n/a" : data.document.ela_score.toFixed(1))
          + "  ·  presented " + data.document.seen_count + " time(s)";
        detail.appendChild(summary);
        (data.document.metadata_flags || []).forEach(function (flag) {
          detail.appendChild(el("p", "muted small", "• " + flag));
        });
        if (data.document.has_ela_image) {
          const figure = el("figure", "ela-figure");
          const img = el("img", "ela");
          img.src = "/api/document/" + encodeURIComponent(data.document.doc_hash) + "/ela";
          img.alt = "Error Level Analysis heatmap of the submitted document";
          img.loading = "lazy";
          figure.appendChild(img);
          figure.appendChild(el("figcaption", "muted small",
            "Bright regions changed more under re-compression than their "
            + "surroundings — the signature of a pasted or edited area. "
            + "An indicator, not proof."));
          detail.appendChild(figure);
        }
      }

      if (attempt.identity) {
        const graphBox = el("div", "graph-box");
        detail.appendChild(el("h3", null, "Identity links"));
        detail.appendChild(graphBox);
        try {
          const payload = await getJSON("/api/graph/" + encodeURIComponent(attempt.identity));
          if (requestId !== detailRequest) return;
          detail.appendChild(el("p", "muted small", payload.explanation));
          const identityCount = (payload.nodes || [])
            .filter(function (n) { return n.group === "identity"; }).length;
          if (identityCount > 1) {
            renderIdentityGraph(graphBox, payload, attempt.identity);
          } else {
            clear(graphBox);
            graphBox.appendChild(el("p", "muted small",
              "No links through documents, phones, devices or addresses were found. IP-only sharing is excluded."));
          }
          (payload.links || []).forEach(function (link) {
            detail.appendChild(el("p", "small", humanise(link.attribute) + ": shared with "
              + link.identity_count + " other identit" + (link.identity_count === 1 ? "y" : "ies")
              + " · " + link.strength + " evidence under the current policy."));
          });
          if (payload.truncated) detail.appendChild(el("p", "notice", "This graph is limited to 180 nodes. The cluster contains " + payload.identity_count + " identities."));
        } catch (err) {
          showError(graphBox, err.message);
        }
      }
    } catch (err) {
      if (requestId !== detailRequest) return;
      showError(detail, err.message);
    }
  }

  document.getElementById("toggle-metrics").addEventListener("click", async function () {
    if (!metricsBox.classList.contains("hidden")) {
      metricsBox.className = "panel hidden";
      return;
    }
    metricsBox.className = "panel";
    clear(metricsBox);
    metricsBox.appendChild(el("p", "muted", "Loading…"));

    try {
      const results = await Promise.all([getJSON("/api/metrics"), getJSON("/api/security")]);
      const metrics = results[0].model || {};
      const calibration = results[0].ela_calibration;
      const controls = results[1];
      clear(metricsBox);

      if (metrics.accuracy != null) {
        // Two genuinely different kinds of measurement, kept visually and
        // structurally separate so a correctly-classified attack is never
        // read as "therefore blocked": decision outcomes come from
        // FraudEngine's actual ALLOW/STEP_UP/BLOCK action, while the
        // classifier table below measures whether the model predicted the
        // right attack TYPE. Both are computed over the same held-out
        // synthetic evaluation set (see the methodology note).
        metricsBox.appendChild(el("h3", null, "End-to-End Fraud Decision Outcomes"));
        metricsBox.appendChild(el("p", "muted small",
          "What FraudEngine actually did with each held-out attempt - challenged or blocked it, or let it through."));
        if (metrics.engine) {
          const rates = el("div", "metric-row");
          [["Attack attempts challenged or blocked", metrics.engine.attack_detection_rate],
           ["Legitimate blocked", metrics.engine.legitimate_block_rate],
           ["Legitimate challenged", metrics.engine.legitimate_step_up_rate]].forEach(function (pair) {
            const item = el("div", "metric");
            item.appendChild(el("span", null, pair[0]));
            item.appendChild(el("strong", null, pair[1] == null ? "Unavailable" : (pair[1] * 100).toFixed(1) + "%"));
            rates.appendChild(item);
          });
          metricsBox.appendChild(rates);
        }

        metricsBox.appendChild(el("p", "notice small",
          "Classifier metrics measure attack-type prediction. Decision metrics measure "
          + "whether the FraudEngine challenged or blocked the attempt. A correctly "
          + "classified attack is not automatically BLOCKED - see the decision outcomes above."));

        metricsBox.appendChild(el("h3", null, "Attack-Type Classifier — Held-Out Evaluation"));
        metricsBox.appendChild(el("p", "muted small",
          "Held-out synthetic evaluation set: a separate replay (different seed, documents "
          + "and identities) the model never trained on."));
        const headline = el("div", "metric-row");
        [["Held-out accuracy", (metrics.accuracy * 100).toFixed(1) + "%"],
         ["Fraud vs legitimate AUC", metrics.fraud_vs_legitimate_auc == null ? "Unavailable" : metrics.fraud_vs_legitimate_auc.toFixed(3)],
         ["Train / test", metrics.n_train + " / " + metrics.n_test]]
          .forEach(function (pair) {
            const item = el("div", "metric");
            item.appendChild(el("span", null, pair[0]));
            item.appendChild(el("strong", null, pair[1]));
            headline.appendChild(item);
          });
        metricsBox.appendChild(headline);
        metricsBox.appendChild(el("p", "muted small", metrics.methodology || ""));

        const table = el("table", "matrix");
        const header = el("tr");
        ["Class", "Precision", "Recall", "F1", "n"].forEach(function (label) {
          header.appendChild(el("th", null, label));
        });
        table.appendChild(header);
        Object.keys(metrics.per_class || {}).forEach(function (key) {
          const row = metrics.per_class[key];
          const tr = el("tr");
          tr.appendChild(el("td", null, humanise(key)));
          [row.precision, row.recall, row.f1].forEach(function (value) {
            tr.appendChild(el("td", null, value == null ? "—" : value.toFixed(2)));
          });
          tr.appendChild(el("td", "muted", row.support == null ? "—" : row.support));
          table.appendChild(tr);
        });
        metricsBox.appendChild(table);

        metricsBox.appendChild(el("h3", null, "Confusion matrix"));
        renderConfusionMatrix(metricsBox, metrics);
      } else {
        metricsBox.appendChild(el("p", "muted small",
          "No model trained yet. Run python seed.py."));
      }

      if (calibration) {
        metricsBox.appendChild(el("h3", null, "Document forensics calibration"));
        metricsBox.appendChild(el("p", "small",
          "Threshold " + calibration.threshold + " · calibration fit (not held-out accuracy) "
          + (calibration.balanced_accuracy * 100).toFixed(1) + "% · fitted on "
          + calibration.n_clean + " genuine and " + calibration.n_tampered
          + " tampered documents"));
        metricsBox.appendChild(el("p", "muted small", calibration.note || ""));
      }

      metricsBox.appendChild(el("h3", null, "Security controls"));
      const list = el("div", "controls");
      controls.forEach(function (control) {
        const row = el("div", "control" + (control.active ? " on" : " off"));
        row.appendChild(el("span", "control-state", control.active ? "✓" : "!"));
        const body = el("div");
        body.appendChild(el("strong", null, control.control));
        body.appendChild(el("p", "muted small", control.implementation));
        if (control.detail) {
          body.appendChild(el("p", "notice small", control.detail));
        }
        body.appendChild(el("code", null, control.cyber_essential));
        row.appendChild(body);
        list.appendChild(row);
      });
      metricsBox.appendChild(list);
    } catch (err) {
      showError(metricsBox, err.message);
    }
  });

  ["filter-decision", "filter-scenario"].forEach(function (id) {
    // Both the attempts table AND the risk-score histogram are scoped to
    // these filters, so both have to refresh on every change - previously
    // only the table did, which is why the graph looked stuck on "All".
    document.getElementById(id).addEventListener("change", function () {
      loadStats();
      loadAttempts();
    });
  });

  const refresh = document.getElementById("refresh");
  if (refresh) {
    refresh.addEventListener("click", function () { loadStats(); loadAttempts(); });
  }

  loadStats();
  loadAttempts();
}

/* -------------------------------------------------------------- dispatch */

document.addEventListener("DOMContentLoaded", function () {
  const page = document.body.dataset.page;
  if (page === "verify") initVerify();
  else if (page === "simulator") initSimulator();
  else if (page === "dashboard") initDashboard();
  else if (page === "customer-login") initCustomerLogin();
});
