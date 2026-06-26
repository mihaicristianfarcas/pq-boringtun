"use strict";

// Largest handshake across variants — keep in sync with config.MAX_HANDSHAKE_SIZE.
const MAX_SIZE = 1332;

const state = {
  variants: {},     // key -> public dict
  active: null,     // active variant key
  receiverPort: 8765,
  logCursor: null,  // event count already shown; null = re-prime (skip history)
};

const $ = (id) => document.getElementById(id);

async function jsonFetch(url, opts) {
  const r = await fetch(url, opts);
  if (!r.ok) {
    let detail = r.statusText;
    try { detail = (await r.json()).detail || detail; } catch (_) {}
    throw new Error(detail);
  }
  return r.json();
}

// --- bootstrap --------------------------------------------------------------
async function init() {
  const data = await jsonFetch("/api/variants");
  for (const v of data.variants) state.variants[v.key] = v;
  state.receiverPort = data.receiver_port || state.receiverPort;

  $("mode").textContent =
    data.mode === "vps" ? `VPS · ${data.vps_host || "?"}` : "LOCAL (loopback)";

  buildTabs(data.variants);
  selectVariant(data.variants[0].key);

  // tail the active tunnel's real handshake log into the bottom strip
  setInterval(pollLogs, 1000);

  $("connect").addEventListener("click", onConnect);
  $("send").addEventListener("click", onSend);
  $("file").addEventListener("change", (e) => {
    const f = e.target.files[0];
    e.target.closest(".file").querySelector("span").textContent =
      f ? f.name : "Choose image…";
  });
}

function buildTabs(variants) {
  const nav = $("tabs");
  nav.innerHTML = "";
  for (const v of variants) {
    const b = document.createElement("button");
    b.className = "tab";
    b.textContent = v.label;
    b.dataset.key = v.key;
    b.addEventListener("click", () => selectVariant(v.key));
    nav.appendChild(b);
  }
}

// --- variant selection: render the *expected* picture, clear live results ----
function selectVariant(key) {
  state.active = key;
  const v = state.variants[key];

  for (const tab of document.querySelectorAll(".tab"))
    tab.setAttribute("aria-selected", String(tab.dataset.key === key));

  // X-ray shows expected sizes until "Connect" captures the live ones.
  renderSizes(v.expected_init, v.expected_resp);
  $("m-live").textContent = "—";
  $("m-thesis").textContent = `${v.thesis_us.toFixed(1)} µs`;
  $("m-match").textContent = "—";
  $("capture-note").textContent =
    "Sizes shown are the thesis values; press Connect to capture them live.";

  // Verdict is a thesis claim — safe to show immediately.
  $("crypto").textContent = v.crypto;
  setMark($("v-safe"), v.quantum_safe);
  setMark($("v-fs"), v.pq_forward_secrecy);
  $("verdict-note").textContent = v.note;

  $("transfer-result").innerHTML = "";

  // Reset the live log for the newly-selected tunnel and re-aim the receiver
  // link at this tunnel's IP (so the arrivals page loads *through* the tunnel).
  state.logCursor = null;             // re-prime: skip history, show only new
  const feed = $("log-feed");
  feed.textContent = "";
  addLogPlaceholder(feed, `watching ${v.label} — press Connect to see a handshake`);
  $("log-variant").textContent = `· ${v.label} (${v.peer_ip})`;
  $("receiver-link").href = `http://${v.peer_ip}:${state.receiverPort}/`;
  pollLogs();                         // prime the cursor now, not on the next tick
}

// --- live handshake log -----------------------------------------------------
async function pollLogs() {
  const key = state.active;
  if (!key) return;
  try {
    const after = state.logCursor == null ? 0 : state.logCursor;
    const r = await fetch(`/api/logs/${key}?after=${after}`, { cache: "no-store" });
    if (!r.ok) return;
    const data = await r.json();
    if (data.variant !== state.active) return;   // raced a variant switch
    if (state.logCursor == null) {
      state.logCursor = data.cursor;             // prime: adopt end, skip history
      return;
    }
    if (data.events.length) {
      appendLogEvents($("log-feed"), data.events);
      state.logCursor = data.cursor;
    }
  } catch (_) { /* fail-soft: retry next tick */ }
}

function addLogPlaceholder(feed, text) {
  const p = document.createElement("div");
  p.className = "placeholder";
  p.textContent = text;
  feed.appendChild(p);
}

function appendLogEvents(feed, events) {
  const ph = feed.querySelector(".placeholder");
  if (ph) ph.remove();
  for (const ev of events) {
    const line = document.createElement("div");
    line.className = "ev" + (ev.startsWith("⚠") ? " warn" : "");
    line.textContent = ev;       // textContent: never trust the log boundary
    feed.appendChild(line);
  }
  feed.scrollTop = feed.scrollHeight;
}

function renderSizes(init, resp) {
  $("bar-init").style.width = pct(init);
  $("bar-resp").style.width = pct(resp);
  $("size-init").textContent = fmtBytes(init);
  $("size-resp").textContent = fmtBytes(resp);
}

const pct = (n) => `${Math.max(1, Math.round((n / MAX_SIZE) * 100))}%`;
const fmtBytes = (n) => (n == null ? "—" : `${n.toLocaleString()} B`);

function setMark(el, yes) {
  el.textContent = yes ? "✓" : "✗";
  el.className = "mark " + (yes ? "safe" : "no");
}

// --- connect & capture ------------------------------------------------------
async function onConnect() {
  const key = state.active;
  const btn = $("connect");
  btn.disabled = true;
  btn.textContent = "Capturing…";
  $("capture-note").textContent = "Forcing a fresh handshake and capturing it…";
  try {
    const r = await jsonFetch(`/api/connect/${key}`, { method: "POST" });
    renderSizes(r.init_size, r.resp_size);
    $("m-live").textContent =
      r.handshake_ms != null ? `${r.handshake_ms.toFixed(1)} ms` : "n/a";
    $("m-thesis").textContent = `${r.thesis_us.toFixed(1)} µs`;
    setMatch(r.size_matches_expected);
    $("capture-note").textContent = r.from_fallback
      ? "Live capture missed a packet — showing pre-staged sizes (still real)."
      : `Captured live. Handshake fresh: ${r.handshake_confirmed ? "yes" : "—"}.`;
  } catch (e) {
    $("capture-note").textContent = `Capture failed: ${e.message}`;
  } finally {
    btn.disabled = false;
    btn.textContent = "Connect & capture";
  }
}

function setMatch(ok) {
  const el = $("m-match");
  el.textContent = ok ? "✓ yes" : "≠ differs";
  el.className = "mark " + (ok ? "safe" : "no");
}

// --- transfer ---------------------------------------------------------------
async function onSend() {
  const key = state.active;
  const file = $("file").files[0];
  const secret = $("secret").value.trim();
  const out = $("transfer-result");

  if (!file && !secret) {
    note(out, "Choose an image or type a secret first.");
    return;
  }

  const btn = $("send");
  btn.disabled = true;
  btn.textContent = "Sending…";
  note(out, `Sending through the ${state.variants[key].label} tunnel…`);

  try {
    const fd = new FormData();
    if (file) fd.append("file", file);
    else fd.append("text", secret);
    const r = await jsonFetch(`/api/transfer/${key}`, { method: "POST", body: fd });
    renderTransfer(r);
  } catch (e) {
    note(out, `Transfer failed: ${e.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = "Send";
  }
}

// All dynamic fields below come from the remote receiver, so build with the DOM
// and textContent (never innerHTML) to avoid any injection from that boundary.
function renderTransfer(r) {
  const out = $("transfer-result");
  out.textContent = "";
  if (!r.ok) {
    note(out, `Transfer failed: ${r.error || "unknown"}`);
    return;
  }

  const verdict = document.createElement("p");
  if (r.vps_confirmed_identical) {
    const span = document.createElement("span");
    span.className = "ok";
    span.textContent = "sent ✓  remote confirmed identical ✓";
    verdict.appendChild(span);
  } else {
    verdict.textContent = "sent, but checksum mismatch ✗";
  }
  out.appendChild(verdict);

  const rows = [
    ["bytes", Number(r.bytes).toLocaleString()],
    ["round-trip", `${r.rtt_ms} ms`],
    ["local  SHA-256", short(r.local_sha256)],
    ["remote SHA-256", short(r.remote_sha256)],
  ];
  const table = document.createElement("table");
  for (const [k, val] of rows) {
    const tr = document.createElement("tr");
    const td1 = document.createElement("td");
    td1.textContent = k;
    const td2 = document.createElement("td");
    td2.textContent = val;
    tr.append(td1, td2);
    table.appendChild(tr);
  }
  out.appendChild(table);

  // Only render the echo as an image when the MIME is a safe image/* type and
  // the payload is plain base64 — defends the data: URL against tampering.
  if (r.echo_b64 && isSafeImageType(r.content_type) && isBase64(r.echo_b64)) {
    const img = document.createElement("img");
    img.alt = "round-tripped from remote";
    img.src = `data:${r.content_type};base64,${r.echo_b64}`;
    out.appendChild(img);
  }
}

const SAFE_IMAGE_TYPES = new Set([
  "image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp",
]);
const isSafeImageType = (t) => SAFE_IMAGE_TYPES.has((t || "").toLowerCase());
const isBase64 = (s) => typeof s === "string" && /^[A-Za-z0-9+/=]+$/.test(s);

function note(el, text) {
  el.textContent = "";
  const p = document.createElement("p");
  p.className = "note";
  p.textContent = text;
  el.appendChild(p);
}

const short = (h) => (h ? `${h.slice(0, 12)}…${h.slice(-8)}` : "—");

init().catch((e) => {
  document.body.textContent = "";
  const m = document.createElement("main");
  const p = document.createElement("p");
  p.className = "note";
  p.textContent = `Failed to load demo: ${e.message}`;
  m.appendChild(p);
  document.body.appendChild(m);
});
