#!/usr/bin/env python3
"""Echo+checksum receiver for the PQ-WireGuard demo (VPS side), with a small
live "arrivals" web view.

Stdlib only — nothing to pip-install on the VPS. Listens inside the tunnel(s),
hashes whatever it receives, echoes the bytes straight back with an ``X-Sha256``
header (the Mac compares hashes to prove the payload crossed intact), AND keeps
the last few arrivals in memory so a second browser tab — opened via the tunnel
IP — can show the photo/message landing on the remote machine in real time.

Run on the VPS (one instance serves all three tunnels):

    python3 receiver.py            # binds 0.0.0.0:8765
    python3 receiver.py --port 8765 --bind 0.0.0.0

Open the arrivals view from the Mac at ``http://<tunnel-ip>:8765/`` (e.g.
http://10.13.2.2:8765/ for the PQ tunnel) — the page itself rides the tunnel.
Keep 8765 behind the host firewall so it is reachable only via the WG tunnels.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BYTES = 16 * 1024 * 1024  # 16 MiB cap — demo payloads are tiny
TEXT_PREVIEW_CAP = 2000       # chars of a text payload surfaced to the UI

# /media echoes back attacker-controllable bytes, so never reflect the uploaded
# Content-Type for active types (e.g. text/html -> stored XSS). Serve only this
# safe set as-is; anything else is forced to a download as octet-stream.
SAFE_MEDIA_TYPES = frozenset({
    "image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp", "text/plain",
})

# The local tunnel address a request arrived on tells us which variant it used.
# Same peer IPs in --local loopback mode, so this mapping works there too.
VARIANT_BY_IP = {
    "10.13.0.2": "vanilla",
    "10.13.1.2": "psk",
    "10.13.2.2": "pq",
}


def variant_for_addr(ip: str) -> str:
    """Map the local socket IP a payload landed on to its tunnel variant."""
    return VARIANT_BY_IP.get(ip, "?")


class ArrivalStore:
    """Thread-safe, bounded record of recently received payloads.

    Holds the raw bytes (for ``/media/<id>``) plus metadata. ``list_meta`` and
    the JSON render never expose the raw bytes; a short text preview is surfaced
    for text/* payloads so the demo "secret message" can be shown inline.
    """

    def __init__(self, maxlen: int = 20) -> None:
        self._items: deque = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._next_id = 0

    def add(self, *, variant: str, filename: str, sha256: str,
            content_type: str, data: bytes) -> int:
        text = None
        if content_type.startswith("text/"):
            text = data.decode("utf-8", "replace")[:TEXT_PREVIEW_CAP]
        with self._lock:
            arrival_id = self._next_id
            self._next_id += 1
            self._items.append({
                "id": arrival_id,
                "ts": time.time(),
                "variant": variant,
                "filename": filename,
                "sha256": sha256,
                "content_type": content_type,
                "size": len(data),
                "text": text,
                "data": data,
            })
            return arrival_id

    def list_meta(self) -> list[dict]:
        """Newest-first metadata; the raw ``data`` bytes are dropped."""
        with self._lock:
            return [
                {k: v for k, v in item.items() if k != "data"}
                for item in reversed(self._items)
            ]

    def get(self, arrival_id: int) -> dict | None:
        with self._lock:
            for item in self._items:
                if item["id"] == arrival_id:
                    return item
            return None


def render_arrivals_json(store: ArrivalStore) -> str:
    return json.dumps({"arrivals": store.list_meta()})


# Static shell — all data arrives via the /arrivals.json poll, so the HTML is
# constant (no server-side templating, trivially correct).
INDEX_HTML = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PQ-WireGuard — arrivals (VPS)</title>
<style>
  /* Mirrors the Mac UI: minimal black-on-white, one green accent, 820px column */
  :root {
    --ink: #111; --muted: #666; --line: #ddd; --accent: #1E8449;
    --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    --sans: -apple-system, system-ui, "Helvetica Neue", Arial, sans-serif;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: #fff; color: var(--ink);
         font-family: var(--sans); font-size: 17px; line-height: 1.5; }
  main { max-width: 820px; margin: 0 auto; padding: 32px 28px 64px; }
  .top { display: flex; align-items: baseline; justify-content: space-between;
         gap: 16px; border-bottom: 2px solid var(--ink); padding-bottom: 12px; }
  h1 { font-size: 1.45rem; font-weight: 600; margin: 0; }
  .muted { color: var(--muted); font-weight: 400; }
  .tag { font-family: var(--mono); font-size: 0.8rem; color: var(--muted);
         border: 1px solid var(--line); padding: 2px 8px; white-space: nowrap; }
  .panel { border: 1px solid var(--line); padding: 20px 22px; margin-top: 22px; }
  h2 { font-size: 1.05rem; font-weight: 600; margin: 0 0 12px; }
  #latest { display: flex; flex-direction: column; align-items: center; gap: 10px;
            min-height: 150px; justify-content: center; }
  #latest img { max-width: 100%; max-height: 52vh; border: 1px solid var(--line); }
  #latest .msg { font-size: 1.6rem; font-weight: 600; text-align: center;
                 white-space: pre-wrap; word-break: break-word; }
  .wait { color: var(--muted); font-style: italic; }
  .cap { color: var(--muted); font-size: 0.9rem; font-family: var(--mono); }
  .cap .ok { color: var(--accent); font-weight: 600; }
  .row { font-family: var(--mono); font-size: 0.85rem; padding: 5px 0;
         border-bottom: 1px dotted var(--line); }
  .row .ok { color: var(--accent); }
  .pill { display: inline-block; padding: 0 7px; border: 1px solid var(--ink);
          border-radius: 10px; font-size: 0.75rem; }
</style>
</head><body>
<main>
  <header class="top">
    <h1>Arrivals <span class="muted">— remote receiver (VPS)</span></h1>
    <div class="tag">via the encrypted tunnel</div>
  </header>
  <section class="panel">
    <h2>Latest arrival</h2>
    <div id="latest"><p class="wait">waiting for first transfer…</p></div>
  </section>
  <section class="panel">
    <h2>Arrivals log</h2>
    <div id="log"></div>
  </section>
</main>
<script>
const esc = s => String(s).replace(/[&<>"]/g, c =>
  ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const hhmmss = ts => new Date(ts * 1000).toLocaleTimeString();

function latestHtml(a) {
  let body;
  if ((a.content_type || '').startsWith('image/')) {
    body = `<img src="/media/${a.id}" alt="received image">`;
  } else if (a.text != null) {
    body = `<div class="msg">${esc(a.text)}</div>`;
  } else {
    body = `<div class="msg">binary payload · ${a.size} B</div>`;
  }
  const cap = `received via <b>${esc(a.variant)}</b> tunnel · `
    + `<span class="ok">SHA-256 ✓</span> ${esc((a.sha256||'').slice(0,16))}… · `
    + `${hhmmss(a.ts)}`;
  return body + `<div class="cap">${cap}</div>`;
}

function rowHtml(a) {
  return `<div class="row"><span>${hhmmss(a.ts)}</span> · `
    + `<span class="pill">${esc(a.variant)}</span> · `
    + `${esc(a.filename)} · ${a.size} B · `
    + `<span class="ok">✓</span> ${esc((a.sha256||'').slice(0,8))}</div>`;
}

function render(arrivals) {
  const latest = document.getElementById('latest');
  const log = document.getElementById('log');
  if (!arrivals.length) {
    latest.innerHTML = '<p class="wait">waiting for first transfer…</p>';
    log.innerHTML = '';
    return;
  }
  latest.innerHTML = latestHtml(arrivals[0]);
  log.innerHTML = arrivals.map(rowHtml).join('');
}

async function tick() {
  try {
    const r = await fetch('/arrivals.json', { cache: 'no-store' });
    render((await r.json()).arrivals || []);
  } catch (e) { /* fail-soft: retry next tick */ }
}
tick();
setInterval(tick, 1500);
</script>
</body></html>
"""


STORE = ArrivalStore()


class Handler(BaseHTTPRequestHandler):
    server_version = "pq-demo-receiver/2.0"

    def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 (stdlib naming)
        if self.path != "/payload":
            self.send_error(404, "not found")
            return
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0 or length > MAX_BYTES:
            self.send_error(400, "bad length")
            return

        data = self.rfile.read(length)
        digest = hashlib.sha256(data).hexdigest()
        ctype = self.headers.get("Content-Type", "application/octet-stream")
        filename = self.headers.get("X-Filename", "payload.bin")
        variant = variant_for_addr(self.connection.getsockname()[0])

        STORE.add(variant=variant, filename=filename, sha256=digest,
                  content_type=ctype, data=data)

        # Echo the bytes back so the Mac can verify the round-trip.
        self._send(200, data, ctype, {"X-Sha256": digest})

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/", "/index.html"):
            self._send(200, INDEX_HTML.encode("utf-8"), "text/html; charset=utf-8")
        elif self.path == "/health":
            self._send(200, b"pq-demo receiver up\n", "text/plain")
        elif self.path == "/arrivals.json":
            self._send(200, render_arrivals_json(STORE).encode("utf-8"),
                       "application/json")
        elif self.path.startswith("/media/"):
            try:
                arrival_id = int(self.path[len("/media/"):])
            except ValueError:
                self.send_error(404, "not found")
                return
            entry = STORE.get(arrival_id)
            if entry is None:
                self.send_error(404, "not found")
                return
            ctype = entry["content_type"]
            # Harden the echo-back of attacker-controllable bytes (XSS): only the
            # safe set keeps its type; everything else downloads as octet-stream.
            extra = {
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "default-src 'none'; sandbox",
            }
            if ctype not in SAFE_MEDIA_TYPES:
                ctype = "application/octet-stream"
                extra["Content-Disposition"] = "attachment"
            self._send(200, entry["data"], ctype, extra)
        else:
            self.send_error(404, "not found")

    def log_message(self, fmt: str, *args) -> None:
        # quiet by default; uncomment for debugging
        # super().log_message(fmt, *args)
        pass


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.bind, args.port), Handler)
    print(f"receiver listening on {args.bind}:{args.port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
