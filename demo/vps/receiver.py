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
  :root { color-scheme: light; }
  body { font: 16px/1.5 -apple-system, system-ui, sans-serif; margin: 0;
         background: #fff; color: #111; }
  header { padding: 14px 20px; border-bottom: 2px solid #111; }
  header b { font-size: 18px; }
  header span { color: #666; }
  main { padding: 20px; }
  .wait { color: #888; font-style: italic; }
  #latest { min-height: 200px; display: flex; flex-direction: column;
            align-items: center; gap: 10px; }
  #latest img { max-width: min(720px, 90vw); max-height: 60vh;
                border: 1px solid #ddd; }
  #latest .msg { font-size: 28px; font-weight: 600; text-align: center;
                 white-space: pre-wrap; word-break: break-word; max-width: 90vw; }
  .cap { color: #555; font-size: 14px; }
  .cap .ok { color: #137333; font-weight: 600; }
  h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .06em;
       color: #666; border-bottom: 1px solid #eee; padding-bottom: 6px;
       margin-top: 28px; }
  .row { font-family: ui-monospace, Menlo, monospace; font-size: 13px;
         padding: 4px 0; border-bottom: 1px dotted #eee; }
  .row b { color: #111; }
  .row .ok { color: #137333; }
  .pill { display: inline-block; padding: 0 6px; border: 1px solid #111;
          border-radius: 10px; font-size: 11px; }
</style>
</head><body>
<header><b>Arrivals — remote receiver (VPS)</b>
  <span>· what actually landed, via the encrypted tunnel</span></header>
<main>
  <div id="latest"><p class="wait">waiting for first transfer…</p></div>
  <h2>Arrivals log</h2>
  <div id="log"></div>
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
            self._send(200, entry["data"], entry["content_type"])
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
