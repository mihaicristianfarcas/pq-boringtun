#!/usr/bin/env python3
"""Tiny echo+checksum receiver for the PQ-WireGuard demo (VPS side).

Stdlib only — nothing to pip-install on the VPS. Listens inside the tunnel(s),
hashes whatever it receives, and echoes the bytes straight back with an
``X-Sha256`` header. The Mac side compares hashes to prove the payload crossed
the encrypted tunnel and arrived byte-for-byte.

Run on the VPS (one instance serves all three tunnels):

    python3 receiver.py            # binds 0.0.0.0:8765
    python3 receiver.py --port 8765 --bind 0.0.0.0

Keep it behind the host firewall so 8765 is reachable only via the WG tunnels.
"""

from __future__ import annotations

import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BYTES = 16 * 1024 * 1024  # 16 MiB cap — demo payloads are tiny


class Handler(BaseHTTPRequestHandler):
    server_version = "pq-demo-receiver/1.0"

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

        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Sha256", digest)
        self.end_headers()
        self.wfile.write(data)  # echo it back

    def do_GET(self) -> None:  # noqa: N802
        # simple health check
        if self.path in ("/", "/health"):
            body = b"pq-demo receiver up\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
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
