# PQ-WireGuard Live Demo — "Handshake X-ray"

A minimal black-on-white web UI for the thesis defense. It runs the **real**
boringtun handshakes for all three variants — **vanilla**, **PSK-slot**,
**PQ-hybrid** — captures each handshake live with `tcpdump`, and proves each
tunnel end-to-end by round-tripping an image/secret to a remote host.

The point it makes: the data plane is identical across variants (the image
moves the same every time); the difference is **in the handshake** — vanilla
148 B and quantum-broken, PQ-hybrid 1332 B and quantum-safe with forward
secrecy, for a cost that is *size*, not speed.

Design rationale: `../docs/superpowers/specs/2026-06-26-pq-wireguard-live-demo-design.md`

```
demo/
  backend/    FastAPI app + orchestration (config, capture, orchestrator, transfer)
  frontend/   static UI (index.html, style.css, app.js)
  vps/        receiver.py (echo+checksum) + setup.sh (Linux responder)
  scripts/    prestage_mac.sh, local_fallback.sh, smoke_test.sh
```

## Prerequisites

- This repo, buildable (`cargo build` works).
- `wg` (wireguard-tools): `brew install wireguard-tools`.
- Python 3.11+.
- For the headline path: a **free-tier IaaS VM** with SSH (Oracle Cloud Always
  Free Ampere ARM is ideal — it also mirrors the thesis's ARM evaluation;
  GCP `e2-micro` / AWS `t2.micro` work too). A PaaS won't do — WireGuard needs
  `/dev/net/tun`, root, and a UDP listen port.

## Install backend deps

```bash
cd demo/backend
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```

## Passwordless sudo (so the demo never blocks on a prompt)

The server shells out to `tcpdump`, `wg`, `ifconfig`, `ping`. Add a sudoers
drop-in so these run without a password during the talk:

```
# sudo visudo -f /etc/sudoers.d/pq-demo   (replace USER)
USER ALL=(root) NOPASSWD: /usr/sbin/tcpdump, /usr/bin/wg, /sbin/ifconfig, /sbin/ping
```

(Verify paths with `which tcpdump wg ifconfig ping`.)

## Run — headline (VPS) mode

```bash
# 1. prep the VPS + all three tunnels (once, before the talk).
#    Run as your NORMAL user (not sudo) so ssh uses your keys; it elevates the
#    local tunnel commands with sudo and prompts for your password once.
DEMO_VPS_SSH=USER@VPS_IP DEMO_VPS_HOST=VPS_IP demo/scripts/prestage_mac.sh

# 2. confirm everything is up
demo/scripts/smoke_test.sh

# 3. start the UI
cd demo/backend && . .venv/bin/activate
python app.py --vps-host VPS_IP --egress-iface en0
# open http://127.0.0.1:8000
```

## Run — fallback (laptop-only) mode

No VPS, no external network. Both peers run on this Mac over loopback. This is
the in-room safety net **and** the way to rehearse.

```bash
sudo demo/scripts/local_fallback.sh up
demo/scripts/smoke_test.sh
cd demo/backend && . .venv/bin/activate
python app.py --local
# open http://127.0.0.1:8000
# teardown afterwards:
sudo demo/scripts/local_fallback.sh down
```

## The 5-minute flow

1. **Frame it (0:30).** "Same app, three handshakes. Watch what changes — and
   what doesn't."
2. **Vanilla (1:00).** Connect → live `tcpdump` shows 148 B / 92 B. Verdict:
   X25519 only → quantum-broken. Send the image → remote confirmed identical.
3. **PSK (1:00).** Same 148/92 B on the wire — "identical size, but the key now
   carries a one-time ML-KEM secret." Verdict: safe, but no per-session PQ-FS.
4. **PQ-hybrid (1:15).** Connect → balloons to 1332 B / 1180 B. Verdict: safe +
   PQ forward secrecy. Send the same image → identical result, same speed.
5. **Punchline (0:45).** "The data plane never changed. The cost of quantum
   safety is *size in the handshake*, not speed — and the live handshake time
   was dominated by network RTT, so the microseconds of ML-KEM are invisible."
   → ties back to slide 9.

## Fallback ladder

1. **VPS** (headline) → if the venue network misbehaves:
2. **`--local`** loopback mode (no external network) → if anything else breaks:
3. **Pre-recorded screen capture** of a clean run. Record one during rehearsal:
   `Cmd-Shift-5` on macOS.

## Honesty notes (for Q&A)

- **Measured live:** handshake byte sizes (real `tcpdump`), wall-clock handshake
  time over the link, transfer success + SHA-256 match.
- **Stated from the thesis (labelled as such in the UI):** the quantum-safety /
  PQ-FS verdicts and the Criterion crypto-only µs shown next to the live ms.

## Troubleshooting

- **Sizes show "pre-staged" not live:** `tcpdump` missed the packets. Increase
  `CAPTURE_WARMUP_S` in `backend/orchestrator.py`, or re-press Connect.
- **Connect does nothing / ping fails:** check `$DEMO_WORKDIR/<variant>.mac.log`
  (default `/tmp/pq-demo`). Re-run prestage / `local_fallback.sh up`.
- **PSK tunnel won't handshake:** both ends must share `psk.b64`; re-run the PSK
  step (prestage step 5, or `local_fallback.sh` redoes it).
- **Transfer fails:** confirm the receiver is up (`smoke_test.sh`); it listens on
  `:8765` inside the tunnel.

## Tests

```bash
python3 -m unittest discover -s demo/backend/tests
```
