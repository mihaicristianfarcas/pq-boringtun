"""Tunnel orchestration: force a fresh handshake, capture it, report status.

Runtime assumption: the three tunnels are already *pre-staged* (brought up and
proven) by ``scripts/prestage_mac.sh`` before the talk. At demo time the
orchestrator only:

  * resets a peer's session and triggers a fresh handshake on demand, while
  * tcpdump captures the two handshake packets (the live "X-ray"), and
  * reports per-variant status for the dashboard.

Nothing here brings tunnels up from scratch during the demo — that keeps the
only "live" action low-risk. See ``docs/superpowers/specs`` for the rationale.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import threading
import time

from capture import HandshakeCapture, capture_handshake
from config import Settings, Variant

# tcpdump needs a moment to attach to the interface before we trigger traffic.
# sudo + tcpdump startup on macOS can take ~1s; too short and we miss the init
# packet (capture falls back, handshake time shows "n/a"). Err generous.
CAPTURE_WARMUP_S = 1.0


class Orchestrator:
    def __init__(self, settings: Settings):
        self.s = settings

    # --- low-level command helpers -------------------------------------------
    def _run(self, args: list[str], *, sudo: bool = False, timeout: float = 6.0):
        cmd = (["sudo"] if (sudo and self.s.use_sudo) else []) + args
        # Never raise: a slow/failed command (e.g. a ping that gets no reply)
        # must degrade gracefully, not 500 the endpoint mid-demo.
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout if isinstance(exc.stdout, str) else ""
            return subprocess.CompletedProcess(cmd, 124, stdout=out, stderr="timeout")
        except (OSError, subprocess.SubprocessError) as exc:
            return subprocess.CompletedProcess(cmd, 127, stdout="", stderr=str(exc))

    def _peer_pubkey(self, v: Variant) -> str | None:
        """Read the peer public key stashed by prestage_mac.sh."""
        path = os.path.join(self.s.workdir, f"{v.key}.peerpub")
        try:
            with open(path) as fh:
                return fh.read().strip()
        except OSError:
            return None

    # --- forcing a handshake --------------------------------------------------
    def force_handshake(self, v: Variant) -> None:
        """Drop the current session and provoke a new handshake.

        WireGuard has no official "rehandshake now" verb; removing and re-adding
        the peer reliably clears the session so the next data packet triggers a
        fresh handshake. A single ping is that data packet.
        """
        peerpub = self._peer_pubkey(v)
        if not peerpub:
            # Without the peer key we can't re-add; fall back to just pinging,
            # which still handshakes if the session has expired.
            self._run(["ping", "-c", "1", "-t", "2", v.peer_ip], timeout=4.0)
            return

        endpoint = v.endpoint(self.s)

        # 1. drop the session
        self._run(["wg", "set", v.iface, "peer", peerpub, "remove"], sudo=True)
        # 2. re-add the peer (endpoint + allowed-ips, plus PSK where used)
        add = ["wg", "set", v.iface, "peer", peerpub,
               "endpoint", endpoint, "allowed-ips", f"{v.peer_ip}/32"]
        if v.uses_psk:
            add += ["preshared-key", os.path.join(self.s.workdir, "psk.b64")]
        self._run(add, sudo=True)
        # 3. trigger: one packet into the tunnel kicks off the handshake
        self._run(["ping", "-c", "1", "-t", "2", v.peer_ip], timeout=4.0)

    # --- the headline action: connect + live capture --------------------------
    def connect_and_capture(self, v: Variant) -> dict:
        result: dict[str, HandshakeCapture] = {}

        def _cap():
            result["cap"] = capture_handshake(
                self.s.capture_iface, v.port, use_sudo=self.s.use_sudo
            )

        t = threading.Thread(target=_cap, daemon=True)
        t.start()
        time.sleep(CAPTURE_WARMUP_S)        # let tcpdump attach
        try:
            self.force_handshake(v)         # provoke init + response
        except Exception as exc:            # belt-and-suspenders: never 500
            logging.warning("force_handshake(%s) failed: %s", v.key, exc)
        t.join(timeout=10.0)

        cap = result.get("cap")
        if cap is None:
            cap = HandshakeCapture(None, None, None, raw="capture thread timed out")

        # Fall back to the thesis-expected sizes if the live capture missed,
        # so the panel is never blank in front of the committee.
        init = cap.init_size if cap.init_size is not None else v.init_size
        resp = cap.resp_size if cap.resp_size is not None else v.resp_size
        from_fallback = cap.init_size is None or cap.resp_size is None

        return {
            "variant": v.key,
            "init_size": init,
            "resp_size": resp,
            "expected_init": v.init_size,
            "expected_resp": v.resp_size,
            "size_matches_expected": (init == v.init_size and resp == v.resp_size),
            "handshake_ms": cap.elapsed_ms,
            "from_fallback": from_fallback,
            "thesis_us": v.thesis_us,
        }

    # --- status ---------------------------------------------------------------
    def _latest_handshake_epoch(self, v: Variant) -> int:
        """Seconds-since-epoch of the most recent handshake (0 = never)."""
        out = self._run(["wg", "show", v.iface, "latest-handshakes"], sudo=True)
        # format: "<pubkey>\t<epoch>"
        best = 0
        for line in out.stdout.splitlines():
            m = re.search(r"(\d+)\s*$", line.strip())
            if m:
                best = max(best, int(m.group(1)))
        return best

    def _iface_up(self, v: Variant) -> bool:
        return self._run(["ifconfig", v.iface]).returncode == 0

    def _peer_reachable(self, v: Variant) -> bool:
        return self._run(["ping", "-c", "1", "-t", "2", v.peer_ip], timeout=4.0).returncode == 0

    def status(self) -> dict:
        variants = {}
        for key, v in self._all().items():
            variants[key] = {
                "iface_up": self._iface_up(v),
                "peer_reachable": self._peer_reachable(v),
                "last_handshake_age_s": self._age(v),
            }
        return {
            "mode": "local" if self.s.local else "vps",
            "vps_host": self.s.vps_host,
            "capture_iface": self.s.capture_iface,
            "variants": variants,
        }

    def _age(self, v: Variant) -> int | None:
        epoch = self._latest_handshake_epoch(v)
        return None if epoch == 0 else int(time.time() - epoch)

    @staticmethod
    def _all() -> dict[str, Variant]:
        from config import VARIANTS
        return VARIANTS
