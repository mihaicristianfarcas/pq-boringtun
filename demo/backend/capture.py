"""Live handshake capture via tcpdump, plus a pure parser for its output.

The parser is deliberately separated from the subprocess plumbing so it can be
unit-tested without root or a real interface (see tests/test_capture.py).
"""

from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass

# tcpdump (BSD/macOS) prints UDP records ending in e.g. "UDP, length 1332".
_LENGTH_RE = re.compile(r"\blength\s+(\d+)\b")


def parse_udp_lengths(tcpdump_output: str) -> list[int]:
    """Extract UDP payload lengths, in capture order, from tcpdump text.

    Works with the default macOS/BSD tcpdump format, e.g.::

        12:00:00.000001 IP 10.0.0.1.51822 > 10.0.0.2.51822: UDP, length 1332
        12:00:00.010002 IP 10.0.0.2.51822 > 10.0.0.1.51822: UDP, length 1180

    Lines without a UDP length (ARP, DNS noise, blank lines) are ignored.
    """
    lengths: list[int] = []
    for line in tcpdump_output.splitlines():
        if "UDP" not in line and "udp" not in line:
            continue
        m = _LENGTH_RE.search(line)
        if m:
            lengths.append(int(m.group(1)))
    return lengths


@dataclass
class HandshakeCapture:
    """Result of capturing one handshake exchange."""

    init_size: int | None       # first packet (initiation), bytes
    resp_size: int | None       # second packet (response), bytes
    elapsed_ms: float | None    # wall-clock from first to second packet
    raw: str                    # raw tcpdump text, for debugging
    from_fallback: bool = False # True if live capture missed and we used defaults

    def as_dict(self) -> dict:
        return {
            "init_size": self.init_size,
            "resp_size": self.resp_size,
            "elapsed_ms": self.elapsed_ms,
            "from_fallback": self.from_fallback,
        }


def capture_handshake(
    iface: str,
    port: int,
    *,
    use_sudo: bool = True,
    count: int = 2,
    timeout_s: float = 8.0,
) -> HandshakeCapture:
    """Capture the next ``count`` UDP packets on ``iface``/``port``.

    Intended to run concurrently with a forced handshake (see orchestrator):
    start this first, then trigger the handshake, then read the result.

    Returns a HandshakeCapture; sizes are ``None`` if nothing was captured
    (the orchestrator substitutes the variant's expected sizes in that case).
    """
    cmd: list[str] = []
    if use_sudo:
        cmd += ["sudo"]
    # -l line-buffered, -n no name resolution, -t no timestamp prefix? we keep
    # timestamps off and time it ourselves for portability. -q quiet protocol.
    cmd += [
        "tcpdump",
        "-i", iface,
        "-n",
        "-q",
        "-c", str(count),
        "-l",
        f"udp port {port}",
    ]

    start = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        out = proc.stdout + "\n" + proc.stderr
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or b"").decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")

    lengths = parse_udp_lengths(out)
    elapsed_ms = (time.monotonic() - start) * 1000.0 if lengths else None

    init_size = lengths[0] if len(lengths) >= 1 else None
    resp_size = lengths[1] if len(lengths) >= 2 else None

    return HandshakeCapture(
        init_size=init_size,
        resp_size=resp_size,
        elapsed_ms=round(elapsed_ms, 2) if elapsed_ms is not None else None,
        raw=out,
    )
