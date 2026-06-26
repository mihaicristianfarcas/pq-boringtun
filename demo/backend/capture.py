"""Live handshake capture via tcpdump, plus a pure parser for its output.

The parser is deliberately separated from the subprocess plumbing so it can be
unit-tested without root or a real interface (see tests/test_capture.py).
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass

# tcpdump (BSD/macOS) prints UDP records ending in e.g. "UDP, length 1332".
_LENGTH_RE = re.compile(r"\blength\s+(\d+)\b")
# ...and a leading wall-clock timestamp, e.g. "12:00:00.012002 IP ...".
_TIME_RE = re.compile(r"^\s*(\d{1,2}):(\d{2}):(\d{2}(?:\.\d+)?)")
_SECONDS_PER_DAY = 24 * 3600


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


def parse_udp_timestamps(tcpdump_output: str) -> list[float]:
    """Extract each UDP packet's wall-clock time, in seconds-of-day, in order.

    Mirrors :func:`parse_udp_lengths` (same UDP-only filtering, same order), so
    ``timestamps[i]`` lines up with ``lengths[i]``. From tcpdump's default
    ``HH:MM:SS.ffffff`` prefix; non-UDP and untimestamped lines are skipped.
    """
    times: list[float] = []
    for line in tcpdump_output.splitlines():
        if "UDP" not in line and "udp" not in line:
            continue
        m = _TIME_RE.match(line)
        if m:
            h, minute, sec = int(m.group(1)), int(m.group(2)), float(m.group(3))
            times.append(h * 3600 + minute * 60 + sec)
    return times


def handshake_delta_ms(tcpdump_output: str) -> float | None:
    """Milliseconds between the first two captured packets (init -> response).

    This is the real on-the-wire handshake latency, independent of how long
    tcpdump took to attach. ``None`` if fewer than two packets were captured.
    """
    times = parse_udp_timestamps(tcpdump_output)
    if len(times) < 2:
        return None
    delta = times[1] - times[0]
    if delta < 0:  # the two packets straddled midnight; unwrap the day rollover
        delta += _SECONDS_PER_DAY
    return round(delta * 1000.0, 2)


@dataclass
class HandshakeCapture:
    """Result of capturing one handshake exchange."""

    init_size: int | None       # first packet (initiation), bytes
    resp_size: int | None       # second packet (response), bytes
    elapsed_ms: float | None    # ms between init and response = real handshake RTT
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
    # -n no name resolution, -q quiet protocol, -l line-buffered. We deliberately
    # KEEP tcpdump's default timestamp prefix: the reported handshake time is the
    # delta between the init and response packets (handshake_delta_ms), which is
    # the real on-wire latency, free of however long tcpdump took to attach.
    cmd += [
        "tcpdump",
        "-i", iface,
        "-n",
        "-q",
        "-c", str(count),
        "-l",
        f"udp port {port}",
    ]

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

    init_size = lengths[0] if len(lengths) >= 1 else None
    resp_size = lengths[1] if len(lengths) >= 2 else None

    return HandshakeCapture(
        init_size=init_size,
        resp_size=resp_size,
        elapsed_ms=handshake_delta_ms(out),
        raw=out,
    )
