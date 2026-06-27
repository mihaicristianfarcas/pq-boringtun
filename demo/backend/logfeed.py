"""Turn boringtun's foreground log into clean handshake events for the UI strip.

``boringtun-cli --foreground`` logs with tracing's ``.pretty()`` multi-line
format::

    2026-...Z DEBUG boringtun::noise: Sending handshake_initiation
      at boringtun/src/noise/mod.rs:571

We surface only the handshake lifecycle (init / response / new session /
keepalive) plus any WARN/ERROR (timeouts, expiries), and drop the
``at file:line`` continuations, timer KEEPALIVE spam, and INFO startup chatter.
"""

from __future__ import annotations

import os
import re

# boringtun-cli --foreground writes ANSI-coloured logs (only the background path
# disables colour), so the on-disk lines are full of "\x1b[34m…\x1b[0m". Strip
# those SGR escapes before matching or the level/target regex never fires.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# After the timestamp: "<LEVEL> <target>: <message>". The target is non-space
# (e.g. boringtun::noise); backtracking lands ":" on the target/message split.
_EVENT_RE = re.compile(r"\b(DEBUG|INFO|WARN|ERROR)\s+\S+:\s+(.+?)\s*$")

# message prefix -> clean strip label. pq variants first so they win the match.
_LIFECYCLE = [
    ("Sending pq_handshake_initiation", "→ pq_handshake_initiation"),
    ("Sending handshake_initiation", "→ handshake_initiation"),
    ("Sending pq_handshake_response", "→ pq_handshake_response"),
    ("Sending handshake_response", "→ handshake_response"),
    ("Received pq_handshake_initiation", "← pq_handshake_initiation"),
    ("Received handshake_initiation", "← handshake_initiation"),
    ("Received pq_handshake_response", "← pq_handshake_response"),
    ("Received handshake_response", "← handshake_response"),
    ("New session", "✓ new session"),
    ("Sending keepalive", "keepalive"),
]


def _event_for(level: str, msg: str) -> str | None:
    for prefix, label in _LIFECYCLE:
        if msg.startswith(prefix):
            return label
    if level in ("WARN", "ERROR"):
        return "⚠ " + msg
    return None  # drop INFO startup + DEBUG timer spam (KEEPALIVE/HANDSHAKE)


def parse_handshake_events(raw: str) -> list[str]:
    """Extract clean handshake-event labels from raw boringtun log text."""
    events: list[str] = []
    for line in raw.splitlines():
        line = _ANSI_RE.sub("", line)         # drop colour codes first
        if line.lstrip().startswith("at "):  # "    at file:line" continuation
            continue
        m = _EVENT_RE.search(line)
        if not m:
            continue
        ev = _event_for(m.group(1), m.group(2))
        if ev is not None:
            events.append(ev)
    return events


def read_events(workdir: str, variant: str, after: int = 0) -> tuple[list[str], int]:
    """Events for ``{variant}.mac.log`` past index ``after``, plus the new cursor.

    The cursor is the total event count so far; the frontend passes it back as
    ``after`` to fetch only what's new. Missing/unreadable log -> ``([], 0)``.
    """
    path = os.path.join(workdir, f"{variant}.mac.log")
    try:
        with open(path, "r", errors="replace") as fh:
            raw = fh.read()
    except OSError:
        return ([], 0)
    events = parse_handshake_events(raw)
    return (events[after:], len(events))
