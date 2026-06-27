"""Surface boringtun's *real* foreground log as events for the UI strip.

``boringtun-cli --foreground`` logs with tracing's ``.pretty()`` multi-line,
ANSI-coloured format::

    2026-...Z DEBUG boringtun::noise: Sending pq_handshake_initiation
      at boringtun/src/noise/mod.rs:571

Rather than collapse that to terse tokens (which read like something faked in
the frontend), we surface boringtun's genuine output: the wall-clock time, the
level, the target module, the full message (session indices and all), and the
source location. We strip the ANSI colour, convert boringtun's ISO-8601 UTC
timestamp to the host's local wall-clock trimmed to ``HH:MM:SS.mmm``, and fold
the ``at file:line`` continuation onto its event line. Apart from showing the
time in your local zone (boringtun logs in UTC), what you see is exactly what
the daemon wrote.
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone

# boringtun-cli --foreground writes ANSI-coloured logs (only the background path
# disables colour), so the on-disk lines are full of "\x1b[34m…\x1b[0m". Strip
# those SGR escapes before matching or the level/target regex never fires.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# A primary record line (after ANSI strip): leading indent, ISO-8601 UTC stamp
# (date + time captured separately so we can convert the instant to local time),
# level (pretty() left-pads to 5, e.g. " INFO"/" WARN"), the target module, then
# the message. The target is non-space; the first ": " after it splits message.
_RECORD_RE = re.compile(
    r"^\s*(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})\.(\d+)Z\s+"
    r"(TRACE|DEBUG|INFO|WARN|ERROR)\s+(\S+):\s+(.*\S)\s*$"
)
# The "    at file:line" continuation pretty() prints beneath each record.
_AT_RE = re.compile(r"^\s*at\s+(\S+):(\d+)\s*$")


def _utc_to_local_hms(date: str, hms: str, frac: str) -> str:
    """Render a parsed UTC stamp as the host's local ``HH:MM:SS.mmm``.

    boringtun timestamps its log in UTC (the ISO-8601 ``…Z`` suffix); the strip
    is read by a human at the laptop, so we shift the instant into the host's
    local timezone before trimming to milliseconds.
    """
    micro = (frac + "000000")[:6]  # pad/truncate fractional seconds to microseconds
    utc = datetime.strptime(f"{date} {hms}.{micro}", "%Y-%m-%d %H:%M:%S.%f").replace(
        tzinfo=timezone.utc
    )
    local = utc.astimezone()  # no arg -> host local timezone
    return local.strftime("%H:%M:%S.") + f"{local.microsecond // 1000:03d}"


def parse_handshake_events(raw: str) -> list[dict]:
    """Parse boringtun pretty-log text into real event records, in order.

    Returns ``{"level", "text"}`` dicts, where ``text`` is the genuine log line
    rebuilt as ``HH:MM:SS.mmm LEVEL target: message  (file:line)``. ``level`` is
    carried separately so the UI can emphasise WARN/ERROR without re-parsing.
    """
    events: list[dict] = []
    for line in raw.splitlines():
        line = _ANSI_RE.sub("", line)  # drop colour codes first
        m = _RECORD_RE.match(line)
        if m:
            date, hms, frac, level, target, msg = m.groups()
            stamp = _utc_to_local_hms(date, hms, frac)
            events.append({"level": level, "text": f"{stamp} {level} {target}: {msg}"})
            continue
        a = _AT_RE.match(line)
        if a and events:  # attach the source location to the record above it
            loc = f"{os.path.basename(a.group(1))}:{a.group(2)}"
            events[-1]["text"] += f"  ({loc})"
    return events


def read_events(workdir: str, variant: str, after: int = 0) -> tuple[list[dict], int]:
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
