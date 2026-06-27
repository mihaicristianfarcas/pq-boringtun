"""Unit tests for the boringtun log -> handshake-event parser.

Pure-logic tests against real ``.pretty()`` tcpdump-adjacent fixtures. Run with:

    python3 -m unittest discover -s demo/backend/tests
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from logfeed import parse_handshake_events, read_events  # noqa: E402


# boringtun-cli --foreground uses tracing's .pretty() multi-line format: an
# event line, then an "    at file:line" continuation, then a blank line.
VANILLA_LOG = """\
  2026-06-26T14:46:41.846088Z  INFO boringtun_cli: BoringTun started successfully
    at boringtun-cli/src/main.rs:178

  2026-06-26T14:46:44.758836Z DEBUG boringtun::noise: Sending handshake_initiation
    at boringtun/src/noise/mod.rs:571

  2026-06-26T14:46:44.899360Z DEBUG boringtun::noise: Received handshake_response, local_idx: 2143270145, remote_idx: 1593529857
    at boringtun/src/noise/mod.rs:411

  2026-06-26T14:46:44.902023Z DEBUG boringtun::noise: New session, session: 2143270145
    at boringtun/src/noise/mod.rs:517

  2026-06-26T14:46:44.902054Z DEBUG boringtun::noise: Sending keepalive
    at boringtun/src/noise/mod.rs:429

  2026-06-26T14:46:57.114665Z DEBUG boringtun::noise::timers: KEEPALIVE(KEEPALIVE_TIMEOUT)
    at boringtun/src/noise/timers.rs:286
"""

PQ_LOG = """\
  2026-06-26T14:46:47.060941Z DEBUG boringtun::noise: Sending handshake_initiation
    at boringtun/src/noise/mod.rs:571

  2026-06-26T14:46:47.215435Z DEBUG boringtun::noise: Received pq_handshake_response, local_idx: 1532240897, remote_idx: 1949258753
    at boringtun/src/noise/mod.rs:483

  2026-06-26T14:46:47.226237Z DEBUG boringtun::noise: New session, session: 1532240897
    at boringtun/src/noise/mod.rs:517
"""

WARN_LOG = """\
  2026-06-26T14:47:02.000000Z  WARN boringtun::noise::timers: HANDSHAKE(REKEY_TIMEOUT)
    at boringtun/src/noise/timers.rs:234
"""

# What boringtun-cli --foreground ACTUALLY writes to the log file: tracing's
# .pretty() with ANSI colour left on (only the background path disables it).
# Captured verbatim from /tmp/pq-demo/pq.mac.log.
ANSI_LOG = (
    "  \x1b[2m2026-06-27T06:58:17.950223Z\x1b[0m \x1b[34mDEBUG\x1b[0m "
    "\x1b[1;34mboringtun::noise\x1b[0m\x1b[34m: \x1b[34mSending handshake_initiation\x1b[0m\n"
    "    \x1b[2;3mat\x1b[0m boringtun/src/noise/mod.rs:571\n"
    "\n"
    "  \x1b[2m2026-06-27T06:58:18.104465Z\x1b[0m \x1b[34mDEBUG\x1b[0m "
    "\x1b[1;34mboringtun::noise\x1b[0m\x1b[34m: \x1b[34mReceived pq_handshake_response, "
    "\x1b[1;34mlocal_idx\x1b[0m\x1b[34m: 2775925505\x1b[0m\n"
    "    \x1b[2;3mat\x1b[0m boringtun/src/noise/mod.rs:483\n"
    "  \x1b[2m2026-06-27T06:58:18.116920Z\x1b[0m \x1b[34mDEBUG\x1b[0m "
    "\x1b[1;34mboringtun::noise\x1b[0m\x1b[34m: \x1b[34mNew session, "
    "\x1b[1;34msession\x1b[0m\x1b[34m: 2775925505\x1b[0m\n"
    "  \x1b[2m2026-06-27T06:58:18.117027Z\x1b[0m \x1b[34mDEBUG\x1b[0m "
    "\x1b[1;34mboringtun::noise\x1b[0m\x1b[34m: \x1b[34mSending keepalive\x1b[0m\n"
)


class TestParseHandshakeEvents(unittest.TestCase):
    def test_vanilla_lifecycle_only(self):
        # INFO startup, timer KEEPALIVE spam, and "at file:line" lines all dropped.
        self.assertEqual(
            parse_handshake_events(VANILLA_LOG),
            ["→ handshake_initiation", "← handshake_response",
             "✓ new session", "keepalive"],
        )

    def test_pq_response_labelled(self):
        self.assertEqual(
            parse_handshake_events(PQ_LOG),
            ["→ handshake_initiation", "← pq_handshake_response", "✓ new session"],
        )

    def test_warnings_pass_through(self):
        self.assertEqual(parse_handshake_events(WARN_LOG),
                         ["⚠ HANDSHAKE(REKEY_TIMEOUT)"])

    def test_strips_ansi_colour_codes(self):
        # The real on-disk format is ANSI-coloured; the parser must see through it.
        self.assertEqual(
            parse_handshake_events(ANSI_LOG),
            ["→ handshake_initiation", "← pq_handshake_response",
             "✓ new session", "keepalive"],
        )

    def test_empty(self):
        self.assertEqual(parse_handshake_events(""), [])

    def test_order_preserved(self):
        evs = parse_handshake_events(VANILLA_LOG)
        self.assertEqual(evs[0], "→ handshake_initiation")
        self.assertEqual(evs[-1], "keepalive")


class TestReadEvents(unittest.TestCase):
    def _write(self, d, variant, text):
        with open(os.path.join(d, f"{variant}.mac.log"), "w") as fh:
            fh.write(text)

    def test_reads_all_from_cursor_zero(self):
        with tempfile.TemporaryDirectory() as d:
            self._write(d, "vanilla", VANILLA_LOG)
            events, cursor = read_events(d, "vanilla", after=0)
            self.assertEqual(len(events), 4)
            self.assertEqual(cursor, 4)

    def test_returns_only_new_events_after_cursor(self):
        with tempfile.TemporaryDirectory() as d:
            self._write(d, "vanilla", VANILLA_LOG)
            events, cursor = read_events(d, "vanilla", after=2)
            self.assertEqual(events, ["✓ new session", "keepalive"])
            self.assertEqual(cursor, 4)

    def test_missing_file_is_safe(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(read_events(d, "vanilla", after=0), ([], 0))


if __name__ == "__main__":
    unittest.main()
