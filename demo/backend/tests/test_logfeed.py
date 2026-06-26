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
