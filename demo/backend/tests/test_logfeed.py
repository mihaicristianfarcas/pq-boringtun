"""Unit tests for the boringtun log -> real-event parser.

Pure-logic tests against real ``.pretty()`` fixtures. Run with:

    python3 -m unittest discover -s demo/backend/tests
"""

import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from logfeed import parse_handshake_events, read_events  # noqa: E402

# boringtun logs in UTC; the parser converts to the host's local time. Pin the
# process timezone so the expected wall-clock strings are deterministic on any
# machine. POSIX TZ "XXX-3" means local = UTC+3 with no DST, so a UTC ``HH:MM``
# in a fixture renders as ``HH+3:MM`` below.
_SAVED_TZ = None


def setUpModule():
    global _SAVED_TZ
    _SAVED_TZ = os.environ.get("TZ")
    os.environ["TZ"] = "XXX-3"
    time.tzset()


def tearDownModule():
    if _SAVED_TZ is None:
        os.environ.pop("TZ", None)
    else:
        os.environ["TZ"] = _SAVED_TZ
    time.tzset()


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
  2026-06-26T14:46:47.060941Z DEBUG boringtun::noise: Sending pq_handshake_initiation
    at boringtun/src/noise/mod.rs:572

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
# Captured verbatim from /tmp/pq-demo/pq.mac.log. Note the last two records
# carry no "at" continuation — the parser must handle records with and without.
ANSI_LOG = (
    "  \x1b[2m2026-06-27T06:58:17.950223Z\x1b[0m \x1b[34mDEBUG\x1b[0m "
    "\x1b[1;34mboringtun::noise\x1b[0m\x1b[34m: \x1b[34mSending pq_handshake_initiation\x1b[0m\n"
    "    \x1b[2;3mat\x1b[0m boringtun/src/noise/mod.rs:572\n"
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


def texts(raw):
    return [e["text"] for e in parse_handshake_events(raw)]


class TestParseHandshakeEvents(unittest.TestCase):
    def test_vanilla_real_records(self):
        # Every real record is surfaced (startup INFO, handshake DEBUG, timer
        # DEBUG), with timestamp trimmed to ms and the source location folded in.
        self.assertEqual(
            texts(VANILLA_LOG),
            [
                "17:46:41.846 INFO boringtun_cli: BoringTun started successfully  (main.rs:178)",
                "17:46:44.758 DEBUG boringtun::noise: Sending handshake_initiation  (mod.rs:571)",
                "17:46:44.899 DEBUG boringtun::noise: Received handshake_response, local_idx: 2143270145, remote_idx: 1593529857  (mod.rs:411)",
                "17:46:44.902 DEBUG boringtun::noise: New session, session: 2143270145  (mod.rs:517)",
                "17:46:44.902 DEBUG boringtun::noise: Sending keepalive  (mod.rs:429)",
                "17:46:57.114 DEBUG boringtun::noise::timers: KEEPALIVE(KEEPALIVE_TIMEOUT)  (timers.rs:286)",
            ],
        )

    def test_levels_carried(self):
        evs = parse_handshake_events(VANILLA_LOG)
        self.assertEqual(evs[0]["level"], "INFO")
        self.assertEqual(evs[1]["level"], "DEBUG")

    def test_pq_initiation_labelled(self):
        # The pq build now logs the initiation under its own name.
        self.assertEqual(
            texts(PQ_LOG),
            [
                "17:46:47.060 DEBUG boringtun::noise: Sending pq_handshake_initiation  (mod.rs:572)",
                "17:46:47.215 DEBUG boringtun::noise: Received pq_handshake_response, local_idx: 1532240897, remote_idx: 1949258753  (mod.rs:483)",
                "17:46:47.226 DEBUG boringtun::noise: New session, session: 1532240897  (mod.rs:517)",
            ],
        )

    def test_warnings_carry_level_and_message(self):
        evs = parse_handshake_events(WARN_LOG)
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["level"], "WARN")
        self.assertIn("HANDSHAKE(REKEY_TIMEOUT)", evs[0]["text"])

    def test_strips_ansi_and_handles_missing_at(self):
        # The real on-disk format is ANSI-coloured; the parser must see through it,
        # and the last two records have no "at" line to fold in.
        self.assertEqual(
            texts(ANSI_LOG),
            [
                "09:58:17.950 DEBUG boringtun::noise: Sending pq_handshake_initiation  (mod.rs:572)",
                "09:58:18.104 DEBUG boringtun::noise: Received pq_handshake_response, local_idx: 2775925505  (mod.rs:483)",
                "09:58:18.116 DEBUG boringtun::noise: New session, session: 2775925505",
                "09:58:18.117 DEBUG boringtun::noise: Sending keepalive",
            ],
        )

    def test_empty(self):
        self.assertEqual(parse_handshake_events(""), [])

    def test_order_preserved(self):
        t = texts(VANILLA_LOG)
        self.assertIn("BoringTun started successfully", t[0])
        self.assertIn("KEEPALIVE(KEEPALIVE_TIMEOUT)", t[-1])


class TestReadEvents(unittest.TestCase):
    def _write(self, d, variant, text):
        with open(os.path.join(d, f"{variant}.mac.log"), "w") as fh:
            fh.write(text)

    def test_reads_all_from_cursor_zero(self):
        with tempfile.TemporaryDirectory() as d:
            self._write(d, "vanilla", VANILLA_LOG)
            events, cursor = read_events(d, "vanilla", after=0)
            self.assertEqual(len(events), 6)
            self.assertEqual(cursor, 6)

    def test_returns_only_new_events_after_cursor(self):
        with tempfile.TemporaryDirectory() as d:
            self._write(d, "vanilla", VANILLA_LOG)
            events, cursor = read_events(d, "vanilla", after=4)
            self.assertEqual([e["text"] for e in events], [
                "17:46:44.902 DEBUG boringtun::noise: Sending keepalive  (mod.rs:429)",
                "17:46:57.114 DEBUG boringtun::noise::timers: KEEPALIVE(KEEPALIVE_TIMEOUT)  (timers.rs:286)",
            ])
            self.assertEqual(cursor, 6)

    def test_missing_file_is_safe(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(read_events(d, "vanilla", after=0), ([], 0))


if __name__ == "__main__":
    unittest.main()
