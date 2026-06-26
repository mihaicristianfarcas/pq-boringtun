"""Unit tests for the tcpdump output parser.

Pure-logic tests — no root, no real interface required. Run with:

    python3 -m unittest demo.backend.tests.test_capture     (from repo root)
or
    python3 -m unittest discover -s demo/backend/tests
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from capture import (  # noqa: E402
    handshake_delta_ms,
    parse_udp_lengths,
    parse_udp_timestamps,
)


VANILLA = """\
12:00:00.000001 IP 10.13.0.1.51820 > 10.13.0.2.51820: UDP, length 148
12:00:00.012002 IP 10.13.0.2.51820 > 10.13.0.1.51820: UDP, length 92
"""

PQ = """\
12:00:00.000001 IP 10.13.2.1.51822 > 10.13.2.2.51822: UDP, length 1332
12:00:00.034002 IP 10.13.2.2.51822 > 10.13.2.1.51822: UDP, length 1180
"""

NOISY = """\
12:00:00.000000 ARP, Request who-has 10.13.0.2 tell 10.13.0.1, length 28
12:00:00.000001 IP 10.13.0.1.51820 > 10.13.0.2.51820: UDP, length 148

12:00:00.012002 IP 10.13.0.2.51820 > 10.13.0.1.51820: UDP, length 92
"""


class TestParseUdpLengths(unittest.TestCase):
    def test_vanilla_sizes(self):
        self.assertEqual(parse_udp_lengths(VANILLA), [148, 92])

    def test_pq_sizes(self):
        self.assertEqual(parse_udp_lengths(PQ), [1332, 1180])

    def test_ignores_arp_and_blank_lines(self):
        # ARP line also contains "length 28" but no "UDP" — must be skipped.
        self.assertEqual(parse_udp_lengths(NOISY), [148, 92])

    def test_empty_input(self):
        self.assertEqual(parse_udp_lengths(""), [])

    def test_order_preserved(self):
        # Init must come before response so the UI labels them correctly.
        lengths = parse_udp_lengths(PQ)
        self.assertEqual(lengths[0], 1332)
        self.assertEqual(lengths[1], 1180)


# A handshake that crosses a wall-clock second boundary (init at .980, response
# 40 ms later at the next second) — the delta must still be 40 ms, not -960 ms.
ACROSS_SECOND = """\
12:00:00.980000 IP 10.13.0.1.51820 > 10.13.0.2.51820: UDP, length 148
12:00:01.020000 IP 10.13.0.2.51820 > 10.13.0.1.51820: UDP, length 92
"""

# Both packets straddling midnight — exercises the day-wrap guard.
ACROSS_MIDNIGHT = """\
23:59:59.990000 IP 10.13.0.1.51820 > 10.13.0.2.51820: UDP, length 148
00:00:00.030000 IP 10.13.0.2.51820 > 10.13.0.1.51820: UDP, length 92
"""


class TestParseUdpTimestamps(unittest.TestCase):
    def test_seconds_of_day_in_order(self):
        # 12:00:00.000001 and 12:00:00.012002 -> 43200.000001, 43200.012002
        ts = parse_udp_timestamps(VANILLA)
        self.assertEqual(len(ts), 2)
        self.assertAlmostEqual(ts[0], 43200.000001, places=6)
        self.assertAlmostEqual(ts[1], 43200.012002, places=6)

    def test_ignores_arp_line(self):
        # Only the two UDP packets get a timestamp, not the leading ARP.
        self.assertEqual(len(parse_udp_timestamps(NOISY)), 2)

    def test_empty_input(self):
        self.assertEqual(parse_udp_timestamps(""), [])


class TestHandshakeDeltaMs(unittest.TestCase):
    def test_vanilla_delta(self):
        # 12.001 ms between init and response — the real on-wire handshake time,
        # independent of the tcpdump warmup.
        self.assertAlmostEqual(handshake_delta_ms(VANILLA), 12.001, places=2)

    def test_pq_delta(self):
        self.assertAlmostEqual(handshake_delta_ms(PQ), 34.001, places=2)

    def test_ignores_arp_line(self):
        self.assertAlmostEqual(handshake_delta_ms(NOISY), 12.001, places=2)

    def test_none_when_no_response_captured(self):
        # Only the init packet made it into the capture — no delta to report.
        one_packet = "12:00:00.000001 IP 10.13.0.1.51820 > 10.13.0.2.51820: UDP, length 148\n"
        self.assertIsNone(handshake_delta_ms(one_packet))

    def test_none_on_empty(self):
        self.assertIsNone(handshake_delta_ms(""))

    def test_delta_across_second_boundary(self):
        self.assertAlmostEqual(handshake_delta_ms(ACROSS_SECOND), 40.0, places=2)

    def test_delta_across_midnight(self):
        self.assertAlmostEqual(handshake_delta_ms(ACROSS_MIDNIGHT), 40.0, places=2)


if __name__ == "__main__":
    unittest.main()
