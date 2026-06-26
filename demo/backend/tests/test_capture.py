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

from capture import parse_udp_lengths  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
