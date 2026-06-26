"""Unit tests for the variant registry and endpoint resolution."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import VARIANTS, Settings  # noqa: E402


class TestRegistry(unittest.TestCase):
    def test_three_variants(self):
        self.assertEqual(set(VARIANTS), {"vanilla", "psk", "pq"})

    def test_handshake_sizes_match_thesis(self):
        self.assertEqual((VARIANTS["vanilla"].init_size, VARIANTS["vanilla"].resp_size), (148, 92))
        self.assertEqual((VARIANTS["psk"].init_size, VARIANTS["psk"].resp_size), (148, 92))
        self.assertEqual((VARIANTS["pq"].init_size, VARIANTS["pq"].resp_size), (1332, 1180))

    def test_builds(self):
        # PSK rides the vanilla build (it's out-of-band); only PQ needs the pq build.
        self.assertEqual(VARIANTS["vanilla"].build, "vanilla")
        self.assertEqual(VARIANTS["psk"].build, "vanilla")
        self.assertEqual(VARIANTS["pq"].build, "pq")
        self.assertTrue(VARIANTS["psk"].uses_psk)
        self.assertFalse(VARIANTS["pq"].uses_psk)

    def test_security_verdicts(self):
        self.assertFalse(VARIANTS["vanilla"].quantum_safe)
        self.assertTrue(VARIANTS["psk"].quantum_safe)
        self.assertFalse(VARIANTS["psk"].pq_forward_secrecy)
        self.assertTrue(VARIANTS["pq"].quantum_safe)
        self.assertTrue(VARIANTS["pq"].pq_forward_secrecy)

    def test_unique_ports_ifaces_ips(self):
        ports = [v.port for v in VARIANTS.values()]
        lports = [v.local_peer_port for v in VARIANTS.values()]
        ifaces = [v.iface for v in VARIANTS.values()]
        ips = [v.peer_ip for v in VARIANTS.values()]
        for seq in (ports, lports, ifaces, ips):
            self.assertEqual(len(seq), len(set(seq)), f"duplicate in {seq}")
        # Mac and loopback-peer ports must never collide (same host in --local).
        self.assertTrue(set(ports).isdisjoint(set(lports)))


class TestEndpoint(unittest.TestCase):
    def test_vps_mode_uses_same_port_remote_host(self):
        s = Settings(local=False, vps_host="203.0.113.9")
        self.assertEqual(VARIANTS["pq"].endpoint(s), "203.0.113.9:51822")

    def test_local_mode_uses_loopback_peer_port(self):
        s = Settings(local=True)
        self.assertEqual(VARIANTS["pq"].endpoint(s), "127.0.0.1:51832")

    def test_capture_iface_depends_on_mode(self):
        self.assertEqual(Settings(local=True).capture_iface, "lo0")
        self.assertEqual(Settings(local=False, egress_iface="en0").capture_iface, "en0")


if __name__ == "__main__":
    unittest.main()
