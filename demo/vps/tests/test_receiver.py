"""Unit tests for the VPS receiver's pure seams (arrival store, variant map,
JSON render). Stdlib only — no socket/HTTP needed. Run with:

    python3 -m unittest discover -s demo/vps/tests        (from repo root)
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from receiver import ArrivalStore, render_arrivals_json, variant_for_addr  # noqa: E402


class TestVariantForAddr(unittest.TestCase):
    def test_known_tunnel_ips(self):
        self.assertEqual(variant_for_addr("10.13.0.2"), "vanilla")
        self.assertEqual(variant_for_addr("10.13.1.2"), "psk")
        self.assertEqual(variant_for_addr("10.13.2.2"), "pq")

    def test_unknown_ip_is_question_mark(self):
        self.assertEqual(variant_for_addr("1.2.3.4"), "?")
        self.assertEqual(variant_for_addr(""), "?")


class TestArrivalStore(unittest.TestCase):
    def _add(self, store, name, data=b"x"):
        return store.add(
            variant="pq",
            filename=name,
            sha256="deadbeef",
            content_type="text/plain",
            data=data,
        )

    def test_add_returns_increasing_ids(self):
        s = ArrivalStore()
        self.assertEqual(self._add(s, "a"), 0)
        self.assertEqual(self._add(s, "b"), 1)

    def test_list_meta_newest_first_without_raw_bytes(self):
        s = ArrivalStore()
        self._add(s, "a")
        self._add(s, "b")
        meta = s.list_meta()
        self.assertEqual([m["filename"] for m in meta], ["b", "a"])
        # metadata must never leak the raw payload bytes
        self.assertNotIn("data", meta[0])
        self.assertEqual(meta[0]["size"], 1)
        self.assertEqual(meta[0]["variant"], "pq")
        self.assertEqual(meta[0]["sha256"], "deadbeef")

    def test_get_returns_full_entry_with_bytes(self):
        s = ArrivalStore()
        i = self._add(s, "a", data=b"hello")
        entry = s.get(i)
        self.assertEqual(entry["data"], b"hello")
        self.assertEqual(entry["content_type"], "text/plain")

    def test_get_unknown_id_is_none(self):
        self.assertIsNone(ArrivalStore().get(99))

    def test_maxlen_evicts_oldest_but_ids_stay_stable(self):
        s = ArrivalStore(maxlen=2)
        i0 = self._add(s, "a")
        i1 = self._add(s, "b")
        i2 = self._add(s, "c")
        self.assertEqual([m["filename"] for m in s.list_meta()], ["c", "b"])
        self.assertIsNone(s.get(i0))          # oldest evicted
        self.assertIsNotNone(s.get(i1))       # survivors keep their ids
        self.assertIsNotNone(s.get(i2))


class TestRenderArrivalsJson(unittest.TestCase):
    def test_shape_newest_first_no_bytes(self):
        s = ArrivalStore()
        s.add(variant="vanilla", filename="a.txt", sha256="aa",
              content_type="text/plain", data=b"a")
        s.add(variant="pq", filename="b.png", sha256="bb",
              content_type="image/png", data=b"b")
        payload = json.loads(render_arrivals_json(s))
        self.assertIn("arrivals", payload)
        self.assertEqual([a["filename"] for a in payload["arrivals"]],
                         ["b.png", "a.txt"])
        self.assertNotIn("data", payload["arrivals"][0])
        self.assertEqual(payload["arrivals"][0]["variant"], "pq")


if __name__ == "__main__":
    unittest.main()
