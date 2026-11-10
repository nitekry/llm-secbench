"""Offline self-tests: no model or server needed.

    python3 -m unittest discover -s tests -v
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import gen_code  # noqa: E402
import run_bench as rb  # noqa: E402


class TestJsonExtraction(unittest.TestCase):
    def test_fenced_and_chatty(self):
        self.assertEqual(rb.extract_json('Sure!\n```json\n{"a": 1}\n```'), {"a": 1})
        self.assertEqual(rb.extract_json('{bad} then {"b": 2}'), {"b": 2})
        self.assertIsNone(rb.extract_json("no json here"))


class TestCodeScoring(unittest.TestCase):
    vuln = dict(track="code", key=dict(vulnerable=True, cwe=[89], lines=[20, 22]))
    safe = dict(track="code", key=dict(vulnerable=False, cwe=[], lines=[]))

    def test_full_credit_needs_cwe_and_line(self):
        s = rb.score_task(self.vuln, {"vulnerable": True, "cwe": "CWE-89", "line": 24})
        self.assertTrue(s["full"])  # within +-2 of line 22
        s = rb.score_task(self.vuln, {"vulnerable": True, "cwe": "CWE-79", "line": 20})
        self.assertFalse(s["full"])
        s = rb.score_task(self.vuln, {"vulnerable": True, "cwe": "CWE-89", "line": 30})
        self.assertFalse(s["full"])

    def test_safe_sample(self):
        self.assertTrue(rb.score_task(self.safe, {"vulnerable": False})["full"])
        self.assertFalse(rb.score_task(self.safe, {"vulnerable": "true", "cwe": "CWE-89"})["full"])

    def test_invalid(self):
        self.assertFalse(rb.score_task(self.vuln, None)["valid"])


class TestLogScoring(unittest.TestCase):
    key = dict(first_seen="16:28:48", attacker_ip="141.79.72.158")

    def test_first_seen(self):
        ok = rb.first_seen_ok
        self.assertTrue(ok("Nov  3 16:28:48", self.key))
        self.assertTrue(ok("03/Nov/2026:16:28:48 +0000", self.key))
        self.assertTrue(ok("Nov  3 16:28:48 web01 sshd: Accepted password for x from 141.79.72.158 port 1", self.key))
        # a pasted line from a different host, or more than one time, does not count
        self.assertFalse(ok("Nov  3 16:28:48 web01 sshd: Failed password from 103.254.124.130 port 1", self.key))
        self.assertFalse(ok("16:28:48 to 18:43:48", self.key))
        self.assertFalse(ok("", self.key))

    def test_technique_list_shuffled_but_deterministic(self):
        t = dict(id="log-L1", track="logs", file="x", fmt="f")
        orders = set()
        for tid in ("log-L1", "log-L2", "log-L3", "log-L4"):
            t["id"] = tid
            rng = rb.random.Random(tid)
            lst = list(rb.TECHNIQUES)
            rng.shuffle(lst)
            orders.add(tuple(lst))
        self.assertGreater(len(orders), 1)


class TestGenerator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        gen_code.ROOT = Path(cls.tmp.name)
        (gen_code.ROOT / "tasks").mkdir()
        cls.m1 = json.loads(gen_code.build(101).read_text())
        cls.text1 = {t["id"]: (gen_code.ROOT / t["file"]).read_text() for t in cls.m1["tasks"]}
        cls.m1b = json.loads(gen_code.build(101).read_text())
        cls.text1b = {t["id"]: (gen_code.ROOT / t["file"]).read_text() for t in cls.m1b["tasks"]}
        cls.m2 = json.loads(gen_code.build(102).read_text())
        cls.text2 = {t["id"].replace("gen102", "gen101"): (gen_code.ROOT / t["file"]).read_text() for t in cls.m2["tasks"]}

    @classmethod
    def tearDownClass(cls):
        gen_code.ROOT = ROOT
        cls.tmp.cleanup()

    def test_shape(self):
        tasks = self.m1["tasks"]
        self.assertEqual(len(tasks), len(gen_code.F) * 4)
        for t in tasks:
            k = t["key"]
            self.assertEqual(k["vulnerable"], k["variant"] in ("obvious", "hidden"))
            self.assertEqual(bool(k["lines"]), k["vulnerable"])

    def test_markers_stripped(self):
        for text in self.text1.values():
            self.assertNotIn("@@VULN@@", text)
            self.assertNotIn("${", text)

    def test_deterministic_per_seed(self):
        self.assertEqual(self.text1, self.text1b)

    def test_seeds_differ(self):
        same = sum(self.text1[k] == self.text2.get(k) for k in self.text1)
        self.assertLess(same, len(self.text1) // 4)


if __name__ == "__main__":
    unittest.main()
