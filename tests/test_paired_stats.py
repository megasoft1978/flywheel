#!/usr/bin/env python3
"""Tests for bench-tb/paired_stats.py (stdlib unittest). Run: python3 tests/test_paired_stats.py"""
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bench-tb"))
import paired_stats as ps  # noqa: E402


class Stats(unittest.TestCase):
    def test_wilson_known(self):
        lo, hi = ps.wilson(8, 10)
        self.assertAlmostEqual(lo, 0.4902, places=3)
        self.assertAlmostEqual(hi, 0.9433, places=3)
        self.assertEqual(ps.wilson(0, 0), (0.0, 0.0))
        lo, hi = ps.wilson(0, 10)
        self.assertAlmostEqual(lo, 0.0, places=9)
        self.assertGreater(hi, 0.2)

    def test_mcnemar_known(self):
        # b=9,c=1 -> 2 * (1+10)/1024
        self.assertAlmostEqual(ps.mcnemar_exact(9, 1), 22 / 1024)
        self.assertEqual(ps.mcnemar_exact(0, 0), 1.0)
        self.assertEqual(ps.mcnemar_exact(5, 5), 1.0)
        self.assertAlmostEqual(ps.mcnemar_exact(24, 3), ps.mcnemar_exact(3, 24))
        self.assertLess(ps.mcnemar_exact(24, 3), 1e-3)  # Cortheon pooled AIME: +24/-3

    def test_compare(self):
        a = {"t1": True, "t2": False, "t3": True, "t4": False, "x": True}
        b = {"t1": True, "t2": True, "t3": False, "t4": False, "y": True}
        r = ps.compare(a, b)
        self.assertEqual(r["n"], 4)
        self.assertEqual((r["both"], r["neither"]), (1, 1))
        self.assertEqual((r["fix"], r["brk"]), (["t2"], ["t3"]))
        self.assertEqual((r["only_a"], r["only_b"]), (["x"], ["y"]))
        self.assertEqual(r["p"], 1.0)


class Loaders(unittest.TestCase):
    def _harbor(self, d, rows):
        for i, (task, rw) in enumerate(rows):
            td = os.path.join(d, f"{task}__{i}")
            os.makedirs(td)
            with open(os.path.join(td, "result.json"), "w") as f:
                json.dump({"task_name": f"terminal-bench/{task}",
                           "verifier_result": {"rewards": {"reward": rw}}}, f)
        with open(os.path.join(d, "result.json"), "w") as f:
            json.dump({"id": "job-level, no task_name"}, f)

    def test_harbor_dir(self):
        with tempfile.TemporaryDirectory() as d:
            self._harbor(d, [("a", 1.0), ("b", 0.0)])
            got, multi = ps.load(d)
            self.assertEqual(got, {"a": True, "b": False})
            self.assertEqual(multi, 0)

    def test_harbor_multi_trial(self):
        with tempfile.TemporaryDirectory() as d:
            self._harbor(d, [("a", 1.0), ("a", 1.0), ("a", 0.0), ("b", 0.0), ("b", 0.0)])
            got, multi = ps.load(d)
            self.assertEqual(got, {"a": True, "b": False})
            self.assertEqual(multi, 2)

    def test_fw_summary(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "summary.json")
            with open(p, "w") as f:
                json.dump([{"id": "x", "attempts": [{"full_pass": True}]},
                           {"id": "y", "attempts": [{"full_pass": False}]},
                           {"id": "z", "attempts": []}], f)
            self.assertEqual(ps.load(p)[0], {"x": True, "y": False})
            self.assertEqual(ps.load(d)[0], {"x": True, "y": False})  # dir containing summary.json

    def test_missing(self):
        with self.assertRaises(SystemExit):
            ps.load("/nonexistent/path/xyz")


class Report(unittest.TestCase):
    def test_report_text(self):
        a = {f"t{i}": i < 4 for i in range(10)}
        b = {f"t{i}": i < 7 for i in range(10)}
        out = io.StringIO()
        ps.report(ps.compare(a, b), "base", "cand", out)
        s = out.getvalue()
        self.assertIn("4/10", s)
        self.assertIn("7/10", s)
        self.assertIn("+30.0 pts", s)
        self.assertIn("+3 fixed / -0 broken", s)
        self.assertIn("McNemar p = 0.2500", s)
        self.assertIn("caution", s)


if __name__ == "__main__":
    unittest.main()
