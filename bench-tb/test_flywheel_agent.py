"""Tests for the flywheel Harbor agent's time budget (no Harbor run, no container, no model).

Run with the Harbor tool's interpreter so harbor imports resolve:
  ~/.local/share/uv/tools/harbor/bin/python -m unittest discover -s bench-tb -p 'test_*.py'
"""

import asyncio
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))

from flywheel_agent import (  # noqa: E402
    CMD_TIMEOUT_SEC,
    MAX_TURNS,
    TIMEOUTS_TSV,
    WALL_MARGIN_SEC,
    FlywheelAgent,
    task_budget_sec,
    wall_limit_sec,
)


def tsv_rows():
    rows = []
    for line in TIMEOUTS_TSV.read_text().splitlines():
        if line and not line.startswith("#"):
            name, agent_sec, _verifier = line.split("\t")
            rows.append((name, float(agent_sec)))
    return rows


class FakeEnvironment:
    def __init__(self, environment_name):
        self.environment_name = environment_name
        self.exec_calls = []

    async def exec(self, command, env=None, timeout_sec=None):
        self.exec_calls.append({"command": command, "timeout_sec": timeout_sec})
        return SimpleNamespace(stdout="FW_EXIT_0", stderr="")

    async def download_file(self, source, target):
        return None


class TaskBudgetTest(unittest.TestCase):
    def test_table_has_89_tasks_with_positive_budgets(self):
        rows = tsv_rows()
        self.assertEqual(len(rows), 89)
        self.assertTrue(all(sec > 0 for _, sec in rows))

    def test_budget_is_table_value_times_multiplier(self):
        self.assertEqual(task_budget_sec("adaptive-rejection-sampler", 1.0), 900.0)
        self.assertEqual(task_budget_sec("adaptive-rejection-sampler", 2.0), 1800.0)
        self.assertEqual(task_budget_sec("bn-fit-modify", 0.5), 1800.0)

    def test_extremes_of_the_table_are_not_capped_at_900(self):
        rows = tsv_rows()
        shortest = min(rows, key=lambda r: r[1])
        longest = max(rows, key=lambda r: r[1])
        self.assertEqual(task_budget_sec(shortest[0], 1.0), shortest[1])
        self.assertEqual(task_budget_sec(longest[0], 1.0), longest[1])
        self.assertGreater(longest[1], 900)

    def test_unknown_task_is_an_error_not_a_default(self):
        with self.assertRaises(KeyError):
            task_budget_sec("no-such-task", 1.0)

    def test_wall_limit_is_below_budget_for_every_task(self):
        for name, sec in tsv_rows():
            with self.subTest(task=name):
                self.assertLess(sec - WALL_MARGIN_SEC, sec)
                self.assertGreater(sec - WALL_MARGIN_SEC, CMD_TIMEOUT_SEC)


class WallLimitTest(unittest.TestCase):
    def test_budget_minus_margin(self):
        self.assertEqual(wall_limit_sec(3600), 3540)
        self.assertEqual(wall_limit_sec(600), 540)

    def test_budget_at_or_under_margin_is_refused(self):
        # -W 0 is unlimited in flywheel (src/main.c), so it must not reach the command line
        for budget in (WALL_MARGIN_SEC, WALL_MARGIN_SEC - 1, 0, -5):
            with self.subTest(budget=budget):
                with self.assertRaises(ValueError):
                    wall_limit_sec(budget)

    def test_budget_just_above_margin_gives_one_second(self):
        self.assertEqual(wall_limit_sec(WALL_MARGIN_SEC + 1), 1)

    def test_run_refuses_short_budget_before_any_container_write(self):
        # 600 s table value x 0.05 = 30 s budget, which is under the margin
        logs = Path(tempfile.mkdtemp())
        agent = FlywheelAgent(logs_dir=logs, timeout_multiplier=0.05)
        env = FakeEnvironment("modernize-scientific-stack")
        with self.assertRaises(ValueError):
            asyncio.run(agent.run("x", env, SimpleNamespace()))
        self.assertEqual(env.exec_calls, [])


class RunCommandTest(unittest.TestCase):
    def _run(self, task, multiplier):
        logs = Path(tempfile.mkdtemp())
        agent = FlywheelAgent(logs_dir=logs, timeout_multiplier=multiplier)
        env = FakeEnvironment(task)
        asyncio.run(agent.run("do the thing", env, SimpleNamespace()))
        return next(c for c in env.exec_calls if "flywheel -q" in c["command"])

    def test_limits_follow_budget(self):
        call = self._run("bn-fit-modify", 1.0)
        self.assertIn(f"-W {int(3600 - WALL_MARGIN_SEC)} ", call["command"])
        self.assertIn(f"-T {MAX_TURNS} ", call["command"])
        self.assertIn(f"-t {CMD_TIMEOUT_SEC} ", call["command"])
        self.assertEqual(call["timeout_sec"], 3600 - WALL_MARGIN_SEC + 120)

    def test_multiplier_scales_the_wall_limit(self):
        call = self._run("adaptive-rejection-sampler", 0.5)
        self.assertIn(f"-W {int(450 - WALL_MARGIN_SEC)} ", call["command"])

    def test_no_flywheel_run_for_unknown_task(self):
        logs = Path(tempfile.mkdtemp())
        agent = FlywheelAgent(logs_dir=logs)
        env = FakeEnvironment("no-such-task")
        with self.assertRaises(KeyError):
            asyncio.run(agent.run("x", env, SimpleNamespace()))
        self.assertFalse(any("flywheel -q" in c["command"] for c in env.exec_calls))


if __name__ == "__main__":
    unittest.main()
