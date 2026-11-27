#!/usr/bin/env python3
"""Paired comparison of two benchmark runs (baseline vs candidate).

Single runs on a 10-task slice cannot tell a real harness improvement from
noise. This script compares two runs task-by-task and reports:

  * pass rate per arm with a 95% Wilson interval
  * the paired table: both pass / fixed (+) / broken (-) / both fail
  * exact two-sided McNemar p-value on the discordant pairs
  * the list of tasks that flipped

Supported inputs (auto-detected):
  * a Harbor job directory  (<job>/<trial>/result.json with verifier_result)
  * a flywheel bench summary.json  (pass = attempts[0].full_pass)

Usage:
  paired_stats.py BASELINE CANDIDATE [--names base cand]

Stdlib only. Exit status is always 0 unless the inputs cannot be read.
"""
import argparse
import glob
import json
import math
import os
import sys


def wilson(k, n, z=1.959964):
    """95% Wilson score interval for k successes out of n, as (lo, hi)."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - h) / d, (c + h) / d)


def mcnemar_exact(b, c):
    """Exact two-sided McNemar p-value; b, c are the two discordant counts."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / (2 ** n)
    return min(1.0, 2 * tail)


def _load_harbor(path):
    rewards = {}
    for rj in glob.glob(os.path.join(path, "*", "result.json")):
        try:
            with open(rj) as f:
                d = json.load(f)
        except (OSError, ValueError):
            continue
        task = d.get("task_name")
        if not task:
            continue
        task = task.split("/")[-1]
        vr = d.get("verifier_result") or {}
        rw = (vr.get("rewards") or {}).get("reward")
        rewards.setdefault(task, []).append(float(rw) if rw is not None else 0.0)
    return rewards


def _load_fw_summary(path):
    rewards = {}
    with open(path) as f:
        records = json.load(f)
    for rec in records:
        atts = rec.get("attempts") or []
        if not atts:
            continue
        rewards.setdefault(rec["id"], []).append(1.0 if atts[0].get("full_pass") else 0.0)
    return rewards


def load(path):
    """Return {task: bool passed}. Several trials of one task are aggregated
    by mean reward >= 0.5 (and reported by the caller)."""
    if os.path.isdir(path):
        sj = os.path.join(path, "summary.json")
        rewards = _load_harbor(path)
        if not rewards and os.path.isfile(sj):
            rewards = _load_fw_summary(sj)
    elif os.path.isfile(path):
        rewards = _load_fw_summary(path)
    else:
        raise SystemExit(f"error: {path} not found")
    if not rewards:
        raise SystemExit(f"error: no results found in {path}")
    multi = sum(1 for v in rewards.values() if len(v) > 1)
    passed = {t: (sum(v) / len(v)) >= 0.5 if len(v) > 1 else v[0] >= 1.0 for t, v in rewards.items()}
    return passed, multi


def compare(a, b):
    """Paired counts over the tasks present in both arms."""
    common = sorted(set(a) & set(b))
    both = sum(1 for t in common if a[t] and b[t])
    fix = [t for t in common if not a[t] and b[t]]
    brk = [t for t in common if a[t] and not b[t]]
    neither = sum(1 for t in common if not a[t] and not b[t])
    return {
        "n": len(common), "both": both, "fix": fix, "brk": brk, "neither": neither,
        "ka": sum(1 for t in common if a[t]), "kb": sum(1 for t in common if b[t]),
        "p": mcnemar_exact(len(brk), len(fix)),
        "only_a": sorted(set(a) - set(b)), "only_b": sorted(set(b) - set(a)),
    }


def _pct(x):
    return f"{100 * x:5.1f}%"


def report(r, na, nb, out=sys.stdout):
    n = r["n"]
    w = max(len(na), len(nb))
    print(f"paired tasks: {n}", file=out)
    for name, k in ((na, r["ka"]), (nb, r["kb"])):
        lo, hi = wilson(k, n)
        print(f"  {name:<{w}}  {k}/{n}  {_pct(k / n if n else 0)}  95% CI [{_pct(lo)}, {_pct(hi)}]", file=out)
    delta = (r["kb"] - r["ka"]) / n if n else 0.0
    print(f"  delta  {100 * delta:+.1f} pts  (+{len(r['fix'])} fixed / -{len(r['brk'])} broken, "
          f"both pass {r['both']}, both fail {r['neither']})", file=out)
    print(f"  exact McNemar p = {r['p']:.4f}", file=out)
    if r["fix"]:
        print("  fixed :", ", ".join(r["fix"]), file=out)
    if r["brk"]:
        print("  broken:", ", ".join(r["brk"]), file=out)
    if r["only_a"] or r["only_b"]:
        print(f"  note: {len(r['only_a'])} task(s) only in {na}, {len(r['only_b'])} only in {nb} (ignored)", file=out)
    d = len(r["fix"]) + len(r["brk"])
    if n < 30 or d < 6:
        print(f"  caution: {n} tasks / {d} discordant pairs is too few to call this "
              f"significant either way; treat as a signal, not a result.", file=out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("baseline")
    ap.add_argument("candidate")
    ap.add_argument("--names", nargs=2, metavar=("BASE", "CAND"))
    args = ap.parse_args(argv)
    a, ma = load(args.baseline)
    b, mb = load(args.candidate)
    if ma or mb:
        print(f"note: multiple trials per task found ({ma} / {mb}); "
              f"aggregated as mean reward >= 0.5", file=sys.stderr)
    na, nb = args.names or (os.path.basename(args.baseline.rstrip("/")) or "baseline",
                            os.path.basename(args.candidate.rstrip("/")) or "candidate")
    report(compare(a, b), na, nb)
    return 0


if __name__ == "__main__":
    sys.exit(main())
