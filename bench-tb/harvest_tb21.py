#!/usr/bin/env python3
"""Harvest Harbor job dirs for Terminal-Bench 2.1 into results JSON + inline SVG charts.

stdlib only; run as: python3 -I harvest_tb21.py JOB_DIR [JOB_DIR ...] [--tasks FILE]
                                              [--out DIR] [--label TEXT]

Reads every <job>/<trial>/result.json that has a task_name. Per task:
  pass     verifier reward == 1.0
  fail     verifier ran, reward != 1.0
  error    trial raised an exception (exception_info set) or no verifier result
  missing  task in --tasks list but no trial result at all
Missing and error trials are never dropped: they stay in the denominator
(the primary rate treats them as not passed) and are listed by name.

Assumed Harbor result.json fields (checked against harbor 0.27.0 output at smoke time):
  task_name, trial_name, verifier_result.rewards.reward, exception_info,
  started_at, finished_at (ISO-8601). Unknown shapes become "error" with the reason.

Outputs (in --out, default ./harvest-out): results.json, report.md,
  chart_rates.svg (bars + 95% Wilson whiskers), chart_grid.svg (task x harness pass/fail grid),
  chart_time.svg (per-task wall-time strip). Never writes into docs/ or README.
"""

import argparse
import datetime
import glob
import html
import json
import math
import os
import sys

Z95 = 1.959963984540054


def wilson(k, n):
    """95% Wilson score interval for k successes out of n. Returns (lo, hi) in 0..1."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    z2 = Z95 * Z95
    denom = 1 + z2 / n
    centre = (p + z2 / (2 * n)) / denom
    half = Z95 * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def parse_iso(s):
    if not s:
        return None
    try:
        return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def read_trials(job_dir):
    """Yield (task_name, record) for each trial result.json under a job dir."""
    for path in glob.glob(os.path.join(job_dir, "**", "result.json"), recursive=True):
        try:
            with open(path, encoding="utf-8") as fh:
                d = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            yield (os.path.basename(os.path.dirname(path)), {"status": "error", "reason": f"unreadable: {exc}"})
            continue
        if not isinstance(d, dict) or "task_name" not in d:
            continue
        task = d.get("task_name") or "?"
        rec = {"status": None, "reward": None, "reason": None, "seconds": None, "trial": d.get("trial_name")}
        if d.get("exception_info"):
            rec["status"] = "error"
            rec["reason"] = str(d["exception_info"].get("exception_type", "exception"))
        else:
            vr = d.get("verifier_result") or {}
            rw = (vr.get("rewards") or {}).get("reward") if isinstance(vr, dict) else None
            if rw is None:
                rec["status"] = "error"
                rec["reason"] = "no verifier reward"
            else:
                rec["reward"] = float(rw)
                rec["status"] = "pass" if float(rw) == 1.0 else "fail"
        s, e = parse_iso(d.get("started_at")), parse_iso(d.get("finished_at"))
        if s and e:
            rec["seconds"] = round((e - s).total_seconds(), 1)
        yield task, rec


def harness_name(job_dir):
    """Harness = job dir basename; strip a leading 'tb21-' so 'tb21-flywheel' -> 'flywheel'."""
    base = os.path.basename(os.path.normpath(job_dir))
    return base[5:] if base.startswith("tb21-") else base


def load_expected(path):
    if not path:
        return None
    with open(path, encoding="utf-8") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]


def summarise(name, trials, expected):
    """trials: {task: record} (last record wins if duplicated and counted as duplicates)."""
    tasks = expected if expected is not None else sorted(trials)
    rows = {}
    counts = {"pass": 0, "fail": 0, "error": 0, "missing": 0}
    for t in tasks:
        rec = trials.get(t)
        if rec is None:
            st = {"status": "missing", "reward": None, "reason": "no trial result", "seconds": None}
        else:
            st = rec
        rows[t] = st
        counts[st["status"]] += 1
    n = len(tasks)
    k = counts["pass"]
    lo, hi = wilson(k, n)
    scored = counts["pass"] + counts["fail"]
    slo, shi = wilson(k, scored)
    times = [r["seconds"] for r in rows.values() if r.get("seconds") is not None]
    return {
        "harness": name,
        "n_tasks": n,
        "expected_list": expected is not None,
        "counts": counts,
        "pass_rate": k / n if n else 0.0,
        "wilson95": [lo, hi],
        "scored_n": scored,
        "scored_pass_rate": (k / scored) if scored else None,
        "scored_wilson95": [slo, shi],
        "median_seconds": sorted(times)[len(times) // 2] if times else None,
        "tasks": rows,
    }


def svg_bars(summaries):
    W, H, pad_l, pad_b, pad_t = 560, 300, 60, 50, 30
    plot_h = H - pad_t - pad_b
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
           'font-family="sans-serif" font-size="12">',
           f'<text x="{pad_l}" y="18" font-size="14">Pass rate, 95% Wilson interval</text>']
    n = max(len(summaries), 1)
    slot = (W - pad_l - 20) / n
    for i in range(0, 11, 2):
        y = pad_t + plot_h - plot_h * i / 10
        out.append(f'<line x1="{pad_l}" x2="{W-20}" y1="{y:.1f}" y2="{y:.1f}" stroke="#ddd"/>')
        out.append(f'<text x="{pad_l-6}" y="{y+4:.1f}" text-anchor="end">{i*10}%</text>')
    for j, s in enumerate(summaries):
        cx = pad_l + slot * (j + 0.5)
        bw = slot * 0.5
        p = s["pass_rate"]
        lo, hi = s["wilson95"]
        top = pad_t + plot_h * (1 - p)
        out.append(f'<rect x="{cx-bw/2:.1f}" y="{top:.1f}" width="{bw:.1f}" '
                   f'height="{pad_t+plot_h-top:.1f}" fill="#4a7bb7"/>')
        ylo = pad_t + plot_h * (1 - lo)
        yhi = pad_t + plot_h * (1 - hi)
        out.append(f'<line x1="{cx:.1f}" x2="{cx:.1f}" y1="{yhi:.1f}" y2="{ylo:.1f}" stroke="#222"/>')
        for yy in (yhi, ylo):
            out.append(f'<line x1="{cx-6:.1f}" x2="{cx+6:.1f}" y1="{yy:.1f}" y2="{yy:.1f}" stroke="#222"/>')
        label = html.escape(f'{s["harness"]} {p*100:.1f}% [{lo*100:.1f}, {hi*100:.1f}] n={s["n_tasks"]}')
        out.append(f'<text x="{cx:.1f}" y="{pad_t+plot_h+16}" text-anchor="middle">{html.escape(s["harness"])}</text>')
        out.append(f'<text x="{cx:.1f}" y="{pad_t+plot_h+32}" text-anchor="middle" font-size="10">'
                   f'{p*100:.1f}% [{lo*100:.1f}, {hi*100:.1f}]</text><title>{label}</title>')
    out.append("</svg>")
    return "\n".join(out)


def svg_grid(summaries):
    tasks = sorted({t for s in summaries for t in s["tasks"]})
    cell, lab_w, top = 14, 260, 110
    W = lab_w + cell * len(summaries) + 20
    H = top + cell * len(tasks) + 20
    colour = {"pass": "#2e7d32", "fail": "#c62828", "error": "#f9a825", "missing": "#eeeeee"}
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
           'font-family="sans-serif" font-size="11">']
    for j, s in enumerate(summaries):
        x = lab_w + cell * j + cell / 2
        out.append(f'<text transform="translate({x:.1f},{top-6}) rotate(-60)">{html.escape(s["harness"])}</text>')
    for i, t in enumerate(tasks):
        y = top + cell * i
        out.append(f'<text x="{lab_w-6}" y="{y+cell-3}" text-anchor="end">{html.escape(t)}</text>')
        for j, s in enumerate(summaries):
            st = s["tasks"].get(t, {"status": "missing"})["status"]
            out.append(f'<rect x="{lab_w+cell*j}" y="{y}" width="{cell-1}" height="{cell-1}" '
                       f'fill="{colour[st]}"><title>{html.escape(t)} / {html.escape(s["harness"])}: {st}</title></rect>')
    out.append("</svg>")
    return "\n".join(out)


def svg_time(summaries):
    rows = [(s["harness"], t, r["seconds"]) for s in summaries for t, r in s["tasks"].items()
            if r.get("seconds") is not None]
    W, pad_l, row_h, top = 620, 130, 16, 30
    mx = max([r[2] for r in rows], default=1.0)
    H = top + row_h * max(len(summaries), 1) + 40
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
           'font-family="sans-serif" font-size="11">',
           f'<text x="{pad_l}" y="18" font-size="14">Wall time per task (s), one dot per task</text>']
    for j, s in enumerate(summaries):
        y = top + row_h * j + row_h / 2
        out.append(f'<text x="{pad_l-6}" y="{y+4:.1f}" text-anchor="end">{html.escape(s["harness"])}</text>')
        out.append(f'<line x1="{pad_l}" x2="{W-20}" y1="{y:.1f}" y2="{y:.1f}" stroke="#eee"/>')
        for t, r in s["tasks"].items():
            if r.get("seconds") is None:
                continue
            x = pad_l + (W - pad_l - 20) * r["seconds"] / mx
            out.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="#4a7bb7" fill-opacity="0.7">'
                       f'<title>{html.escape(t)}: {r["seconds"]} s</title></circle>')
    out.append(f'<text x="{W-20}" y="{H-8}" text-anchor="end">max {mx:.0f} s</text>')
    out.append("</svg>")
    return "\n".join(out)


def report_md(summaries, label):
    lines = [f"# Terminal-Bench 2.1 harvest: {label}", "",
             "Self-run on the official dataset and harness, trajectories public. Not a leaderboard entry.",
             "Primary rate counts missing and error trials as not passed. Scored rate excludes them.", "",
             "| harness | tasks | pass | fail | error | missing | pass rate (95% Wilson) | scored pass rate (95% Wilson) |",
             "|---|---|---|---|---|---|---|---|"]
    for s in summaries:
        c = s["counts"]
        sr = f'{s["scored_pass_rate"]*100:.1f}% [{s["scored_wilson95"][0]*100:.1f}, {s["scored_wilson95"][1]*100:.1f}] (n={s["scored_n"]})' \
            if s["scored_pass_rate"] is not None else "n/a"
        lines.append(f'| {s["harness"]} | {s["n_tasks"]} | {c["pass"]} | {c["fail"]} | {c["error"]} | '
                     f'{c["missing"]} | {s["pass_rate"]*100:.1f}% [{s["wilson95"][0]*100:.1f}, {s["wilson95"][1]*100:.1f}] | {sr} |')
    lines.append("")
    for s in summaries:
        bad = [(t, r) for t, r in s["tasks"].items() if r["status"] in ("error", "missing")]
        if bad:
            lines.append(f"## {s['harness']}: not scored")
            for t, r in bad:
                lines.append(f"- {t}: {r['status']} ({r.get('reason') or '-'})")
            lines.append("")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("job_dirs", nargs="+")
    ap.add_argument("--tasks", help="file with the expected task names (one per line)")
    ap.add_argument("--out", default="harvest-out")
    ap.add_argument("--label", default="run")
    a = ap.parse_args()
    expected = load_expected(a.tasks)
    summaries = []
    for jd in a.job_dirs:
        if not os.path.isdir(jd):
            print(f"not a directory: {jd}", file=sys.stderr)
            return 2
        trials = {}
        dup = 0
        for task, rec in read_trials(jd):
            if task in trials:
                dup += 1
            trials[task] = rec
        s = summarise(harness_name(jd), trials, expected)
        s["duplicate_trials_ignored"] = dup
        summaries.append(s)
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "results.json"), "w", encoding="utf-8") as fh:
        json.dump({"label": a.label, "summaries": summaries}, fh, indent=2)
    with open(os.path.join(a.out, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(report_md(summaries, a.label))
    for fname, body in (("chart_rates.svg", svg_bars(summaries)),
                        ("chart_grid.svg", svg_grid(summaries)),
                        ("chart_time.svg", svg_time(summaries))):
        with open(os.path.join(a.out, fname), "w", encoding="utf-8") as fh:
            fh.write(body)
    print(report_md(summaries, a.label))
    return 0


if __name__ == "__main__":
    sys.exit(main())
