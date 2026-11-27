#!/usr/bin/env python3
"""Harvest Harbor job dirs for Terminal-Bench 2.1 into results JSON + inline SVG charts.

stdlib only; run as: python3 -I harvest_tb21.py JOB_DIR [JOB_DIR ...] [--tasks FILE]
       [--dev-tasks FILE] [--partial] [--synthetic] [--trajectories-url URL] [--out DIR] [--label TEXT]

Reads every <job>/<trial>/result.json. Task names are compared without
the "terminal-bench/" namespace. Per task:
  pass     verifier reward == 1.0 (also when the trial raised, e.g. AgentTimeoutError)
  fail     verifier reward != 1.0, or no reward after an agent-side exception or timeout
  error    no reward and an infrastructure (or unknown) exception, or no exception at all
  missing  task in the list but no trial result
A trial that ended in AgentTimeoutError also carries a timeout flag.
Missing and error trials are never dropped: they stay in the denominator
(the primary rate treats them as not passed) and are listed by name.

Nothing is written and the exit code is nonzero when: a job has no trials, a trial is not in the
task list, a task has two trials, a result is unreadable, the provenance is wrong (agent, model,
dataset, dataset digest, timeout overrides), or the list is not the 89-task list and neither
--partial nor --synthetic was given.

Result fields used (harbor 0.27.0 TrialResult): task_name, trial_name, agent_info.name,
config.{task.source, agent, verifier, *timeout_multiplier}, verifier_result.rewards.reward,
exception_info.exception_type, started_at, finished_at; job config.json datasets[0].ref.

Outputs (in --out, default ./harvest-out): results.json, report.md,
  chart_rates.svg (bars + 95% Wilson whiskers), chart_grid.svg (task x harness pass/fail grid),
  chart_time.svg (whole trial time per task). Never writes into docs/ or README.
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
HERE = os.path.dirname(os.path.abspath(__file__))
TASKS_FILE = os.path.join(HERE, "tb21-tasks.txt")
DEV_FILE = os.path.join(HERE, "tb21-dev-tasks.txt")
DATASET = "terminal-bench/terminal-bench-2-1"
MODEL = "local/qwen-pi4"
# harness -> (where the trial config names the model, expected value); matches run-tb21.sh
HARNESS_MODEL = {
    "flywheel": (("kwargs", "fw_model"), MODEL),
    "terminus-2": (("model_name",), "openai/" + MODEL),
    "opencode": (("model_name",), "local/" + MODEL),
}
# Exceptions raised by the agent's own run: without a reward they are a fail, not an infra error.
AGENT_EXCEPTIONS = {
    "AgentTimeoutError", "NonZeroAgentExitCodeError", "ContextWindowExceededError",
    "ContextLengthExceededError", "OutputTokenExceededError", "OutputLengthExceededError",
    "AgentSafetyRefusalError", "ContentPolicyViolationError",
}


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


def bare(name):
    return name.rsplit("/", 1)[-1]


def load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
    except (OSError, ValueError):
        return None
    return d if isinstance(d, dict) else None


def provenance(harness, d):
    """Return the reasons why trial result d does not belong to a scored run of this harness."""
    cfg = d.get("config") or {}
    agent = cfg.get("agent") or {}
    bad = []
    name = (d.get("agent_info") or {}).get("name")
    if name != harness:
        bad.append(f"agent is {name!r}, expected {harness!r}")
    keys, want = HARNESS_MODEL[harness]
    got = agent
    for k in keys:
        got = (got or {}).get(k)
    if got != want:
        bad.append(f"model is {got!r}, expected {want!r}")
    source = (cfg.get("task") or {}).get("source")
    if source != DATASET or not str(d.get("task_name", "")).startswith("terminal-bench/"):
        bad.append(f"dataset is {source!r}, expected {DATASET!r}")
    if cfg.get("timeout_multiplier") != 1.0:
        bad.append(f"timeout multiplier is {cfg.get('timeout_multiplier')!r}, expected 1.0")
    over = [k for k, v in cfg.items() if k.endswith("_timeout_multiplier") and v not in (None, 1.0)]
    for part in ("agent", "verifier"):
        over += [f"{part}.{k}" for k, v in (cfg.get(part) or {}).items()
                 if k in ("override_timeout_sec", "max_timeout_sec") and v is not None]
    if over:
        bad.append("timeout overrides set: " + ", ".join(over))
    return bad


def classify(d):
    rec = {"status": None, "reward": None, "reason": None, "seconds": None,
           "timeout": False, "trial": d.get("trial_name")}
    exc = (d.get("exception_info") or {}).get("exception_type")
    vr = d.get("verifier_result") or {}
    rw = (vr.get("rewards") or {}).get("reward")
    rec["reason"] = exc
    rec["timeout"] = exc == "AgentTimeoutError"
    if rw is not None:
        rec["reward"] = float(rw)
        rec["status"] = "pass" if float(rw) == 1.0 else "fail"
    elif exc in AGENT_EXCEPTIONS:
        rec["status"] = "fail"
    else:
        rec["status"] = "error"
        rec["reason"] = exc or "no verifier reward"
    s, e = parse_iso(d.get("started_at")), parse_iso(d.get("finished_at"))
    if s and e:
        rec["seconds"] = round((e - s).total_seconds(), 1)
    return rec


def read_job(job_dir, harness, digest, expected):
    """Return ({task: record}, [problems]) for one job dir."""
    trials, problems, found = {}, [], 0
    for path in sorted(glob.glob(os.path.join(job_dir, "*", "result.json"))):
        d = load_json(path)
        if d is None:
            problems.append(f"unreadable result: {path}")
            continue
        found += 1
        task = bare(d.get("task_name") or "?")
        if task not in expected:
            problems.append(f"unexpected trial: {task} ({path})")
            continue
        if task in trials:
            problems.append(f"duplicate trial for {task}: {path}")
            continue
        problems += [f"{task}: {why}" for why in provenance(harness, d)]
        job = load_json(os.path.join(os.path.dirname(os.path.dirname(path)), "config.json")) or {}
        ref = (job.get("datasets") or [{}])[0].get("ref")
        if ref != digest:
            problems.append(f"{task}: job dataset digest is {ref!r}, expected {digest!r}")
        trials[task] = classify(d)
    if not found:
        problems.append(f"no trials in {job_dir}")
    return trials, problems


def harness_name(job_dir):
    """'tb21-flywheel[-suffix]' -> 'flywheel'; None when the dir names no known harness."""
    base = os.path.basename(os.path.normpath(job_dir))
    base = base[5:] if base.startswith("tb21-") else base
    return next((h for h in HARNESS_MODEL if base == h or base.startswith(h + "-")), None)


def load_reruns(job_dir):
    path = os.path.join(job_dir, "reruns.jsonl")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return [json.loads(ln) for ln in fh if ln.strip()]


def load_names(path):
    with open(path, encoding="utf-8") as fh:
        return [bare(ln.strip()) for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]


def load_digest(path):
    with open(path, encoding="utf-8") as fh:
        return next((ln.split(":", 1)[1].strip() for ln in fh if ln.startswith("# dataset-digest:")), None)


def summarise(name, trials, expected):
    """trials: {task: record}; expected: the task names that form the denominator."""
    rows = {}
    counts = {"pass": 0, "fail": 0, "error": 0, "missing": 0}
    for t in expected:
        rec = trials.get(t)
        if rec is None:
            st = {"status": "missing", "reward": None, "reason": "no trial result", "seconds": None,
                  "timeout": False}
        else:
            st = rec
        rows[t] = st
        counts[st["status"]] += 1
    n = len(expected)
    k = counts["pass"]
    lo, hi = wilson(k, n)
    scored = counts["pass"] + counts["fail"]
    slo, shi = wilson(k, scored)
    times = [r["seconds"] for r in rows.values() if r.get("seconds") is not None]
    return {
        "harness": name,
        "n_tasks": n,
        "counts": counts,
        "timeouts": sum(r["timeout"] for r in rows.values()),
        "pass_rate": k / n if n else 0.0,
        "wilson95": [lo, hi],
        "scored_n": scored,
        "scored_pass_rate": (k / scored) if scored else None,
        "scored_wilson95": [slo, shi],
        "median_seconds": sorted(times)[len(times) // 2] if times else None,
        "tasks": rows,
    }


def stamp_svg(body, stamps, x, y, anchor):
    if not stamps:
        return body
    text = (f'<text x="{x}" y="{y}" text-anchor="{anchor}" font-size="14" font-weight="bold" '
            f'fill="#c62828">{" ".join(stamps)}</text>')
    return body.replace("</svg>", text + "\n</svg>")


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
           f'<text x="{pad_l}" y="18" font-size="14">Time per task: whole trial (s), one dot per task</text>']
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


def rate(p, interval, n=None):
    s = f"{p*100:.1f}% [{interval[0]*100:.1f}, {interval[1]*100:.1f}]"
    return s if n is None else f"{s} (n={n})"


def report_md(summaries, label, stamps, url):
    lines = [f"# {' '.join(stamps + [''])}Terminal-Bench 2.1 harvest: {label}", ""]
    if "SYNTHETIC" in stamps:
        lines.append("SYNTHETIC test data. Not a benchmark result.")
    elif url:
        lines.append(f"Self-run on the official dataset and harness, trajectories public: {url} "
                     "Not a leaderboard entry.")
    else:
        lines.append("Self-run on the official dataset and harness. Not a leaderboard entry.")
    if "PARTIAL" in stamps:
        lines.append("PARTIAL: tasks are missing. Do not publish as a result.")
    lines += ["Primary rate counts missing and error trials as not passed. Scored rate excludes them.",
              "Timeouts are agent time-limit hits; each is also counted as pass or fail.", "",
              "| harness | set | tasks | pass | fail | error | missing | timeouts | pass rate (95% Wilson) "
              "| scored pass rate (95% Wilson) |",
              "|---|---|---|---|---|---|---|---|---|---|"]
    for s in summaries:
        for name, r in s["sets"].items():
            c = r["counts"]
            sr = rate(r["scored_pass_rate"], r["scored_wilson95"], r["scored_n"]) \
                if r["scored_pass_rate"] is not None else "n/a"
            lines.append(f'| {s["harness"]} | {name} | {r["n_tasks"]} | {c["pass"]} | {c["fail"]} | '
                         f'{c["error"]} | {c["missing"]} | {r["timeouts"]} | '
                         f'{rate(r["pass_rate"], r["wilson95"])} | {sr} |')
    lines.append("")
    for s in summaries:
        bad = [(t, r) for t, r in s["tasks"].items() if r["status"] in ("error", "missing")]
        if bad:
            lines.append(f"## {s['harness']}: not scored")
            for t, r in bad:
                lines.append(f"- {t}: {r['status']} ({r.get('reason') or '-'})")
            lines.append("")
    lines.append("## Rerun log")
    log = [(s["harness"], e) for s in summaries for e in s["reruns"]]
    for h, e in log:
        lines.append(f"- {h} {e.get('task')}: {e.get('kind')} at {e.get('time')} "
                     f"(reward {e.get('reward')}, exception {e.get('exception') or '-'}, "
                     f"old trial {e.get('trial')})")
    if not log:
        lines.append("- no entries")
    lines.append("")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("job_dirs", nargs="+")
    ap.add_argument("--tasks", default=TASKS_FILE, help="expected task list (one name per line)")
    ap.add_argument("--dev-tasks", default=DEV_FILE, help="development tasks, reported separately")
    ap.add_argument("--partial", action="store_true", help="allow a task list other than the 89")
    ap.add_argument("--synthetic", action="store_true", help="test data: stamp every output")
    ap.add_argument("--trajectories-url", help="where the trajectories are published")
    ap.add_argument("--out", default="harvest-out")
    ap.add_argument("--label", default="run")
    a = ap.parse_args()

    expected = load_names(a.tasks)
    dev = load_names(a.dev_tasks)
    full = load_names(TASKS_FILE)
    digest = load_digest(TASKS_FILE)
    problems = []
    if len(set(expected)) != len(expected) or len(set(dev)) != len(dev) or not expected:
        problems.append("empty task list or repeated names in a task list")
    dev_in = [t for t in expected if t in set(dev)]
    held = [t for t in expected if t not in set(dev)]
    if not (a.partial or a.synthetic):
        if sorted(expected) != sorted(full) or len(full) != 89:
            problems.append(f"task list is not the 89-task list ({len(expected)} names); "
                            "use --partial for a subset")
        elif (len(dev), len(dev_in), len(held)) != (10, 10, 79):
            problems.append(f"expected 10 dev and 79 held-out tasks, got {len(dev_in)} and {len(held)}")

    summaries = []
    for jd in a.job_dirs:
        harness = harness_name(jd)
        if not os.path.isdir(jd) or harness is None:
            print(f"not a job directory of a known harness: {jd}", file=sys.stderr)
            return 2
        if any(s["harness"] == harness for s in summaries):
            problems.append(f"two job dirs for {harness}")
        trials, bad = read_job(jd, harness, digest, set(expected))
        problems += [f"{harness}: {p}" for p in bad]
        s = summarise(harness, trials, expected)
        s["sets"] = {}
        for kind, names in (("all", expected), ("held-out", held), ("dev", dev_in)):
            r = summarise(harness, trials, names)
            del r["harness"], r["tasks"]
            s["sets"][f"{kind}-{len(names)}"] = r
        s["reruns"] = load_reruns(jd)
        summaries.append(s)
    if problems:
        for p in problems:
            print(f"ERROR: {p}", file=sys.stderr)
        return 1

    stamps = ["SYNTHETIC"] if a.synthetic else []
    if len(expected) < len(full) and not a.synthetic or any(s["counts"]["missing"] for s in summaries):
        stamps.append("PARTIAL")
    report = report_md(summaries, a.label, stamps, a.trajectories_url)
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "results.json"), "w", encoding="utf-8") as fh:
        json.dump({"label": a.label, "stamps": stamps, "dataset_digest": digest,
                   "trajectories_url": a.trajectories_url, "summaries": summaries}, fh, indent=2)
    with open(os.path.join(a.out, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(report)
    for fname, body in (("chart_rates.svg", stamp_svg(svg_bars(summaries), stamps, 556, 18, "end")),
                        ("chart_grid.svg", stamp_svg(svg_grid(summaries), stamps, 4, 16, "start")),
                        ("chart_time.svg", stamp_svg(svg_time(summaries), stamps, 616, 18, "end"))):
        with open(os.path.join(a.out, fname), "w", encoding="utf-8") as fh:
            fh.write(body)
    print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
