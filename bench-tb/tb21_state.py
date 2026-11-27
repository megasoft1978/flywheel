#!/usr/bin/env python3
"""Job-dir bookkeeping for run-tb21.sh. stdlib only; run as: python3 -I tb21_state.py ...

Harbor 0.27.0 on resume (job.py _maybe_init_existing_job): raises FileExistsError when the job
config differs, deletes (rmtree) every trial dir without a result.json, skips unreadable ones and
keeps every parsed result, including cancelled ones. So before each run this script
  - checks the existing config.json has the same dataset ref and task list,
  - moves (never deletes) partial and cancelled trial dirs to <archive-dir>,
  - moves finished trials named with --rerun there too,
and logs every move in <job-dir>/reruns.jsonl.

--rerun needs --reason, and follows one rule for every harness: never a trial with reward 1
(unless it is an error, i.e. its reward is invalid);
a fail only with recorded outage evidence (it overlaps a window in <job-dir>/outages.jsonl)
unless --rerun-without-evidence; an error trial (harvest_tb21.classify) may be re-run.
For flywheel and opencode, a model API error without that outage evidence is a fail, not an error.

Prints "DONE_COUNT TODO_COUNT" on stdout; messages go to stderr.

Two more modes, for the model server (URL is the OpenAI base URL, probed at URL/models):
  tb21_state.py health URL                  exit 1 if it does not answer
  tb21_state.py watch URL JOB_DIR -- CMD    run CMD; on an outage record it in outages.jsonl,
                                            stop CMD (SIGTERM) and exit 75
"""

import argparse
import datetime
import json
import os
import signal
import subprocess
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # -I leaves it out
from harvest_tb21 import classify, load_outages, outage_overlap  # noqa: E402

OUTAGE_EXIT = 75


def bare(name):
    return name.rsplit("/", 1)[-1]


def read_result(trial_dir):
    try:
        with open(os.path.join(trial_dir, "result.json"), encoding="utf-8") as fh:
            d = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(d, dict) or not d.get("task_name") or not d.get("finished_at"):
        return None
    return d


def scan(job_dir):
    """Return [(trial_dir_name, result or None)] for every subdir of a job dir."""
    if not os.path.isdir(job_dir):
        return []
    return [(n, read_result(os.path.join(job_dir, n)))
            for n in sorted(os.listdir(job_dir)) if os.path.isdir(os.path.join(job_dir, n))]


def check_config(job_dir, dataset, digest, tasks):
    path = os.path.join(job_dir, "config.json")
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as fh:
        datasets = json.load(fh).get("datasets") or [{}]
    ds = datasets[0]
    if ds.get("name") != dataset or ds.get("ref") != digest or ds.get("task_names") != tasks:
        sys.exit(f"{job_dir} was created with a different dataset, ref or task list; "
                 "Harbor cannot resume it. Use another --job-name.")


def archive(job_dir, archive_dir, name, entry, dry):
    dest = os.path.join(archive_dir, name)
    i = 1
    while os.path.exists(dest):
        i += 1
        dest = os.path.join(archive_dir, f"{name}.{i}")
    verb = "would archive" if dry else "archived"
    print(f"{verb} ({entry['kind']}): {name} -> {dest}", file=sys.stderr)
    if dry:
        return
    os.makedirs(archive_dir, exist_ok=True)
    os.rename(os.path.join(job_dir, name), dest)
    entry.update(time=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                 trial=name, archived_to=dest)
    with open(os.path.join(job_dir, "reruns.jsonl"), "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def healthy(url, timeout):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url.rstrip("/") + "/models", timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


def record_outage(job_dir, url, start):
    os.makedirs(job_dir, exist_ok=True)
    entry = {"start": start.isoformat(), "end": now().isoformat(), "url": url}
    with open(os.path.join(job_dir, "outages.jsonl"), "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")


def watch(url, job_dir, cmd):
    interval = float(os.environ.get("TB_HEALTH_INTERVAL", "15"))
    timeout = float(os.environ.get("TB_HEALTH_TIMEOUT", "10"))
    limit = int(os.environ.get("TB_HEALTH_FAILS", "3"))     # consecutive failed probes
    last_ok = now()                                         # outage windows start at a good probe
    proc = subprocess.Popen(cmd)
    signal.signal(signal.SIGINT, lambda *_: None)           # CMD gets Ctrl-C itself; wait for it
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda *_: proc.send_signal(signal.SIGTERM))
    fails = 0
    while True:
        try:
            rc = proc.wait(timeout=interval)
            break
        except subprocess.TimeoutExpired:
            pass
        probed = now()
        if healthy(url, timeout):
            fails, last_ok = 0, probed
            continue
        fails += 1
        if fails >= limit:
            print(f"model server outage: {url} failed {fails} probes; stopping the run", file=sys.stderr)
            record_outage(job_dir, url, last_ok)
            proc.send_signal(signal.SIGTERM)
            proc.wait()                                     # let Harbor record the cancellation
            record_outage(job_dir, url, last_ok)            # extend the window over the shutdown
            return OUTAGE_EXIT
    if not healthy(url, timeout):
        print(f"model server outage: {url} is down at the end of the run", file=sys.stderr)
        record_outage(job_dir, url, last_ok)                # trials finished since the last good probe
        return OUTAGE_EXIT
    return rc if rc >= 0 else 128 - rc


def judge_rerun(job_dir, res, override, trial_dir=None):
    """Return (status, evidence, refusal) for re-running a finished trial."""
    rec = classify(res, trial_dir, job_dir)
    reward = ((res.get("verifier_result") or {}).get("rewards") or {}).get("reward")
    if reward is not None and float(reward) == 1.0 and rec["status"] != "error":
        return rec["status"], None, "it has reward 1"
    evidence = outage_overlap(job_dir, res)
    if rec["status"] == "error":
        evidence = evidence or f"no valid reward: {rec['reason']}"
    if not evidence and not override:
        bad = load_outages(job_dir)[1]
        return rec["status"], None, (f"it is a scored fail (reward {reward}) with no recorded outage "
                                     "evidence; --rerun-without-evidence overrides and is reported"
                                     + (f" ({bad})" if bad else ""))
    return rec["status"], evidence, None


def main():
    if sys.argv[1:2] == ["health"] and len(sys.argv) == 3:
        if not healthy(sys.argv[2], float(os.environ.get("TB_HEALTH_TIMEOUT", "10"))):
            sys.exit(f"model server does not answer at {sys.argv[2]}/models")
        return
    if sys.argv[1:2] == ["watch"] and len(sys.argv) > 5 and sys.argv[4] == "--":
        sys.exit(watch(sys.argv[2], sys.argv[3], sys.argv[5:]))
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-dir", required=True)
    ap.add_argument("--archive-dir", required=True)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--digest", required=True)
    ap.add_argument("--rerun", action="append", default=[])
    ap.add_argument("--reason", help="why the --rerun trials are re-run")
    ap.add_argument("--rerun-without-evidence", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("tasks", nargs="+", help="the full namespaced task list of the job")
    a = ap.parse_args()
    if a.rerun and not (a.reason or "").strip():
        ap.error("--rerun requires --reason")

    check_config(a.job_dir, a.dataset, a.digest, a.tasks)
    wanted = {bare(t) for t in a.tasks}
    rerun = {bare(t) for t in a.rerun}
    trials = scan(a.job_dir)

    finished = {}
    moves = []
    refused = []
    for name, res in trials:
        exc = ((res or {}).get("exception_info") or {}).get("exception_type")
        if res is None:
            # no usable result.json: the task name is only known from the (truncated) dir name
            moves.append((name, {"kind": "partial", "task": name.rsplit("__", 1)[0]}))
            continue
        task = bare(res["task_name"])
        reward = ((res.get("verifier_result") or {}).get("rewards") or {}).get("reward")
        entry = {"task": task, "reward": reward, "exception": exc}
        if exc == "CancelledError" and reward is None:
            moves.append((name, dict(entry, kind="cancelled")))
        elif task in rerun:
            status, evidence, refusal = judge_rerun(a.job_dir, res, a.rerun_without_evidence,
                                                    os.path.join(a.job_dir, name))
            if refusal:
                refused.append(f"--rerun {task} refused: {refusal}")
            moves.append((name, dict(entry, kind="rerun", status=status, reason=a.reason.strip(),
                                     evidence=evidence)))
        else:
            finished[task] = name

    # validate every --rerun before moving anything
    moved = {e["task"] for _, e in moves if e["kind"] == "rerun"}
    if rerun - moved:
        sys.exit("--rerun: no finished trial in " + a.job_dir + " for " + ", ".join(sorted(rerun - moved)))

    if refused:
        sys.exit("\n".join(refused))

    for name, entry in moves:
        archive(a.job_dir, a.archive_dir, name, entry, a.dry_run)

    done = len(wanted & set(finished))
    print(done, len(wanted) - done)


if __name__ == "__main__":
    main()
