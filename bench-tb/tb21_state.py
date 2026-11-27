#!/usr/bin/env python3
"""Job-dir bookkeeping for run-tb21.sh. stdlib only; run as: python3 -I tb21_state.py ...

Harbor 0.27.0 on resume (job.py _maybe_init_existing_job): raises FileExistsError when the job
config differs, deletes (rmtree) every trial dir without a result.json, skips unreadable ones and
keeps every parsed result, including cancelled ones. So before each run this script
  - checks the existing config.json has the same dataset ref and task list,
  - moves (never deletes) partial and cancelled trial dirs to <archive-dir>,
  - moves finished trials named with --rerun there too,
and logs every move in <job-dir>/reruns.jsonl.

Prints "DONE_COUNT TODO_COUNT" on stdout; messages go to stderr.
"""

import argparse
import datetime
import json
import os
import sys


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-dir", required=True)
    ap.add_argument("--archive-dir", required=True)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--digest", required=True)
    ap.add_argument("--rerun", action="append", default=[])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("tasks", nargs="+", help="the full namespaced task list of the job")
    a = ap.parse_args()

    check_config(a.job_dir, a.dataset, a.digest, a.tasks)
    wanted = {bare(t) for t in a.tasks}
    rerun = {bare(t) for t in a.rerun}
    trials = scan(a.job_dir)

    finished = {}
    moves = []
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
            moves.append((name, dict(entry, kind="rerun")))
        else:
            finished[task] = name

    # validate every --rerun before moving anything
    moved = {e["task"] for _, e in moves if e["kind"] == "rerun"}
    if rerun - moved:
        sys.exit("--rerun: no finished trial in " + a.job_dir + " for " + ", ".join(sorted(rerun - moved)))

    for name, entry in moves:
        archive(a.job_dir, a.archive_dir, name, entry, a.dry_run)

    done = len(wanted & set(finished))
    print(done, len(wanted) - done)


if __name__ == "__main__":
    main()
