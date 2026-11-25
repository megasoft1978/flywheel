#!/bin/bash
# harvest slice results — safe to run any time, prints partial state too
cd "$(dirname "$0")"
JOB=$(ls -td jobs/slice-*/ 2>/dev/null | head -1)
[ -z "$JOB" ] && echo "no slice job found" && exit 1
echo "job: $JOB"
python3 - "$JOB" <<'PYE'
import json, sys, os, glob
jobdir = sys.argv[1]
rows = []
for rj in sorted(glob.glob(os.path.join(jobdir, "*", "*__*", "result.json"))) or glob.glob(os.path.join(jobdir, "*__*", "result.json")):
    try:
        d = json.load(open(rj))
        if "task_name" not in d:
            continue
        task = d.get("task_name", "?")
        vr = d.get("verifier_result") or {}
        rw = (vr.get("rewards") or {}).get("reward", 0)
        rows.append((task, rw))
    except Exception:
        pass
done = len(rows)
passed = sum(1 for _, r in rows if r == 1.0)
running = "yes (in progress)" if os.path.exists(jobdir + ".log") or glob.glob(jobdir + "*") else "unknown"
print(f"completed: {done}/10 tasks, passed: {passed}")
for t, r in rows:
    print(f"  {'PASS' if r == 1.0 else 'fail'} {t}: {r}")
if done:
    print(f"slice accuracy so far: {passed}/{done} = {passed*100.0/done:.0f}%")
print("\nfor reference: Qwen3-Coder-480B best=27.2%, Claude Haiku 4.5 best=35.5%, Claude Sonnet 4.5 in Claude Code=40.1%")
PYE
