#!/bin/bash
# A/B the failure-spiral rescue on the TB2.0 slice: same binary, same tasks,
# only --spiral differs (A = 0 / off, B = 3 / default). Sequential because the
# engine is single-slot. Then prints the paired comparison.
#   REPEATS=3 bench-tb/run-ab.sh        # 3 attempts per task per arm
#   ARM_B=2 bench-tb/run-ab.sh          # try a different trigger threshold
# Rebuild dist/flywheel-linux-* first (build-zig.sh) so BOTH arms run the new code.
set -e
cd "$(dirname "$0")"
export REPEATS="${REPEATS:-1}"
A="${ARM_A:-0}"; B="${ARM_B:-3}"
newest() { ls -dt jobs/slice-spiral$1-* 2>/dev/null | grep -v '\.log$' | head -1; }
SPIRAL=$A ./run-slice.sh
JA=$(newest $A)
SPIRAL=$B ./run-slice.sh
JB=$(newest $B)
echo; echo "=== A (spiral=$A) vs B (spiral=$B) ==="
python3 paired_stats.py "$JA" "$JB" --names "spiral=$A" "spiral=$B"
echo; echo "rescues fired in B (fw_out.log summary lines):"
grep -rho "rescues=[0-9]*" "$JB" 2>/dev/null | sort | uniq -c || true
