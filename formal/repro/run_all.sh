#!/usr/bin/env bash
# Runs every stress test and writes the output to $R (default formal/results/after/).
# formal/results/*.txt hold the "before" numbers (code at 5805459); do not overwrite them.
# All scripts isolate HOME/USERPROFILE and every store path in a temp dir.
#   R=formal/results/after PY=/path/to/python.exe formal/repro/run_all.sh
set -u
cd "$(dirname "$0")/../.."
PY=${PY:-.venv/Scripts/python.exe}
R=${R:-formal/results/after}
export PYTHONPATH="$(pwd)"
mkdir -p $R
run() { name=$1; shift; echo "== $name: $*" ; $PY "$@" > $R/$name.txt 2>&1; tail -8 $R/$name.txt; }
run stress_hook_8x40      formal/repro/stress_hook.py --procs 8 --rounds 40
run stress_hook_3x40      formal/repro/stress_hook.py --procs 3 --rounds 40
for s in ledger history feedback agentfiles; do
  run stress_append_${s}_3  formal/repro/stress_append.py --store $s --procs 3 --records 200 --rounds 20
  run stress_append_${s}_8  formal/repro/stress_append.py --store $s --procs 8 --records 200 --rounds 20
done
run stress_deny_streak_8  formal/repro/stress_deny_streak.py --procs 8 --updates 100 --rounds 20
run stress_deny_streak_3  formal/repro/stress_deny_streak.py --procs 3 --updates 20 --rounds 20
run stress_snapshot_same_8     formal/repro/stress_snapshot.py --procs 8 --rounds 30 --mode same
run stress_snapshot_distinct_8 formal/repro/stress_snapshot.py --procs 8 --rounds 30 --mode distinct
run stress_snapshot_same_3     formal/repro/stress_snapshot.py --procs 3 --rounds 30 --mode same
run stress_learned_8      formal/repro/stress_learned.py --procs 8 --steps 60 --rounds 10
run stress_learned_3      formal/repro/stress_learned.py --procs 3 --steps 60 --rounds 10
run control_append_8      formal/repro/control_append.py --procs 8 --records 200 --rounds 10
run feedback_reuse        formal/repro/feedback_reuse.py
run stress_feedback_scope_8x40 formal/repro/stress_feedback_scope.py --procs 8 --decisions 40
run serve_queue_6s        formal/repro/serve_queue.py --delay 6 --burst 5
run serve_queue_6s_burst8 formal/repro/serve_queue.py --delay 6 --burst 8
run serve_queue_hang2     formal/repro/serve_queue.py --hang 2 --delay 1 --burst 6
run stress_drift_200      formal/repro/stress_drift.py --rounds 200
run f6_post_window        formal/repro/f6_post_window.py
echo ALLDONE
