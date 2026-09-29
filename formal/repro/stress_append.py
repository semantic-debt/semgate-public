"""Stress test: N real processes append to the same JSONL store at once,
through the real semgate APIs. Each process builds its own store object (its
own threading.Lock), exactly like N parallel hook processes do.

Stores and the real method each child calls. Every one of them now appends
through semgate/filelock.py append_record (cross-process lock:
msvcrt.locking on Windows, fcntl.flock on POSIX; bounded wait
SEMGATE_LOCK_TIMEOUT_S, default 5 s):
  ledger    Ledger.record_host_response   (semgate/ledger.py Ledger._append)
  history   ToolHistory.record_pending     (semgate/history.py ToolHistory._append)
  feedback  FeedbackStore.record           (semgate/feedback.py FeedbackStore.record; an
            "allow" needs session_id and project_root, so the child passes
            session_id="s" and project_root=<the round dir>)
  agentfiles AgentFiles._append            (semgate/agentfiles.py AgentFiles._append, used by record_pre/record_post)

After each round the parent reads the file byte-exactly and counts:
  torn   non-empty lines that are not one JSON object
  lost   expected record ids that are missing
  dup    ids found more than once
and also calls the real reader (Ledger.host_responses /
ToolHistory.count_executed_after_ask / AgentFiles.records /
FeedbackStore.latest) to see whether it raises. The readers now skip
malformed lines instead of raising.

    .venv\\Scripts\\python.exe formal\\repro\\stress_append.py --store ledger --procs 8 --records 200 --rounds 20 --pad 200
"""
from __future__ import annotations

import argparse
import multiprocessing as mp
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import isolate, rate, scan_jsonl  # noqa: E402


def child(store: str, path: str, pid: int, records: int, pad: int, barrier, round_dir: str = "") -> None:
    from semgate.agentfiles import AgentFiles
    from semgate.feedback import FeedbackStore
    from semgate.history import ToolHistory
    from semgate.ledger import Ledger
    filler = "x" * pad
    if store == "ledger":
        s = Ledger(path)
        write = lambda rid: s.record_host_response("conv", rid, {"decision": "ask", "reason": filler}, tool="bash")
    elif store == "history":
        s = ToolHistory(path)
        write = lambda rid: s.record_pending("conv", rid, "bash", {"command": "echo " + filler}, "ask", "semantic")
    elif store == "feedback":
        s = FeedbackStore(path)
        write = lambda rid: s.record("allow", "bash", {"command": f"echo {rid} {filler}"}, note=rid,
                                     session_id="s", project_root=round_dir)
    elif store == "agentfiles":
        s = AgentFiles(base_dir=path)
        write = lambda rid: s._append("sess", {"record_type": "pre", "session_id": "sess", "step_idx": rid,
                                               "paths": [], "scripts": [], "pad": filler})
    else:
        raise SystemExit(f"unknown store {store}")
    barrier.wait()
    for j in range(records):
        write(f"p{pid}-r{j}")


def record_id(store: str, rec: dict) -> str:
    if store == "feedback":
        return str(rec.get("note"))
    return str(rec.get("step_idx"))


def real_reader(store: str, path: Path) -> str:
    """Call the real reader. Returns "ok" or the exception type."""
    from semgate.agentfiles import AgentFiles
    from semgate.feedback import FeedbackStore
    from semgate.history import ToolHistory
    from semgate.ledger import Ledger
    try:
        if store == "ledger":
            Ledger(str(path)).host_responses()
        elif store == "history":
            ToolHistory(str(path)).count_executed_after_ask("bash", {"command": "echo"})
        elif store == "feedback":
            FeedbackStore(str(path)).latest("bash", {"command": "echo"})
        elif store == "agentfiles":
            list(AgentFiles(base_dir=str(path)).records("sess"))
        return "ok"
    except Exception as exc:
        return type(exc).__name__


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--store", default="ledger", choices=("ledger", "history", "feedback", "agentfiles"))
    ap.add_argument("--procs", type=int, default=8)
    ap.add_argument("--records", type=int, default=200)
    ap.add_argument("--rounds", type=int, default=10)
    ap.add_argument("--pad", type=int, default=200, help="filler bytes per record")
    a = ap.parse_args()
    tmp = isolate()
    ctx = mp.get_context("spawn")
    tot_expected = tot_lost = tot_torn = tot_dup = rounds_bad = reader_fail = tot_phantom = 0
    t0 = time.time()
    for r in range(a.rounds):
        rdir = tmp / f"round{r}"
        rdir.mkdir()
        if a.store == "agentfiles":
            target = str(rdir / "base")
            from semgate.agentfiles import session_key
            file_path = rdir / "base" / "agent_files" / f"{session_key('sess')}.jsonl"
        else:
            target = str(rdir / f"{a.store}.jsonl")
            file_path = Path(target)
        barrier = ctx.Barrier(a.procs)
        ps = [ctx.Process(target=child, args=(a.store, target, i, a.records, a.pad, barrier, str(rdir))) for i in range(a.procs)]
        for p in ps:
            p.start()
        for p in ps:
            p.join()
        good, bad = scan_jsonl(file_path)
        ids = Counter(record_id(a.store, g) for g in good)
        expected = {f"p{i}-r{j}" for i in range(a.procs) for j in range(a.records)}
        lost = len(expected - set(ids))
        dup = sum(c - 1 for c in ids.values() if c > 1)
        phantom = sum(c for i, c in ids.items() if i not in expected)   # parsed as a record that was never written
        tot_phantom += phantom
        reader = real_reader(a.store, file_path)
        tot_expected += len(expected)
        tot_lost += lost
        tot_torn += len(bad)
        tot_dup += dup
        rounds_bad += 1 if (lost or bad or dup) else 0
        reader_fail += 1 if reader != "ok" else 0
        print(f"round {r}: records={len(expected)} lost={lost} torn_lines={len(bad)} dup={dup} phantom={phantom} real_reader={reader}"
              + (f" first_torn={bad[0][:80]!r}" if bad else ""), flush=True)
    print(f"SUMMARY store={a.store} procs={a.procs} records/proc={a.records} pad={a.pad} rounds={a.rounds} "
          f"elapsed={time.time()-t0:.1f}s")
    print(f"  rounds with any defect: {rate(rounds_bad, a.rounds)}")
    print(f"  records lost: {rate(tot_lost, tot_expected)}; torn lines: {tot_torn}; duplicates: {tot_dup}; phantom records: {tot_phantom}")
    print(f"  rounds where the real reader raised: {rate(reader_fail, a.rounds)}")
    print(f"  temp dir: {tmp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
