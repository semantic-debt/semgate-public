"""Stress test: F6 created-file records and snapshots (semgate/agentfiles.py
AgentFiles.record_post and AgentFiles._snapshot) when several PostToolUse
hooks of one session run at once.

Setup per round (parent, sequential, no race): a temp project with N new
files; for each, a `pre` record (existed=false) is written first with
expected={name: agentfiles.expected_hashes(body)} (the sha256 of the content
the tool writes, plus its CRLF variant), then the file is created with
write_text(body) (CRLF on Windows). record_post records a path as
agent-created ONLY if its current sha256 is one of the expected hashes;
without expected hashes nothing is recorded. Then N real processes call
AgentFiles.record_post for their own step at the same time (same session,
same agent_files dir).

Mode `same`: every file has the same content -> same sha256 -> same snapshot
path. Before the fix the temp name was `<sha>.tmp` for every process (a
collision); now AgentFiles._snapshot uses a temp name unique per process.
Mode `distinct`: different content per file (only the JSONL append, now
under the filelock).

Checks: created records present per path; eligible() per path (all files are
unchanged, so every path should be eligible); and the safety invariant
"eligible => snapshot content == current file content" (checked by reading
both files, independent of semgate's own re-hash).

    .venv\\Scripts\\python.exe formal\\repro\\stress_snapshot.py --procs 8 --rounds 30 --mode same
"""
from __future__ import annotations

import argparse
import hashlib
import multiprocessing as mp
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import isolate, rate, scan_jsonl  # noqa: E402

SESSION = "sess-f6"


def child(base: str, step: str, barrier, out) -> None:
    from semgate.agentfiles import AgentFiles
    store = AgentFiles(base_dir=base)
    barrier.wait()
    res = store.record_post(SESSION, step)
    out.put((step, len(res["created"])))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--procs", type=int, default=8)
    ap.add_argument("--rounds", type=int, default=30)
    ap.add_argument("--mode", choices=("same", "distinct"), default="same")
    ap.add_argument("--size", type=int, default=200_000, help="bytes per file (bigger = longer copy window)")
    a = ap.parse_args()
    tmp = isolate("semgate-formal-snap-")
    from semgate.agentfiles import AgentFiles, expected_hashes, session_key
    ctx = mp.get_context("spawn")
    tot = dict(paths=0, reported=0, records=0, eligible=0, unsafe=0, torn=0, leftover_tmp=0, not_recorded=0)
    t0 = time.time()
    for r in range(a.rounds):
        root = tmp / f"round{r}" / "proj"
        root.mkdir(parents=True)
        base = str(tmp / f"round{r}" / "base")
        store = AgentFiles(base_dir=base)
        paths = []
        for i in range(a.procs):
            f = root / f"reproduce_{i}.py"
            body = ("print('same')\n" if a.mode == "same" else f"print({i})\n") * (a.size // 14)
            # The expected hashes come from the content the tool writes (a Write tool carries it).
            # write_text writes CRLF on Windows; expected_hashes includes that variant.
            store.record_pre(SESSION, f"toolu_{i}", project_root=str(root), cwd=str(root), targets=[f.name],
                             expected={f.name: expected_hashes(body)})
            f.write_text(body, encoding="utf-8")
            paths.append(f)
        barrier = ctx.Barrier(a.procs)
        out = ctx.Queue()
        ps = [ctx.Process(target=child, args=(base, f"toolu_{i}", barrier, out)) for i in range(a.procs)]
        for p in ps:
            p.start()
        for p in ps:
            p.join()
        reported = sum(n for _, n in (out.get() for _ in ps))
        recfile = Path(base) / "agent_files" / f"{session_key(SESSION)}.jsonl"
        good, bad = scan_jsonl(recfile)
        created = {g["path"] for g in good if g.get("record_type") == "created"}
        eligible = unsafe = 0
        for f in paths:
            from semgate.agentfiles import resolve
            full = resolve(str(f), "")
            if store.eligible(SESSION, full, str(root), raw_path=str(f)):
                eligible += 1
                sha = hashlib.sha256(f.read_bytes()).hexdigest()
                snap = Path(base) / "snapshots" / session_key(SESSION) / sha
                if not snap.exists() or snap.read_bytes() != f.read_bytes():
                    unsafe += 1
        leftover = len(list((Path(base) / "snapshots").rglob("*.tmp"))) if (Path(base) / "snapshots").exists() else 0
        tot["paths"] += len(paths)
        tot["reported"] += reported
        tot["records"] += len(created)
        tot["eligible"] += eligible
        tot["unsafe"] += unsafe
        tot["torn"] += len(bad)
        tot["not_recorded"] += sum(1 for g in good if g.get("record_type") == "not_recorded")
        tot["leftover_tmp"] += leftover
        print(f"round {r}: files={len(paths)} record_post reported created={reported} created records on disk={len(created)} "
              f"eligible={eligible} unsafe={unsafe} torn={len(bad)} leftover .tmp={leftover}", flush=True)
    n = tot["paths"]
    print(f"SUMMARY mode={a.mode} procs={a.procs} rounds={a.rounds} size={a.size} elapsed={time.time()-t0:.1f}s")
    print(f"  record_post skipped the file (no created record written): {rate(n - tot['reported'], n)}")
    print(f"  created record written but lost from the JSONL: {rate(tot['reported'] - tot['records'], n)}")
    print(f"  unchanged agent-created files NOT eligible (extra human ask): {rate(n - tot['eligible'], n)}")
    print(f"  eligible with snapshot != file (unsafe): {tot['unsafe']}; torn lines: {tot['torn']}; leftover .tmp files: {tot['leftover_tmp']}")
    print(f"  not_recorded records (file content differs from the expected hash): {tot['not_recorded']}")
    print(f"  temp dir: {tmp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
