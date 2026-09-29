"""Control for stress_append.py: the same N-process JSONL append pattern, NOT
through semgate, with three write methods:

  python_a        open(path, "a") + write, what semgate does (ledger.py:34,
                  history.py:283, feedback.py:54, agentfiles.py:110). On
                  Windows the C runtime emulates O_APPEND: seek to end, then
                  WriteFile. Two processes can seek to the same end.
  locked          python_a inside a cross-process byte-range lock
                  (msvcrt.locking on a side lock file).
  append_data     a Win32 handle opened with FILE_APPEND_DATA only (ctypes
                  CreateFileW); each WriteFile is appended atomically at the
                  current end by the file system.

Records: JSON objects of `pad` bytes, same shape as the stress test.

    .venv\\Scripts\\python.exe formal\\repro\\control_append.py --procs 8 --records 200 --rounds 10
"""
from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import isolate, rate, scan_jsonl  # noqa: E402


def child(method: str, path: str, pid: int, records: int, pad: int, barrier) -> None:
    filler = "x" * pad
    lines = [(json.dumps({"id": f"p{pid}-r{j}", "pad": filler}, sort_keys=True) + "\n") for j in range(records)]
    if method == "append_data":
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateFileW.restype = wintypes.HANDLE
        FILE_APPEND_DATA, SHARE_RW, OPEN_ALWAYS = 0x0004, 0x00000003, 4
        h = k32.CreateFileW(path, FILE_APPEND_DATA, SHARE_RW, None, OPEN_ALWAYS, 0x80, None)
        barrier.wait()
        for text in lines:
            data = text.replace("\n", "\r\n").encode("utf-8")
            written = wintypes.DWORD(0)
            k32.WriteFile(h, data, len(data), ctypes.byref(written), None)
        k32.CloseHandle(h)
        return
    if method == "locked":
        import msvcrt
        lockf = open(path + ".lock", "a+b")
        barrier.wait()
        for text in lines:
            lockf.seek(0)
            while True:
                try:
                    msvcrt.locking(lockf.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    time.sleep(0.0005)
            try:
                with open(path, "a", encoding="utf-8") as handle:
                    handle.write(text)
            finally:
                lockf.seek(0)
                msvcrt.locking(lockf.fileno(), msvcrt.LK_UNLCK, 1)
        return
    barrier.wait()
    for text in lines:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(text)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--procs", type=int, default=8)
    ap.add_argument("--records", type=int, default=200)
    ap.add_argument("--rounds", type=int, default=10)
    ap.add_argument("--pad", type=int, default=200)
    a = ap.parse_args()
    tmp = isolate("semgate-formal-control-")
    ctx = mp.get_context("spawn")
    for method in ("python_a", "locked", "append_data"):
        lost = torn = dup = 0
        t0 = time.time()
        for r in range(a.rounds):
            path = tmp / f"{method}-{r}.jsonl"
            barrier = ctx.Barrier(a.procs)
            ps = [ctx.Process(target=child, args=(method, str(path), i, a.records, a.pad, barrier)) for i in range(a.procs)]
            for p in ps:
                p.start()
            for p in ps:
                p.join()
            good, bad = scan_jsonl(path)
            ids = Counter(g.get("id") for g in good)
            expected = {f"p{i}-r{j}" for i in range(a.procs) for j in range(a.records)}
            lost += len(expected - set(ids))
            torn += len(bad)
            dup += sum(c - 1 for c in ids.values() if c > 1)
        n = a.procs * a.records * a.rounds
        print(f"{method:12} procs={a.procs} records={n}: lost {rate(lost, n)}, torn lines {torn}, duplicates {dup}, "
              f"elapsed {time.time()-t0:.1f}s", flush=True)
    print(f"temp dir: {tmp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
