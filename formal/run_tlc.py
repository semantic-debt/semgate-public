"""Runs TLC for every (module, variant, property) job and records the result.

    .venv\\Scripts\\python.exe formal\\run_tlc.py [--only SUBSTRING[,SUBSTRING]] [--list] [--skip-done]

Writes formal/cfg/<job>.cfg, formal/results/tlc/<job>.out and a summary in
formal/results/tlc/summary.json (merged with earlier runs).
Java and tla2tools.jar come from the session scratchpad (see REPORT.md), or
from SEMGATE_TLA_DIR.

Variants: "code" models the code on branch concurrency-fixes (cross-process
locks with bounded waits, skip-bad-lines readers, scoped approvals with
expiry). "old" models commit 5805459 (the analysis in REPORT.md). "M_*" are
mutants of "code"; each must violate at least one property.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
TLA = Path(os.environ.get("SEMGATE_TLA_DIR") or (HERE / "tools"))  # TLA+ tools folder: tla2tools.jar and a JDK
JAVA = TLA / "jdk-21.0.12.1+1" / "bin" / "java.exe"
JAR = TLA / "tla2tools.jar"

SYMMETRY = {"MC_Semgate": "Perms"}
# serve: a stuck state is judged by the liveness properties (S3, S4), not reported as a deadlock
NO_DEADLOCK = {"SemgateServe"}

# ---------------- Semgate.tla ----------------
SG_COMMON = {"Procs": "{p1, p2, p3}", "Sessions": '{"s1", "s2"}', "Projects": '{"j1", "j2"}', "Commands": '{"c1", "c2"}',
             "Base": "<- MCBase", "MinCount": "2", "GrantCmds": '{"c1"}', "GrantSess": '"s1"', "GrantProj": '"j1"'}
SG_CODE = dict(SG_COMMON, AppendMode='"crt"', LockMode='"oslock"', LockTimeouts="FALSE", TimeoutAction='"closed"',
               HistReader='"skip"', CountMode='"code"', PostDelivery='"once"', KeyMode='"scoped"', ExpiryMode='"check"',
               Legacy="TRUE", Crashes="FALSE")
SG_OLD = dict(SG_CODE, LockMode='"none"', HistReader='"raise"', KeyMode='"exact"', ExpiryMode='"ignore"')
SG_VARIANTS = {
    "code": SG_CODE,
    "code_crash": dict(SG_CODE, Crashes="TRUE"),
    "code_timeout": dict(SG_CODE, LockTimeouts="TRUE"),
    "code_timeout_crash": dict(SG_CODE, LockTimeouts="TRUE", Crashes="TRUE"),
    "old": SG_OLD,
    "old_crash": dict(SG_OLD, Crashes="TRUE"),
    # store mutants
    "M_nolock": dict(SG_CODE, LockMode='"none"'),
    "M_lockfile_crash": dict(SG_CODE, LockMode='"lockfile"', Crashes="TRUE"),
    "M_tolerant": dict(SG_CODE, LockMode='"none"', HistReader='"tolerant"'),
    "M_raise_nolock": dict(SG_CODE, LockMode='"none"', HistReader='"raise"'),
    "M_count_error": dict(SG_CODE, CountMode='"ignore_error"'),
    "M_post_twice": dict(SG_CODE, PostDelivery='"twice"'),
    # lock-timeout mutants
    "M_timeout_open": dict(SG_CODE, LockTimeouts="TRUE", TimeoutAction='"open"'),
    "M_timeout_drop": dict(SG_CODE, LockTimeouts="TRUE", TimeoutAction='"drop"'),
    # approval mutants
    "M_key_tool": dict(SG_CODE, KeyMode='"tool_only"'),
    "M_key_nosession": dict(SG_CODE, KeyMode='"nosession"'),
    "M_key_noproject": dict(SG_CODE, KeyMode='"noproject"'),
    "M_legacy_ok": dict(SG_CODE, KeyMode='"legacy_ok"'),
    "M_noexpiry": dict(SG_CODE, ExpiryMode='"ignore"'),
}
# Store properties do not depend on session, project or approvals: one session,
# one project, no legacy record (2 choices per process instead of 8).
ONE_SCOPE = {"Sessions": '{"s1"}', "Projects": '{"j1"}', "Legacy": "FALSE"}
SG_STORE_INV = ["LedgerOneLine", "NoMisread", "LearnedSound", "CountNoOver", "CountExactAtEnd", "NoTornLine", "NoLostRecord"]
SG_TIMEOUT_INV = ["LedgerOneLine", "FailClosed", "LearnedSound", "CountNoOver", "NoMisread"]
SG_APPROVAL_INV = ["ApprovalScoped", "ApprovalExact", "ApprovalSessionScoped", "ApprovalUnexpired"]
SG_APPROVAL_VARIANTS = ["code", "M_key_tool", "M_key_nosession", "M_key_noproject", "M_legacy_ok", "M_noexpiry"]
# Mutants and "old" run the properties they are built to break (a "holds" run
# on an unlocked configuration explores 20M+ states and adds nothing: the
# property holds for "code" already). Approval mutants run the full
# strong/weak matrix (SG_APPROVAL_VARIANTS).
SG_TARGETS = {
    "old": ["LedgerOneLine", "CountExactAtEnd", "NoTornLine", "NoLostRecord"],
    "M_nolock": ["LedgerOneLine", "CountExactAtEnd", "NoTornLine", "NoLostRecord"],
    "M_tolerant": ["NoMisread", "CountNoOver"],
    "M_raise_nolock": ["CountExactAtEnd"],
    "M_count_error": ["LearnedSound", "CountNoOver", "CountExactAtEnd"],
    "M_post_twice": ["LearnedSound", "CountNoOver", "CountExactAtEnd"],
    "M_timeout_open": ["FailClosed"],
    "M_timeout_drop": ["LedgerOneLine"],
}
OLD_APPROVAL = ["ApprovalScoped", "ApprovalSessionScoped", "ApprovalUnexpired", "ApprovalExact"]
SG_CANARY_CODE = ["K1_NoApprovalUsed", "K2_NoLearnedAllow", "K3_NoReturn", "ApprovalOnce"]
SG_CANARY_OLD = ["K4_NoTornLine", "K5_NoLostRecord"]
SG_CANARY_TIMEOUT = ["K10_NoLockTimeout", "K11_NoFailClosed"]
# liveness (no symmetry): 2 processes, one session/project, one command (c1, asked).
LIVE2 = dict(ONE_SCOPE, Procs="{p1, p2}", Commands='{"c1"}')
APPROVAL2 = {"Procs": "{p1, p2}"}


def jobs():
    out = []
    for prop in SG_STORE_INV:
        out.append(("MC_Semgate", "code", dict(SG_CODE, **ONE_SCOPE), "inv", prop, "Spec"))
    for prop in SG_TIMEOUT_INV:
        out.append(("MC_Semgate", "code_timeout", dict(SG_VARIANTS["code_timeout"], **ONE_SCOPE), "inv", prop, "Spec"))
    for v, props in SG_TARGETS.items():
        for prop in props:
            out.append(("MC_Semgate", v, dict(SG_VARIANTS[v], **ONE_SCOPE), "inv", prop, "Spec"))
    for v in ("code_crash", "old_crash"):
        out.append(("MC_Semgate", v, dict(SG_VARIANTS[v], **ONE_SCOPE), "inv", "LedgerOneLine", "Spec"))
    # timeouts + crashes with 3 processes did not finish in 1 h; 2 processes (suffix _2p)
    for prop in ("LedgerOneLine", "FailClosed"):
        out.append(("MC_Semgate", "code_timeout_crash_2p", dict(SG_VARIANTS["code_timeout_crash"], **ONE_SCOPE, Procs="{p1, p2}"),
                    "inv", prop, "Spec"))
    # Approval properties are about each decision: 2 processes, 2 sessions, 2 projects,
    # 2 commands, a legacy record and the expiry clock (3 processes: > 1 h per run).
    for v in SG_APPROVAL_VARIANTS:
        for prop in SG_APPROVAL_INV:
            out.append(("MC_Semgate", v + "_2p", dict(SG_VARIANTS[v], **APPROVAL2), "inv", prop, "Spec"))
    for prop in OLD_APPROVAL:
        out.append(("MC_Semgate", "old_2p", dict(SG_OLD, **APPROVAL2), "inv", prop, "Spec"))
    for prop in SG_CANARY_CODE:
        cfg = dict(SG_CODE, **ONE_SCOPE) if prop in ("K2_NoLearnedAllow", "K3_NoReturn") else dict(SG_CODE, **APPROVAL2)
        out.append(("MC_Semgate", "code" if prop in ("K2_NoLearnedAllow", "K3_NoReturn") else "code_2p", cfg, "inv", prop, "Spec"))
    for prop in SG_CANARY_OLD:
        out.append(("MC_Semgate", "old", dict(SG_OLD, **ONE_SCOPE), "inv", prop, "Spec"))
    for prop in SG_CANARY_TIMEOUT:
        out.append(("MC_Semgate", "code_timeout", dict(SG_VARIANTS["code_timeout"], **ONE_SCOPE), "inv", prop, "Spec"))
    # T2 as an end-state invariant, 3 processes, symmetry
    for v in ["code", "old", "M_raise_nolock"]:
        out.append(("MC_Semgate", v, dict(SG_VARIANTS[v], **ONE_SCOPE), "inv", "HistoryRecoversFinal", "Spec"))
    # liveness, 2 processes, weak fairness only (WF on each process's steps)
    temp_variants = {"Termination": ["code", "code_crash", "code_timeout", "code_timeout_crash", "M_lockfile_crash", "old"],
                     "HistoryRecovers": ["code", "old", "M_raise_nolock"]}
    for prop, vs in temp_variants.items():
        for v in vs:
            out.append(("MC_Semgate", v + "_2p", dict(SG_VARIANTS[v], **LIVE2), "prop", prop, "Spec"))
    # fairness check: without WF the liveness properties must fail (they are not true by stuttering alone)
    out.append(("MC_Semgate", "code_2p_nofair", dict(SG_CODE, **LIVE2), "prop", "Termination", "SpecNoFair"))
    try:
        from run_tlc_more import more_jobs     # F6 and serve modules
        out.extend(more_jobs())
    except ImportError:
        pass
    return out


def write_cfg(name: str, consts: dict, kind: str, prop: str, symmetry: str = "", spec: str = "Spec") -> Path:
    lines = ["CONSTANTS"]
    for k, v in consts.items():
        lines.append(f"  {k} {v}" if v.startswith("<-") else f"  {k} = {v}")
    lines.append(f"SPECIFICATION {spec}")
    if kind == "inv" and symmetry:
        lines.append(f"SYMMETRY {symmetry}")     # sound for invariants; never used for liveness
    lines.append(("INVARIANT " if kind == "inv" else "PROPERTY ") + prop)
    p = HERE / "cfg" / f"{name}.cfg"
    p.parent.mkdir(exist_ok=True)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def run(module: str, variant: str, consts: dict, kind: str, prop: str, timeout: int, spec: str = "Spec") -> dict:
    name = f"{module}__{variant}__{prop}"
    cfg = write_cfg(name, consts, kind, prop, SYMMETRY.get(module, ""), spec)
    outp = HERE / "results" / "tlc" / f"{name}.out"
    outp.parent.mkdir(parents=True, exist_ok=True)
    meta = TLA / "states" / name
    t0 = time.time()
    try:
        p = subprocess.run([str(JAVA), "-XX:+UseParallelGC", "-Xmx6g", "-cp", str(JAR), "tlc2.TLC", "-workers", "auto",
                            "-metadir", str(meta), "-cleanup", *(["-deadlock"] if module in NO_DEADLOCK else []),
                            "-config", str(cfg), f"{module}.tla"],
                           cwd=str(HERE), capture_output=True, text=True, timeout=timeout)
        text = p.stdout + p.stderr
    except subprocess.TimeoutExpired as exc:
        text = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        text += "\nDRIVER: TIMEOUT"
    outp.write_text(text, encoding="utf-8")
    secs = round(time.time() - t0, 1)
    states = re.findall(r"^State (\d+):", text, re.M)
    back = re.search(r"Back to state (\d+)", text)
    distinct = re.findall(r"([\d,]+) distinct states found", text)
    depth = re.search(r"depth of the complete state graph search is (\d+)", text)
    if "No error has been found" in text:
        result = "holds"
    elif re.search(r"Invariant \S+ is violated", text):
        result = "violated"
    elif "Temporal properties were violated" in text:
        result = "violated (liveness)"
    elif "Deadlock reached" in text:
        result = "violated (deadlock)"
    elif "DRIVER: TIMEOUT" in text:
        result = "timeout"
    else:
        result = "error"
    return {"job": name, "module": module, "variant": variant, "property": prop, "kind": kind, "spec": spec, "result": result,
            "trace_states": max(map(int, states)) if states else None,
            "lasso_back_to": int(back.group(1)) if back else None,
            "distinct_states": distinct[-1] if distinct else None,
            "depth": int(depth.group(1)) if depth else None, "seconds": secs}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--timeout", type=int, default=3600)
    ap.add_argument("--skip-done", action="store_true", help="skip jobs already in summary.json with a result")
    a = ap.parse_args()
    summary_path = HERE / "results" / "tlc" / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.exists() else {}
    for module, variant, consts, kind, prop, spec in jobs():
        name = f"{module}__{variant}__{prop}"
        if a.only and not any(all(s in name for s in alt.split("+")) for alt in a.only.split(",")):
            continue
        if a.list:
            print(name)
            continue
        if a.skip_done and summary.get(name, {}).get("result") in ("holds", "violated", "violated (liveness)", "violated (deadlock)"):
            continue
        r = run(module, variant, consts, kind, prop, a.timeout, spec)
        summary[name] = r
        summary_path.write_text(json.dumps(summary, indent=1, sort_keys=True), encoding="utf-8")
        print(f"{name:62} {r['result']:20} trace={r['trace_states']} back={r['lasso_back_to']} "
              f"states={r['distinct_states']} depth={r['depth']} {r['seconds']}s", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
