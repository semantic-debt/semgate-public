"""Link placement experiment (S6_link_placement and the persistence_link gate).

Two modes. Neither reads evals/private.

  --state-diff (no network): every case of the given public case files is
      judged twice with a recording provider that returns fixed answers:
      A = router_policy_dev.json with the persistence_link gate switched off
          (what the code did before the gate and S6),
      B = the policy under test (default router_policy_dev_s6.json), gate on.
      Prints every case whose stage, reason or judge input (state and
      questions) differs. Everything else is judged on byte-identical input.

  --dump OUT --cases F [F ...] [--semgate-root DIR] (no network): judges
      every case with the recording provider using the semgate code in DIR
      (default: this checkout; e.g. `git archive <commit>` unpacked in a temp
      folder for the code before a change) and its policies/router_policy_dev.json,
      and writes per case the stage, reason, gate hits, code signals and a
      hash of every judge input. --dump-policy P uses the policy file P
      instead (e.g. policies/router_policy_dev_testrun.json).
  --compare A.json B.json: prints every case whose stage, reason or judge
      input differs between two dumps, with the full user request and command.

  --repeat N --case-file F --case ID [--case ID ...] --policy P [--gate off]
      (live, TypeSafe; the key is read by the provider from .env): judges
      each case N times and prints the decision and the main answers. With
      --gate off the persistence_link gate is switched off, so the model is
      asked and S6 (when the policy lists it) reaches it. Prints the full
      user request and command first.

Usage:
  py evals/21-link-placement.py --dump before.json --semgate-root %TEMP%/semgate-0adbab3 --cases fixtures/eval/*.jsonl
  py evals/21-link-placement.py --dump after.json --cases fixtures/eval/*.jsonl
  py evals/21-link-placement.py --compare before.json after.json
  py evals/21-link-placement.py --state-diff --cases evals/data/redcode-nl2sh/cases.jsonl fixtures/eval/swe-trajectories.jsonl
  py evals/21-link-placement.py --repeat 5 --case-file evals/data/redcode-nl2sh/cases.jsonl \\
      --case nl2sh:150 --case nl2sh:253 --policy policies/router_policy_dev_s6.json --gate off --output out.json
"""
from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]


def _code_root(argv: List[str]) -> Path:
    """--semgate-root DIR: import semgate from DIR (read before the imports)."""
    for i, a in enumerate(argv):
        if a == "--semgate-root" and i + 1 < len(argv):
            return Path(argv[i + 1]).resolve()
        if a.startswith("--semgate-root="):
            return Path(a.split("=", 1)[1]).resolve()
    return ROOT


CODE_ROOT = _code_root(sys.argv[1:])
sys.path.insert(0, str(CODE_ROOT))

from semgate import linkplace, rules  # noqa: E402
from semgate.eval.case import BenchmarkCase  # noqa: E402
from semgate.judge import judge  # noqa: E402
from semgate.policy import Policy  # noqa: E402
from semgate.providers.base import PredicateAnswer  # noqa: E402
from semgate.scriptsource import SyntheticWorkspace  # noqa: E402
from semgate.gitstate import SyntheticFacts, SyntheticHistory  # noqa: E402

_REAL_HITS = linkplace.persistence_hits
_REAL_SCRIPT_HITS = getattr(linkplace, "script_persistence_hits", None)


def gate(on: bool) -> None:
    rules.linkplace.persistence_hits = _REAL_HITS if on else (lambda *a, **k: [])
    if _REAL_SCRIPT_HITS is not None:
        rules.linkplace.script_persistence_hits = _REAL_SCRIPT_HITS if on else (lambda *a, **k: [])


def load(path: str) -> List[BenchmarkCase]:
    if "private" in Path(path).parts:
        raise SystemExit("held-out case files are not read by this script")
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            raw = json.loads(line)
            if raw.get("schema", "semgate-eval-case/1") == "semgate-eval-case/1" and "envelope" in raw:
                raw.setdefault("schema", "semgate-eval-case/1")
                raw.setdefault("label", "ask")
                raw.setdefault("source", "")
                raw.setdefault("source_id", raw.get("case_id", ""))
                raw.setdefault("category", "")
                out.append(BenchmarkCase.from_dict(raw))
    return out


def run(case: BenchmarkCase, policy: Policy, provider: Any):
    ws = case.workspace or {}
    workspace = (SyntheticWorkspace(ws.get("files") or {}, ws.get("dirs") or ())
                 if (ws.get("files") or ws.get("dirs")) else None)
    facts = (SyntheticFacts(ws.get("agent_created") or {}, case.envelope.environment.project_root)
             if ws.get("agent_created") else None)
    predates = case.envelope.environment.git_head_predates_session
    history = SyntheticHistory(predates) if predates is not None else None
    prior = case.envelope.environment.prior_on_task_p
    # A fixed fake PATH from the case, never this machine's PATH (the same rule
    # as semgate/eval/runner.py). Older code has no path_env parameter.
    extra = ({"path_env": str(ws["path_env"])}
             if ws.get("path_env") and "path_env" in inspect.signature(judge).parameters else {})
    return judge(case.envelope, policy, provider=provider, facts=facts, workspace=workspace, git_history=history,
                 prior_on_task=list(prior) if prior is not None else None, **extra)


class Recorder:
    name = "recorder"

    def __init__(self) -> None:
        self.calls: List[str] = []

    def evaluate(self, state, questions):
        self.calls.append(json.dumps({"state": state, "questions": questions}, sort_keys=True))
        out = {}
        for q, spec in questions.items():
            kind = spec.get("type")
            if kind == "choice":
                out[q] = PredicateAnswer(q, value="review", confidence=0.6,
                                         raw={"probabilities": {"run": 0.2, "review": 0.6, "block": 0.2}})
            elif kind == "score":
                out[q] = PredicateAnswer(q, value=1.0, confidence=0.6, raw={"probabilities": {}})
            else:
                out[q] = PredicateAnswer(q, probability=0.5, confidence=0.5)
        return out


def state_diff(files: List[str], policy_b: str) -> int:
    a_pol = Policy.load(str(ROOT / "policies" / "router_policy_dev.json"))
    b_pol = Policy.load(policy_b)
    total = changed = 0
    for f in files:
        n = d = 0
        for case in load(f):
            n += 1
            ra, rb = Recorder(), Recorder()
            gate(False)
            da = run(case, a_pol, ra)
            gate(True)
            db = run(case, b_pol, rb)
            if (da.stage, da.reason_code) != (db.stage, db.reason_code) or ra.calls != rb.calls:
                d += 1
                cmd = case.envelope.action.arguments.get("command")
                print(f"DIFF {f} {case.case_id} label={case.label}\n  USER: {case.envelope.user_message!r}\n"
                      f"  CMD: {cmd!r}\n  A: {da.decision}/{da.stage}/{da.reason_code} calls={len(ra.calls)}\n"
                      f"  B: {db.decision}/{db.stage}/{db.reason_code} calls={len(rb.calls)}")
        print(f"## {f}: {n} cases, {d} differ")
        total += n
        changed += d
    gate(True)
    print(f"## total {total} cases, {changed} differ")
    return 0


def dump(files: List[str], output: str, policy_path: str = "") -> int:
    policy = Policy.load(policy_path or str(CODE_ROOT / "policies" / "router_policy_dev.json"))
    gate(True)
    out: Dict[str, Any] = {"code_root": str(CODE_ROOT), "policy_version": policy.version, "files": {}}
    for f in files:
        rows = {}
        for case in load(f):
            rec = Recorder()
            d = run(case, policy, rec)
            states = [json.loads(c)["state"] for c in rec.calls]
            rows[case.case_id] = {
                "label": case.label, "decision": d.decision, "stage": d.stage, "reason_code": d.reason_code,
                "gate_hits": d.gate_hits or [],
                "code_signals": [s.get("code_signals", "") for s in states],
                "script_source": [s.get("script_source", "") for s in states],
                "calls": len(rec.calls),
                "input_sha": hashlib.sha256("\n".join(rec.calls).encode("utf-8")).hexdigest(),
                "user": case.envelope.user_message,
                "command": case.envelope.action.arguments.get("command"),
                "tool": case.envelope.action.tool,
            }
        out["files"][f] = rows
        print(f"## {f}: {len(rows)} cases")
    Path(output).write_text(json.dumps(out, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return 0


def compare(a_path: str, b_path: str) -> int:
    a = json.loads(Path(a_path).read_text(encoding="utf-8"))
    b = json.loads(Path(b_path).read_text(encoding="utf-8"))
    total = changed = 0
    for f in sorted(set(a["files"]) | set(b["files"])):
        ra, rb = a["files"].get(f, {}), b["files"].get(f, {})
        d = 0
        for cid in sorted(set(ra) | set(rb)):
            x, y = ra.get(cid), rb.get(cid)
            if x is None or y is None:
                print(f"MISSING {f} {cid} in {'A' if x is None else 'B'}")
                d += 1
                continue
            def key(r):
                return r["stage"], r["reason_code"], r["input_sha"], sorted(g["gate_class"] for g in r["gate_hits"])
            if key(x) == key(y):
                continue
            d += 1
            print(f"DIFF {f} {cid} label={x['label']} tool={x['tool']}\n  USER: {x['user']!r}\n  CMD: {x['command']!r}\n"
                  f"  A: {x['decision']}/{x['stage']}/{x['reason_code']} calls={x['calls']} gates={x['gate_hits']}\n"
                  f"  B: {y['decision']}/{y['stage']}/{y['reason_code']} calls={y['calls']} gates={y['gate_hits']}")
            if x["code_signals"] != y["code_signals"]:
                print(f"  A code_signals: {x['code_signals']!r}\n  B code_signals: {y['code_signals']!r}")
            if x.get("script_source", []) != y.get("script_source", []):
                print(f"  A script_source: {x.get('script_source', [])!r}\n  B script_source: {y.get('script_source', [])!r}")
        n = len(set(ra) | set(rb))
        print(f"## {f}: {n} cases, {d} differ")
        total += n
        changed += d
    print(f"## total {total} cases, {changed} differ")
    return 0


def _votes(decision) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for v in decision.predicate_votes or []:
        pid = v.get("predicate")
        if pid in ("route", "effect", "user_asked", "on_task", "executes", "edit_allow_review"):
            out[pid] = {k: v.get(k) for k in ("value", "confidence", "p", "probabilities", "vote") if v.get(k) is not None}
    return out


def repeat(case_file: str, ids: List[str], policy_path: str, n: int, gate_on: bool, output: str) -> int:
    from semgate.providers.typesafe import TypeSafeProvider
    policy = Policy.load(policy_path)
    provider = TypeSafeProvider()
    by_id = {c.case_id: c for c in load(case_file)}
    gate(gate_on)
    records = []
    for cid in ids:
        case = by_id[cid]
        print(f"== {cid} label={case.label}\n  USER: {case.envelope.user_message!r}\n"
              f"  CMD: {case.envelope.action.arguments.get('command')!r}")
        for i in range(n):
            d = run(case, policy, provider)
            sig = [s.get("id") for s in (d.evidence.get("code_signals") or {}).get("fired", [])]
            rec = {"case_id": cid, "label": case.label, "run": i + 1, "decision": d.decision, "stage": d.stage,
                   "reason_code": d.reason_code, "signals": sig, "votes": _votes(d),
                   "provider_error": bool(d.error)}
            records.append(rec)
            v = rec["votes"]
            print(f"  run {i + 1}: {d.decision} ({d.stage}/{d.reason_code}) signals={sig} "
                  f"route={v.get('route', {}).get('probabilities')} effect={v.get('effect', {}).get('value')} "
                  f"user_asked={v.get('user_asked', {}).get('p')}")
        counts = {k: sum(1 for r in records if r["case_id"] == cid and r["decision"] == k) for k in ("allow", "ask", "deny")}
        print(f"  {cid}: {counts}")
    gate(True)
    report = {"policy": policy_path, "policy_version": policy.version, "gate": "on" if gate_on else "off",
              "repeats": n, "case_file": case_file, "records": records,
              "provider_errors": sum(1 for r in records if r["provider_error"])}
    if output:
        Path(output).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"provider_errors={report['provider_errors']}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state-diff", action="store_true")
    ap.add_argument("--cases", nargs="*", default=[])
    ap.add_argument("--policy", default=str(ROOT / "policies" / "router_policy_dev_s6.json"))
    ap.add_argument("--repeat", type=int, default=0)
    ap.add_argument("--case-file", default="")
    ap.add_argument("--case", action="append", default=[])
    ap.add_argument("--gate", choices=["on", "off"], default="on")
    ap.add_argument("--output", default="")
    ap.add_argument("--dump", default="")
    ap.add_argument("--semgate-root", default="")
    ap.add_argument("--compare", nargs=2, default=None)
    ap.add_argument("--dump-policy", default="")
    args = ap.parse_args(argv)
    if args.dump:
        # --dump uses the checkout's router_policy_dev.json unless --dump-policy names another file.
        return dump(args.cases, args.dump, args.dump_policy)
    if args.compare:
        return compare(*args.compare)
    if args.state_diff:
        return state_diff(args.cases, args.policy)
    if args.repeat:
        return repeat(args.case_file, args.case, args.policy, args.repeat, args.gate == "on", args.output)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
