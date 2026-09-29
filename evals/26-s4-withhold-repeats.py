"""Repeats for router threshold test_damage_withholds_edit_allow.

Judges each given case N times live (OpenRouter) under the candidate policy
(default policies/router_policy_dev_s4allow.json), records every answer and a
hash of the judge input, and replays the same answers under the base policy
(default policies/router_policy_dev_buildfacts.json: dev before the switch was
adopted). Both decisions come from the same
model answers, so a difference is the switch, never model variance. The two
policies must send byte-identical judge input; the script checks that the
replay under the base policy sends the same input hash as the live call.

The key: semgate's own lookup (providers/keys.find_key) in the .env given with
--key-env-file only (evals/24-margin-study.live_provider). Never printed.

Usage:
  py evals/26-s4-withhold-repeats.py --key-env-file <checkout>/.env --repeats 5 \\
     --case-file fixtures/eval/test-damage.jsonl --case <id> [--case <id> ...] \\
     [--case-file fixtures/eval/nonsense-steps.jsonl --case <id> ...] --output evals/reports/s4allow-repeats-<date>.json
  (--case applies to the --case-file before it.)
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from semgate.eval.runner import evaluate_cases, load_cases  # noqa: E402
from semgate.policy import Policy  # noqa: E402

_spec = importlib.util.spec_from_file_location("margin_study_s4", ROOT / "evals" / "24-margin-study.py")
ms = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(ms)


def judge_once(case: Any, policy: Policy, provider: Any) -> Dict[str, Any]:
    r = evaluate_cases([case], policy, provider=provider)["cases"][0]
    return {"decision": r["decision"], "stage": r["stage"], "provider_error": r["provider_error"],
            "code_signals": r.get("code_signals", []),
            "withheld": [v.get("predicate") for v in r["predicate_votes"] if v.get("vote") == "withheld"]}


def paired_run(case: Any, candidate: Policy, base: Policy, provider: Any) -> Dict[str, Any]:
    """One live call under `candidate`, then the same answers under `base`."""
    rec = ms.Recorder(provider)
    got = judge_once(case, candidate, rec)
    calls = rec.take()
    out = dict(got, calls=calls)
    answered = [c["answers"] for c in calls if "answers" in c]
    if not calls:
        out["base_decision"] = got["decision"]          # a gate decided; no model call
        return out
    replay = ms.ReplayProvider(answered)
    base_r = judge_once(case, base, replay)
    out["base_decision"] = base_r["decision"]
    out["base_input_same"] = replay.seen == [c["input_sha"] for c in calls if "answers" in c]
    return out


def parse_cases(argv_pairs: Sequence[Tuple[str, List[str]]]) -> List[Tuple[str, Any]]:
    out = []
    for path, ids in argv_pairs:
        if "private" in Path(path).parts:
            raise SystemExit("held-out case files are not read by this script")
        by_id = {c.case_id: c for c in load_cases([path])}
        for cid in ids:
            if cid not in by_id:
                raise SystemExit(f"{cid} is not in {path}")
            out.append((path, by_id[cid]))
    return out


def summarize(rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    cand = Counter(r["decision"] for r in rows if not r.get("provider_error"))
    base = Counter(r["base_decision"] for r in rows if not r.get("provider_error"))
    return {"candidate": dict(cand), "base": dict(base),
            "changed_runs": sum(1 for r in rows if not r.get("provider_error") and r["decision"] != r["base_decision"])}


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--key-env-file", required=True)
    ap.add_argument("--model", default="typesafe/jev-1.13")
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--budget", type=float, default=1.0)
    ap.add_argument("--candidate", default=str(ROOT / "policies" / "router_policy_dev_s4allow.json"))
    ap.add_argument("--base", default=str(ROOT / "policies" / "router_policy_dev_buildfacts.json"))
    ap.add_argument("--case-file", action="append", default=[])
    ap.add_argument("--case", action="append", default=[])
    ap.add_argument("--output", required=True)
    # --case belongs to the latest --case-file: re-read argv in order.
    raw = list(sys.argv[1:] if argv is None else argv)
    args = ap.parse_args(raw)
    pairs: List[Tuple[str, List[str]]] = []
    for i, tok in enumerate(raw[:-1]):
        if tok == "--case-file":
            pairs.append((raw[i + 1], []))
        elif tok == "--case":
            if not pairs:
                raise SystemExit("--case needs a --case-file before it")
            pairs[-1][1].append(raw[i + 1])
    candidate, base = Policy.load(args.candidate), Policy.load(args.base)
    inner = ms.live_provider(args.key_env_file, args.model)
    budget = ms.Budget(args.budget)
    out_cases, stopped = [], ""
    for path, case in parse_cases(pairs):
        rows = []
        for n in range(args.repeats):
            r = paired_run(case, candidate, base, inner)
            for c in r["calls"]:
                budget.add(c.get("cost"))
            rows.append(dict(r, run=n + 1))
            if budget.over():
                stopped = f"budget: {budget.total:.5f} USD passed {budget.limit}"
                break
        hashes = {c["input_sha"] for r in rows for c in r["calls"]}
        s = summarize(rows)
        out_cases.append({"case_id": case.case_id, "case_file": path, "label": case.label,
                          "input_hashes": len(hashes), "base_input_same": all(r.get("base_input_same", True) for r in rows),
                          **s, "runs": rows})
        print(f"{case.case_id} label={case.label} candidate={s['candidate']} base={s['base']} "
              f"hashes={len(hashes)} spend={budget.total:.5f}")
        if stopped:
            break
    doc = {"schema": "semgate-s4-withhold-repeats/1", "candidate": Path(args.candidate).name,
           "candidate_version": candidate.version, "base": Path(args.base).name, "base_version": base.version,
           "provider": inner.name, "model": inner.model, "repeats": args.repeats, "provider_usage": inner.usage_report(),
           "spend_usd": round(budget.total, 6), "stopped": stopped, "cases": out_cases}
    Path(args.output).write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"spend {budget.total:.5f} USD; {stopped or 'complete'}")
    return 3 if stopped else 0


if __name__ == "__main__":
    sys.exit(main())
