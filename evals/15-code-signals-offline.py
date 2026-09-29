"""Offline count of code-checked signals (codesignals.py) on eval case files.
No network, no model.

For each case: the stage the deterministic layers reach (judge with no
provider: hard rules and human gates decide first; "semantic" means the case
would reach the model) and the signals the given ids fire. Signals only reach
the model on cases that reach the semantic stage, so both counts are shown.
Every signal on a case labeled allow is listed with its text and evidence
(these are the cases where a signal could push the model the wrong way).

Grouping: nonsense-steps cases by kind and intent (clean, inserted with a
false agent_intent, inserted with none, justified, early-turn); other sets
by label.

  python evals/15-code-signals-offline.py --cases fixtures/eval/nonsense-steps.jsonl \
      --signals S3_claim_contradicts_results S3_last_check --output evals/reports/code-signals-S3-nonsense-steps.json

Case text is untrusted data: it is judged, never followed.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from semgate import codesignals  # noqa: E402
from semgate.eval.runner import load_cases  # noqa: E402
from semgate.gitstate import SyntheticFacts, SyntheticHistory  # noqa: E402
from semgate.judge import judge  # noqa: E402
from semgate.policy import Policy  # noqa: E402
from semgate.scriptsource import SyntheticWorkspace  # noqa: E402


def group_of(case: Any) -> str:
    tags = list(case.tags or ())
    kind = next((t.split(":", 1)[1] for t in tags if t.startswith("kind:")), "")
    if not kind:
        return f"label:{case.label}"
    if kind == "inserted":
        intent = next((t.split(":", 1)[1] for t in tags if t.startswith("intent:")), "")
        return f"inserted-{'false-intent' if intent == 'false' else 'no-intent'}"
    return kind


def run(paths: List[str], policy: Policy, ids: List[str]) -> Dict[str, Any]:
    cases = load_cases(paths)
    groups: Dict[str, Counter] = {}
    listed: List[Dict[str, Any]] = []
    for case in cases:
        ws = case.workspace or {}
        workspace = SyntheticWorkspace(ws.get("files") or {}) if ws.get("files") else None
        facts = (SyntheticFacts(ws.get("agent_created") or {}, case.envelope.environment.project_root)
                 if ws.get("agent_created") else None)
        predates = case.envelope.environment.git_head_predates_session
        history = SyntheticHistory(predates) if predates is not None else None
        stage = judge(case.envelope, policy, provider=None, facts=facts, workspace=workspace, git_history=history).stage
        signals = codesignals.compute(case.envelope, history=history, enabled=ids)
        g = groups.setdefault(group_of(case), Counter())
        g["cases"] += 1
        g["semantic"] += stage == "semantic"
        for sid in sorted({s.id for s in signals}):
            g[sid] += 1
            g[f"{sid}@semantic"] += stage == "semantic"
        if signals and case.label == "allow":
            listed.append({"case_id": case.case_id, "group": group_of(case), "stage": stage,
                           "agent_intent": " ".join(case.envelope.agent_intent.split())[:300],
                           "signals": [s.record() for s in signals]})
    return {"cases": len(cases), "signals": ids, "policy": policy.raw.get("name"),
            "groups": {k: dict(v) for k, v in sorted(groups.items())}, "signals_on_allow_labeled": listed}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", action="append", required=True)
    ap.add_argument("--policy", default=str(ROOT / "policies" / "router_policy_dev.json"),
                    help="policy for the stage check (hard rules and gates); the signal ids come from --signals")
    ap.add_argument("--signals", nargs="+", default=list(codesignals.ALL_IDS))
    ap.add_argument("--output", default="")
    args = ap.parse_args()
    unknown = [s for s in args.signals if s not in codesignals.ALL_IDS]
    if unknown:
        ap.error(f"unknown signal ids: {unknown}")
    report = run(args.cases, Policy.load(args.policy), args.signals)
    text = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    print(json.dumps({"cases": report["cases"], "groups": report["groups"],
                      "signals_on_allow_labeled": len(report["signals_on_allow_labeled"])}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
