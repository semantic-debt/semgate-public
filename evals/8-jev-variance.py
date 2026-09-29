"""Measure Jev run-to-run variance on the router questions. Read-only; no command runs.

Same cases asked N times, each repeat with a fresh `uid` so the draws are
independent (per the TypeSafe self-consistency cookbook). Reports, per question,
the mean per-case standard deviation of the score, and how often the router's
final decision changes across repeats (decision instability).

Cases are sampled by case_id from a git-ignored benchmark file, so no dataset
command text lives in this script. A fixed seed makes the sample reproducible.
"""
from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from semgate.envelope import Envelope  # noqa: E402
from semgate.policy import Policy  # noqa: E402
from semgate.providers.base import PredicateAnswer  # noqa: E402
from semgate.providers.typesafe import TypeSafeProvider  # noqa: E402
from semgate import router  # noqa: E402


def sample(cases_path: Path, per_label: int, seed: int) -> list:
    rows = [json.loads(l) for l in cases_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    by_label = defaultdict(list)
    for r in rows:
        by_label[r["label"]].append(r)
    rng = random.Random(seed)
    chosen = []
    for label in ("allow", "ask", "deny"):
        pool = by_label.get(label, [])
        chosen += rng.sample(pool, min(per_label, len(pool)))
    return chosen


def scalar(qid: str, answer) -> float:
    # route is a choice; track P(run) so its movement is numeric like the others.
    if qid == "route":
        return float((answer.raw.get("probabilities") or {}).get("run", 0.0))
    if answer.value is not None:
        return float(answer.value)
    return float(answer.probability) if answer.probability is not None else float("nan")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", required=True)
    parser.add_argument("--policy", default=str(ROOT / "policies" / "router_policy_v3.json"))
    parser.add_argument("--reps", type=int, default=10)
    parser.add_argument("--per-label", type=int, default=12)
    parser.add_argument("--seed", type=int, default=20260920)
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    policy = Policy.load(args.policy)
    questions = router.questions(policy)
    provider = TypeSafeProvider()
    cases = sample(Path(args.cases), args.per_label, args.seed)

    per_case = []
    for case in cases:
        envelope = Envelope.from_dict(case["envelope"])
        state = router.build_state(envelope)
        reps = []
        for i in range(args.reps):
            answers = provider.evaluate(dict(state, uid=f"{case['case_id']}#{i}"), questions)
            decision = router.decide(policy, answers)["decision"]
            reps.append({"decision": decision, "scores": {q: scalar(q, a) for q, a in answers.items()}})
        decisions = [r["decision"] for r in reps]
        stds = {q: statistics.pstdev([r["scores"][q] for r in reps]) for q in questions}
        per_case.append({
            "case_id": case["case_id"], "label": case["label"],
            "decisions": dict(Counter(decisions)),
            "decision_stable": len(set(decisions)) == 1,
            "modal_decision": Counter(decisions).most_common(1)[0][0],
            "score_std": {q: round(v, 4) for q, v in stds.items()},
        })

    report = {
        "policy_version": policy.version, "reps": args.reps, "cases": len(cases), "seed": args.seed,
        "mean_score_std": {q: round(statistics.mean(c["score_std"][q] for c in per_case), 4) for q in questions},
        "max_score_std": {q: round(max(c["score_std"][q] for c in per_case), 4) for q in questions},
        "decision_stable_cases": sum(1 for c in per_case if c["decision_stable"]),
        "decision_unstable_cases": [c["case_id"] for c in per_case if not c["decision_stable"]],
        "per_case": per_case,
    }
    print(json.dumps({k: report[k] for k in ("policy_version", "reps", "cases", "mean_score_std", "max_score_std", "decision_stable_cases", "decision_unstable_cases")}, indent=2))
    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
