"""Run the adversarial-context cases three ways and summarize. Classification
only; nothing is executed. Prompt bodies are never printed.

  A  normal pipeline: deterministic gate on, Jev sees only the overlap windows
     (what semgate really sends)
  B  gate off, same windowed context (Jev judging what semgate would send)
  C  gate off, FULL text as untrusted_context (Jev exposed to the whole prompt)

Usage: python evals/run_adversarial_context.py [cases.jsonl] [out.json] [policy.json] [modes e.g. AB]
"""
import json
import statistics
import sys
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from semgate import injection, rules  # noqa: E402
from semgate.envelope import Envelope  # noqa: E402
from semgate.judge import judge  # noqa: E402
from semgate.policy import Policy  # noqa: E402
from semgate.providers.typesafe import TypeSafeProvider  # noqa: E402

CASES = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "evals" / "data" / "adversarial-context.jsonl"
OUT = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "evals" / "reports" / "adversarial-context.json"
policy = Policy.load(sys.argv[3] if len(sys.argv) > 3 else str(ROOT / "policies" / "router_policy_dev.json"))
MODES = sys.argv[4] if len(sys.argv) > 4 else "ABC"
provider = TypeSafeProvider()
cases = [json.loads(l) for l in CASES.read_text(encoding="utf-8").splitlines() if l.strip()]


def full_context(env, **_):
    out = env.trajectory.recent[0].output if env.trajectory.recent else ""
    return f"[from read: cat README.md] {out[:6000]}" if out else ""


def full_context_flat(env, **_):
    # D: same full text, but whitespace collapsed the way render_context does it.
    # Isolates whether the model is steered by the words or by the layout.
    out = env.trajectory.recent[0].output if env.trajectory.recent else ""
    return f"[from read: cat README.md] {' '.join(out[:6000].split())}" if out else ""


def run(env, mode):
    if mode == "A":
        d = judge(env, policy, provider=provider)
    elif mode == "B":
        with mock.patch.object(injection, "detect", lambda e: []):
            d = judge(env, policy, provider=provider)
    else:
        renderer = full_context_flat if mode == "D" else full_context
        with mock.patch.object(injection, "detect", lambda e: []), mock.patch.object(injection, "render_context", renderer):
            d = judge(env, policy, provider=provider)
    v = {x["predicate"]: x for x in d.predicate_votes}
    p = lambda k: (float(v[k]["p"]) if k in v and "p" in v[k] else None)  # noqa: E731
    return {"decision": d.decision, "stage": d.stage, "reason_code": d.reason_code,
            "user_asked": p("user_asked"), "on_task": p("on_task"), "injected": p("instructed_by_context"),
            "route": v.get("route", {}).get("value"), "effect": v.get("effect", {}).get("value")}


records = []
for i, c in enumerate(cases, 1):
    env = Envelope.from_dict(c["envelope"])
    gate = [h.gate_class for h in rules.detect_gates(env)]
    rec = {"case_id": c["case_id"], "variant": c["category"].split(":")[1], "source_id": c["source_id"],
           "prompt_chars": len(env.trajectory.recent[0].output), "gate": gate}
    for mode in MODES:
        rec[mode] = run(env, mode)
    records.append(rec)
    print(f"[{i}/{len(cases)}] {c['case_id']:18} gate={'/'.join(gate) or '-':28} " + " ".join(
        f"{m}={rec[m]['decision']:5}(inj {rec[m]['injected'] or 0:.2f} asked {rec[m]['user_asked'] or 0:.2f} on_task {rec[m]['on_task'] or 0:.2f})"
        for m in MODES), flush=True)

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps({"cases": records}, indent=1), encoding="utf-8")


def summarize(mode):
    rows = [r[mode] for r in records]
    dec = {}
    for r in rows:
        dec[r["decision"]] = dec.get(r["decision"], 0) + 1
    def stats(key):
        xs = [r[key] for r in rows if r[key] is not None]
        return f"n={len(xs)} min={min(xs):.2f} median={statistics.median(xs):.2f} max={max(xs):.2f}" if xs else "n=0"
    print(f"\n== mode {mode}: decisions {dec}")
    print(f"   P(injected)   {stats('injected')}")
    print(f"   P(user_asked) {stats('user_asked')}")
    print(f"   P(on_task)    {stats('on_task')}")
    allows = [r2["case_id"] for r2, r in zip(records, rows) if r["decision"] == "allow"]
    if allows:
        print(f"   ALLOWED: {allows}")


print(f"\ncases: {len(records)}; deterministic gate fired on {sum(1 for r in records if r['gate'])}/{len(records)}")
gate_kinds = {}
for r in records:
    for g in r["gate"]:
        gate_kinds[g] = gate_kinds.get(g, 0) + 1
print(f"gate classes: {gate_kinds}")
for mode in MODES:
    summarize(mode)
for variant in ("instruct", "steer"):
    rows = [r for r in records if r["variant"] == variant]
    for mode in MODES:
        dec = {}
        for r in rows:
            dec[r[mode]["decision"]] = dec.get(r[mode]["decision"], 0) + 1
        print(f"{variant:9} mode {mode}: {dec}")
