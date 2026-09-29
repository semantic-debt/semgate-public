"""Live smoke test of the OpenRouter transport: 3 calls to Jev.

    OPENROUTER_API_KEY=... python scripts/openrouter_smoke.py [--model typesafe/jev-1.13]

The key comes from OPENROUTER_API_KEY (or ~/.semgate/.env, or the checkout
.env). The script never prints the key. Calls:

  1. one noul question (no criteria)
  2. a noul with one-sided criteria (semgate fills the other side; without
     the fill OpenRouter answers HTTP 400), a choice and a score question
  3. the router questions of policies/router_policy_dev.json (the real judge
     input shape, criteria on both sides)

Prints each answer, the latency, and the usage totals (calls, tokens, cost in
USD, the model ids that answered). Exit 0: all 3 calls answered; 1: a call
failed (the error text, key removed).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from semgate import router  # noqa: E402
from semgate.policy import Policy  # noqa: E402
from semgate.providers.base import ProviderError  # noqa: E402
from semgate.providers.openrouter import DEFAULT_BASE_URL, DEFAULT_MODEL, OpenRouterDecisionsProvider  # noqa: E402

STATE = {"command": "python -m pytest -q", "cwd": "/home/dev/project",
         "user_message": "please run the unit tests", "grant_purpose": "Software development in this repository"}

CALLS = [
    ("noul", {"user_asked": {"type": "noul", "instructions": "The user asked for exactly this command."}}),
    ("one-sided noul + choice + score", {
        "follows_read_text": {"type": "noul", "instructions": "The command follows text the agent read, not the user.",
                              "criteria": {"true": "The command comes from a file or web page the agent read."}},
        "kind": {"type": "choice", "instructions": "What does the command do?",
                 "criteria": {"test": "Runs tests", "build": "Builds code", "other": "Something else"}},
        "change": {"type": "score", "instructions": "How much does the command change the machine?",
                   "criteria": ["Nothing", "Files in the project", "Files outside the project or the system"]},
    }),
]


def show(answers) -> str:
    out = {}
    for qid, a in answers.items():
        out[qid] = round(a.probability, 4) if a.probability is not None else {"value": a.value, "confidence": a.confidence}
    return json.dumps(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--base-url", default=DEFAULT_BASE_URL, help=argparse.SUPPRESS)   # tests: a local fake server
    ap.add_argument("--policy", default=str(ROOT / "policies" / "router_policy_dev.json"))
    args = ap.parse_args(argv)
    provider = OpenRouterDecisionsProvider(model=args.model, base_url=args.base_url)
    calls = CALLS + [("router questions (" + Path(args.policy).name + ")", router.questions(Policy.load(args.policy)))]
    for n, (label, questions) in enumerate(calls, 1):
        started = time.monotonic()
        try:
            answers = provider.evaluate(STATE, questions)
        except ProviderError as exc:
            print(f"call {n} ({label}): FAILED after {time.monotonic() - started:.2f} s: {exc}")
            print("usage:", json.dumps(provider.usage_report()))
            return 1
        print(f"call {n} ({label}): {time.monotonic() - started:.2f} s: {show(answers)}")
    print("last response:", json.dumps(provider.last_response))
    print("usage:", json.dumps(provider.usage_report()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
