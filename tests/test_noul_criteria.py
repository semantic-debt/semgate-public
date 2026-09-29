"""Noul criteria (router_policy_dev_crit.json): the policy's true/false
descriptions reach typesafe-sdk's Noul(criteria=...); the fake provider
accepts them; instructions text stays identical to dev."""
import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

from semgate import router
from semgate.eval.runner import evaluate_cases, load_cases
from semgate.policy import Policy
from semgate.providers.base import ProviderError
from semgate.providers.fake import FakeProvider

ROOT = Path(__file__).parents[1]
DEV = Policy.load(str(ROOT / "policies" / "router_policy_dev.json"))
CRIT = Policy.load(str(ROOT / "policies" / "router_policy_dev_crit.json"))
# dev before it adopted the criteria (2026-09-23 (2)); dev_crit was built as this file plus the criteria
BASE = Policy.load(str(ROOT / "policies" / "experiments" / "router_policy_dev_base_2026-09-23.json"))
QS = ("user_asked", "on_task", "instructed_by_context")

spec = importlib.util.spec_from_file_location("gen_nonsense_steps_crit", ROOT / "evals" / "14-gen-nonsense-steps.py")
GEN = importlib.util.module_from_spec(spec)
sys.modules["gen_nonsense_steps_crit"] = GEN
spec.loader.exec_module(GEN)


def test_dev_crit_is_dev_plus_criteria_with_identical_instructions():
    a, b = json.loads(json.dumps(BASE.raw)), json.loads(json.dumps(CRIT.raw))
    for q in QS:
        crit = b["router"]["questions"][q].pop("criteria")
        assert set(crit) == {"true", "false"} and all(len(v) > 40 for v in crit.values())
        assert b["router"]["questions"][q]["instructions"] == a["router"]["questions"][q]["instructions"]
    for raw in (a, b):
        raw.pop("name")
        raw.pop("provenance")
    assert a == b
    assert all("criteria" not in BASE.router["questions"][q] for q in QS)
    # dev adopted the same criteria with the same instructions
    for q in QS:
        assert DEV.router["questions"][q] == CRIT.router["questions"][q], q


def test_criteria_text_is_waf_safe_and_keeps_the_not_evidence_idea():
    texts = [v for q in QS for v in CRIT.router["questions"][q]["criteria"].values()]
    assert GEN.waf_hits(texts) == [] and GEN.PASSWD_PATH not in json.dumps(CRIT.raw)
    assert "`" not in "".join(texts)
    assert "agent_intent" in CRIT.router["questions"]["user_asked"]["criteria"]["false"]
    assert "agent_intent" in CRIT.router["questions"]["on_task"]["criteria"]["false"]
    assert "untrusted" in CRIT.router["questions"]["instructed_by_context"]["criteria"]["true"]


def test_router_questions_pass_criteria_and_reject_bad_keys():
    qs = router.questions(CRIT)
    assert qs["user_asked"]["criteria"]["true"].startswith("A turn of the user")
    bad = json.loads(json.dumps(CRIT.raw))
    bad["router"]["questions"]["user_asked"]["criteria"] = {"yes": "x"}
    with pytest.raises(ValueError):
        router.questions(Policy(bad))
    bad["router"]["questions"]["user_asked"]["criteria"] = {"true": 1}
    with pytest.raises(ValueError):
        router.questions(Policy(bad))


class _Answer:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def _stub_sdk(calls):
    mod = types.ModuleType("typesafe_sdk")

    class Client:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def system_one(self, state, questions, model):
            calls.append(questions)
            answers = {}
            for qid, q in questions.items():
                if q["kind"] == "noul":
                    answers[qid] = _Answer(noul=0.8)
                else:
                    answers[qid] = _Answer(choice="run", score=1.0, confidence=0.9, probabilities={"run": 0.9})
            return _Answer(answers=answers)

    mod.TypeSafeClient = Client
    mod.Noul = lambda **kw: {"kind": "noul", **kw}
    mod.Choice = lambda **kw: {"kind": "choice", **kw}
    mod.Score = lambda **kw: {"kind": "score", **kw}
    return mod


def test_typesafe_provider_forwards_criteria_only_when_set(monkeypatch):
    calls = []
    monkeypatch.setenv("TYPESAFE_API_KEY", "k")
    monkeypatch.setitem(sys.modules, "typesafe_sdk", _stub_sdk(calls))
    from semgate.providers.typesafe import TypeSafeProvider
    provider = TypeSafeProvider()
    provider.evaluate({"command": "ls"}, router.questions(CRIT))
    provider.evaluate({"command": "ls"}, router.questions(BASE))
    provider.evaluate({"command": "ls"}, router.questions(DEV))
    with_crit, without, dev = calls
    assert with_crit["user_asked"]["criteria"] == CRIT.router["questions"]["user_asked"]["criteria"]
    assert "criteria" not in without["user_asked"]                     # no criteria set: exactly what it sent before
    assert without["user_asked"] == {"kind": "noul", "instructions": BASE.router["questions"]["user_asked"]["instructions"]}
    assert "criteria" in with_crit["route"]                             # choice/score criteria unchanged
    for q in QS:                                                        # dev sets them: forwarded
        assert dev[q]["criteria"] == DEV.router["questions"][q]["criteria"] == with_crit[q]["criteria"], q
    with pytest.raises(ProviderError):
        provider.evaluate({"command": "ls"}, {"q": {"type": "noul", "instructions": "x", "criteria": {"maybe": "x"}}})


def test_real_sdk_noul_accepts_criteria():
    sdk = pytest.importorskip("typesafe_sdk")
    q = sdk.Noul(instructions="Is it on task?", criteria={"true": "yes text", "false": "no text"})
    wire = q.model_dump()
    assert wire["criteria"] == {"true": "yes text", "false": "no text"} and wire["type"] == "noul"
    assert "criteria" not in sdk.Noul(instructions="x").model_dump()


def test_fake_and_scripted_providers_accept_criteria():
    answers = FakeProvider({"user_asked": 0.9}).evaluate({"command": "ls"}, router.questions(CRIT))
    assert answers["user_asked"].probability == 0.9
    cases = load_cases([str(ROOT / "fixtures" / "eval" / "injection.jsonl")])
    a = evaluate_cases(cases, CRIT, scripted=True)
    b = evaluate_cases(cases, BASE, scripted=True)
    assert [r["decision"] for r in a["cases"]] == [r["decision"] for r in b["cases"]]
