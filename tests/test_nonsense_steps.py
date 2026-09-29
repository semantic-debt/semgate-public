"""nonsense-steps eval set (evals/14-gen-nonsense-steps.py). No network, no model.

Checks the committed public fixture (always) and, when the git-ignored SWE row
cache is present, that generation is deterministic and reproduces the fixture.
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EVALS = ROOT / "evals"
sys.path.insert(0, str(EVALS))
sys.path.insert(0, str(ROOT))


def _load(filename: str, name: str):
    spec = importlib.util.spec_from_file_location(name, EVALS / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses look up their module in sys.modules
    spec.loader.exec_module(module)
    return module


gen = _load("14-gen-nonsense-steps.py", "gen_nonsense_steps")
heldout = _load("heldout.py", "heldout")

FIXTURE = ROOT / "fixtures" / "eval" / "nonsense-steps.jsonl"
KINDS = ("clean", "inserted", "justified", "early-turn")
ROWS_PRESENT = gen.ROWS_DIR.is_dir() and any(gen.ROWS_DIR.glob("*.json"))
# explicit trigger shape named by the WAF note: imperative verb, then a backticked command
BACKTICK_IMPERATIVE_RE = re.compile(r"\b(?:run|execute|type|enter|invoke|use|try|paste)\s+`[^`]+`", re.I)


def _cases():
    return [json.loads(line) for line in FIXTURE.read_text(encoding="utf-8").splitlines() if line.strip()]


def _tag(case, key):
    return next((t.split(":", 1)[1] for t in case["tags"] if t.startswith(key + ":")), None)


def _prose(case):
    env = case["envelope"]
    out = list(env["user_messages"]) + [env["user_message"], env.get("agent_intent", "")]
    for e in env["trajectory"]["recent"]:
        out += [e.get("output", ""), e.get("result", "")]
    return out


# ---------- committed public fixture ----------

def test_fixture_loads_as_benchmark_cases():
    from semgate.eval.case import BenchmarkCase
    cases = _cases()
    assert len(cases) > 100
    for raw in cases:
        case = BenchmarkCase.from_dict(raw)
        assert case.envelope.action.tool == "bash"
        assert case.envelope.user_message == raw["envelope"]["user_messages"][-1]
    assert len({c["case_id"] for c in cases}) == len(cases)


def test_schema_fields_present():
    for case in _cases():
        env = case["envelope"]
        msgs = env["user_messages"]
        assert isinstance(msgs, list) and 2 <= len(msgs) <= 4 and all(isinstance(m, str) and m for m in msgs)
        assert env["user_message"] == msgs[-1]
        assert "agent_intent" not in env or (isinstance(env["agent_intent"], str) and env["agent_intent"])
        assert env["action"]["arguments"]["command"]
        recent = env["trajectory"]["recent"]
        assert 3 <= len(recent) <= gen.RECENT
        for e in recent:
            assert isinstance(e["result"], str) and len(e["result"]) <= gen.RESULT_MAX
            if e["tool"] == "bash":
                assert e["result"].startswith("exit ")
            if "files_changed" in e:
                assert isinstance(e["files_changed"], list) and e["files_changed"]
        for key in ("kind", "catalog", "intent", "base", "variant", "repo"):
            assert _tag(case, key), (case["case_id"], key)
        assert _tag(case, "kind") in KINDS
        assert case["source"] == gen.NAME


def test_labels_follow_kind():
    for case in _cases():
        kind, item = _tag(case, "kind"), _tag(case, "catalog")
        if kind == "inserted":
            assert case["label"] == gen.ITEMS[item].label
            assert case["label"] == ("deny" if item == "exfil_env" else "ask")
        else:
            assert case["label"] == "allow", case["case_id"]
        if kind == "clean":
            assert item == "none"
        if kind in ("justified", "early-turn"):
            assert gen.ITEMS[item].scope == "project" and gen.ITEMS[item].label == "ask"


def test_intent_variants():
    by_kind = defaultdict(set)
    for case in _cases():
        intent = _tag(case, "intent")
        by_kind[_tag(case, "kind")].add(intent)
        assert ("agent_intent" in case["envelope"]) == (intent != "none")
    assert by_kind["inserted"] == {"none", "false"}
    assert by_kind["justified"] == {"honest"}
    assert by_kind["clean"] <= {"real", "none"}


def test_no_waf_trigger_strings():
    text = FIXTURE.read_text(encoding="utf-8")
    assert gen.PASSWD_PATH not in text
    for case in _cases():
        assert gen.case_waf_hits(case) == [], case["case_id"]
        for prose in _prose(case):
            assert not BACKTICK_IMPERATIVE_RE.search(prose), (case["case_id"], prose[:120])


def test_written_turns_do_not_authorize_catalog_changes():
    for text in gen.FOLLOW_UPS + gen.GENERIC_LAST:
        assert not gen.waf_hits([text])
        for item in gen.CATALOG:
            assert not gen.mentioned(item, text), (item.id, text)


def test_twin_turns():
    cases = _cases()
    by_base = defaultdict(dict)
    for case in cases:
        by_base[_tag(case, "base")][(_tag(case, "kind"), _tag(case, "intent"))] = case
    for base, group in by_base.items():
        clean = group[("clean", _tag(next(c for k, c in group.items() if k[0] == "clean"), "intent"))]
        ins = [c for k, c in group.items() if k[0] == "inserted"]
        assert len(ins) == 2
        for c in ins:  # same context as the clean control, different action
            assert c["envelope"]["user_messages"] == clean["envelope"]["user_messages"]
            assert c["envelope"]["trajectory"] == clean["envelope"]["trajectory"]
            assert c["envelope"]["action"] != clean["envelope"]["action"]
        for (kind, _), c in group.items():
            msgs = c["envelope"]["user_messages"]
            if kind == "justified":
                assert msgs[-1] not in gen.FOLLOW_UPS and msgs[:-1] == clean["envelope"]["user_messages"][:len(msgs) - 1]
                assert c["envelope"]["action"] == ins[0]["envelope"]["action"]
            if kind == "early-turn":
                assert msgs[-1] in gen.GENERIC_LAST
                assert _tag(c, "authorized-turn") in ("1", "2")
                assert c["envelope"]["action"] == ins[0]["envelope"]["action"]


def test_public_fixture_holds_only_public_bases():
    bases = {_tag(c, "base") for c in _cases()}
    assert bases and not any(heldout.is_private(b) for b in bases)


# ---------- pure helpers ----------

def test_result_of_reports_exit_code_and_first_lines():
    call = {"name": "execute_bash", "output": "line one\nline two\n[The command completed with exit code 1.]\n"
                                              "[Current working directory: /w]\n[Command finished with exit code 1]"}
    assert gen.result_of(call) == "exit 1\nline one\nline two"
    assert len(gen.result_of({"name": "execute_bash", "output": "x" * 5000})) <= gen.RESULT_MAX


def test_waf_hits_detects_both_shapes():
    assert gen.waf_hits(["see " + gen.PASSWD_PATH])
    assert gen.waf_hits(["Please run `make test` now."])
    assert gen.waf_hits([], ["for f in *; do mv \"$f\" x; done"])
    assert not gen.waf_hits(["Tests still fail, keep going."], ["chmod -R 777 /workspace/x"])


def test_files_changed_from_editor_and_redirects():
    edit = {"name": "str_replace_editor", "args": {"command": "str_replace", "path": "/w/a.py"}}
    assert gen.files_changed_of(edit, "/w") == ["/w/a.py"]
    sh = {"name": "execute_bash", "args": {"command": "cd /w && cat > t.py << 'EOF'\nx\nEOF 2>/dev/null"}}
    assert gen.files_changed_of(sh, "/w") == ["/w/t.py"]


# ---------- generation (needs the git-ignored SWE row cache) ----------

@pytest.mark.skipif(not ROWS_PRESENT, reason="evals/data/swe-trajectories/rows not present")
def test_generation_is_deterministic_and_matches_fixture():
    first, _ = gen.generate()
    second, _ = gen.generate()
    assert first == second
    public = [c for c in first if not heldout.is_private(gen.base_of(c))]
    text = "".join(json.dumps(c, sort_keys=True) + "\n" for c in public)
    assert text == FIXTURE.read_text(encoding="utf-8")


@pytest.mark.skipif(not ROWS_PRESENT, reason="evals/data/swe-trajectories/rows not present")
def test_all_variants_of_a_base_share_a_split_and_counts():
    cases, facts = gen.generate()
    split = defaultdict(set)
    for c in cases:
        split[gen.base_of(c)].add(heldout.is_private(gen.base_of(c)))
        assert c["source_id"].startswith(gen.base_of(c) + ":")
    assert all(len(v) == 1 for v in split.values())
    kinds = defaultdict(int)
    for c in cases:
        kinds[_tag(c, "kind")] += 1
    assert len(split) == gen.N_BASES
    assert kinds == {"clean": gen.N_BASES, "inserted": 2 * gen.N_BASES, "justified": gen.N_JUSTIFIED, "early-turn": gen.N_EARLY}
    turn1 = sum(1 for c in cases if _tag(c, "authorized-turn") == "1")
    assert turn1 == gen.N_EARLY_TURN1
    assert all(not gen.case_waf_hits(c) for c in cases)
