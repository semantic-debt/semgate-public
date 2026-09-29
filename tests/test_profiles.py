"""Work kinds: a session can cover several kinds of work; the purpose is composed
from all of them; a model allow on an unrequested kind becomes an ask with an
explanation; hard scope is untouched."""
import json

import pytest

from semgate import profiles
from semgate.adapters.antigravity import first_user_request, user_requests
from semgate.envelope import UserGrant
from semgate.providers.fake import FakeProvider

TABLE = profiles.load_profiles()
KINDS = list(TABLE.kinds)


class Scripted(FakeProvider):
    """Answers kind questions per message/command from a dict; counts calls."""
    calls = 0

    def __init__(self, by_request=None, by_command=None):
        super().__init__({})
        self.by_request, self.by_command = by_request or {}, by_command or {}

    def evaluate(self, state, questions):
        Scripted.calls += 1
        from semgate.providers.base import PredicateAnswer
        if "user_request" in state:
            want = self.by_request.get(state["user_request"], {})
            return {k: PredicateAnswer(predicate_id=k, probability=float(want.get(k, 0.02)), confidence=0.9) for k in questions}
        kind, conf = self.by_command.get(state["command"], ("general", 0.9))
        return {"kind": PredicateAnswer(predicate_id="kind", value=kind, confidence=conf)}


def test_table_loads_all_kinds_with_structured_fields():
    assert {"software-development", "automation", "ml-experiments", "document-processing", "media-understanding",
            "code-review", "data-analysis", "web-research", "devops"} <= set(KINDS)
    assert TABLE.base_restrictions and all(k["authorized"] for k in TABLE.kinds.values())
    assert TABLE.kinds["devops"]["sensitive"] is True
    assert all(k["allowed_domains"] == [] for k in TABLE.kinds.values())


def test_several_kinds_become_active_and_later_messages_add_more(tmp_path):
    cfg = {"state_file": str(tmp_path / "s.json")}
    p = Scripted(by_request={"research rate limiting then implement it": {"web-research": 0.97, "software-development": 0.97},
                             "now deploy it to staging": {"devops": 0.99}})
    Scripted.calls = 0
    k1 = profiles.session_kinds(cfg, session_id="c1", messages=["research rate limiting then implement it"], provider=p, table=TABLE)
    assert set(k1.active) == {"web-research", "software-development"} and k1.source == "classified"
    k2 = profiles.session_kinds(cfg, session_id="c1", messages=["research rate limiting then implement it", "now deploy it to staging"],
                                provider=p, table=TABLE)
    assert set(k2.active) == {"web-research", "software-development", "devops"}
    assert Scripted.calls == 2          # the first message was cached, only the new one was classified


def test_sensitive_kind_needs_a_higher_probability(tmp_path):
    p = Scripted(by_request={"m": {"software-development": 0.9, "devops": 0.7}})
    k = profiles.session_kinds({}, session_id="", messages=["m"], provider=p, table=TABLE)
    assert k.active == ("software-development",)     # devops 0.7 < 0.85


def test_override_and_default():
    k = profiles.session_kinds({"override": ["devops", "data-analysis"]}, session_id="s", messages=["x"], provider=None, table=TABLE)
    assert set(k.active) == {"devops", "data-analysis"} and k.source == "override"
    assert profiles.session_kinds({}, session_id="s", messages=[], provider=None, table=TABLE).active == ("software-development",)
    none_asked = Scripted(by_request={"hello": {}})
    assert profiles.session_kinds({}, session_id="", messages=["hello"], provider=none_asked, table=TABLE).source == "default"


def test_purpose_combines_kinds_and_drops_conflicting_own_restrictions():
    single = profiles.SessionKinds({"code-review": 1.0}, ("code-review",), "classified", ("review this, don't change anything",))
    text = profiles.compose_purpose(TABLE, single)
    assert "editing, creating or deleting project files" in text          # review's own restriction applies alone
    assert "don't change anything" in text
    both = profiles.SessionKinds({}, ("software-development", "code-review"), "classified", ("review the PR and fix the bugs",))
    text2 = profiles.compose_purpose(TABLE, both)
    assert "editing, creating or deleting project files" not in text2       # would contradict dev's authorization
    assert TABLE.base_restrictions in text2 and "This session covers: Software development, Code review or audit" in text2


def test_apply_adds_kind_domains_and_keeps_hard_scope(tmp_path):
    data = json.loads(open(profiles.policy_dir() / "profiles.json", encoding="utf-8").read())
    data["profiles"]["devops"]["allowed_domains"] = ["staging.myapp.com"]
    f = tmp_path / "p.json"; f.write_text(json.dumps(data), encoding="utf-8")
    table = profiles.load_profiles(str(f))
    g = UserGrant(grant_id="g", principal="m", purpose="static", forbidden_patterns=("SENTINEL",),
                  allowed_domains=("api.example.com",), expires_at="2099-01-01T00:00:00Z", provenance="hand")
    kinds = profiles.SessionKinds({}, ("software-development", "devops"), "classified", ("fix then deploy",))
    g2 = profiles.apply(g, kinds, table)
    assert g2.allowed_domains == ("api.example.com", "staging.myapp.com") and g2.forbidden_patterns == ("SENTINEL",)
    assert "domains from kinds: staging.myapp.com" in g2.provenance and g2.purpose.startswith("This session covers")
    # a kind that is not active adds nothing
    assert profiles.apply(g, profiles.SessionKinds({}, ("software-development",), "classified", ()), table).allowed_domains == ("api.example.com",)


def test_bad_domains_rejected(tmp_path):
    data = json.loads(open(profiles.policy_dir() / "profiles.json", encoding="utf-8").read())
    for bad in ["*", "*.com", "https://staging.myapp.com", "staging.myapp.com/api", "staging.myapp.com:22", "com"]:
        data["profiles"]["devops"]["allowed_domains"] = [bad]
        f = tmp_path / "p.json"; f.write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises(ValueError):
            profiles.load_profiles(str(f))


def test_command_kind_check(tmp_path):
    cfg = {"state_file": str(tmp_path / "s.json")}
    kinds = profiles.SessionKinds({}, ("software-development", "web-research"), "classified", ("research then implement",))
    p = Scripted(by_command={"ssh deploy@staging \"systemctl restart app\"": ("devops", 0.95), "pytest -q": ("software-development", 0.9),
                             "ls -la": ("general", 0.9)})
    assert profiles.check_command("pytest -q", cfg, session_id="c", kinds=kinds, provider=p, table=TABLE).requested
    assert profiles.check_command("ls -la", cfg, session_id="c", kinds=kinds, provider=p, table=TABLE).requested
    c = profiles.check_command("ssh deploy@staging \"systemctl restart app\"", cfg, session_id="c", kinds=kinds, provider=p, table=TABLE)
    assert not c.requested and c.kind == "devops" and "DevOps and deployment work" in c.message and "Software development" in c.message
    Scripted.calls = 0
    profiles.check_command("pytest -q", cfg, session_id="c", kinds=kinds, provider=p, table=TABLE)
    assert Scripted.calls == 0          # cached per session + exact command
    assert profiles.check_command("x", cfg, session_id="c", kinds=kinds, provider=None, table=TABLE) is None


def test_user_requests_reads_all_explicit_user_messages(tmp_path):
    t = tmp_path / "transcript.jsonl"
    t.write_text("\n".join([
        json.dumps({"type": "SYSTEM_MESSAGE", "source": "SYSTEM", "content": "<USER_REQUEST>not the user</USER_REQUEST>"}),
        json.dumps({"type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "<USER_REQUEST>\nTranslate docs to Spanish\n</USER_REQUEST>"}),
        json.dumps({"type": "PLANNER_RESPONSE", "source": "MODEL", "tool_calls": []}),
        json.dumps({"type": "USER_INPUT", "source": "USER_EXPLICIT", "content": "<USER_REQUEST>\nnow also the README\n</USER_REQUEST>"}),
    ]), encoding="utf-8")
    assert user_requests(str(t)) == ["Translate docs to Spanish", "now also the README"]
    assert first_user_request(str(t)) == "Translate docs to Spanish" and user_requests(None) == []


def _hook_config(tmp_path, answers):
    grant = tmp_path / "grant.json"
    grant.write_text(json.dumps({"grant_id": "g", "principal": "m", "purpose": "static", "expires_at": "2099-01-01T00:00:00Z"}))
    return {"mode": "enforce", "grant_file": str(grant), "policy_file": str(profiles.policy_dir() / "router_policy_dev.json"),
            "provider": "fake", "ledger_file": str(tmp_path / "ledger.jsonl"), "fake_answers": answers,
            "enforcement": {"enabled": True, "auto_allow_tools": ["bash"], "block_when_unsure": False},
            "profiles": {"enabled": True, "state_file": str(tmp_path / "kinds.json")}}


def _event(tmp_path, cmd, message):
    t = tmp_path / "transcript.jsonl"
    t.write_text(json.dumps({"type": "USER_INPUT", "source": "USER_EXPLICIT", "content": f"<USER_REQUEST>\n{message}\n</USER_REQUEST>"}) + "\n", encoding="utf-8")
    return {"toolCall": {"name": "run_command", "args": {"CommandLine": cmd}}, "conversationId": "conv", "workspacePaths": [str(tmp_path)],
            "transcriptPath": str(t)}


ALLOWING = {"route": {"value": "run", "confidence": 1.0}, "effect": {"value": 0.0, "confidence": 1.0}, "user_asked": 0.9,
            "on_task": 0.9, "instructed_by_context": 0.05, "executes": {"value": 0.0, "confidence": 1.0}}


def test_hook_asks_with_explanation_when_the_kind_was_not_requested(tmp_path):
    from semgate.antigravity_hook import run
    answers = {**ALLOWING, **{k: 0.02 for k in KINDS}, "software-development": 0.95, "kind": {"value": "devops", "confidence": 0.95}}
    result = run(_event(tmp_path, "kubectl get pods -n api", "fix the failing test"), _hook_config(tmp_path, answers))
    assert result["decision"] == "force_ask" and "unrequested_kind:devops" in result["reason"]
    assert "you asked for: Software development" in result["reason"]


def test_hook_allows_when_the_kind_was_requested_and_records_the_composed_purpose(tmp_path):
    from semgate.antigravity_hook import run
    answers = {**ALLOWING, **{k: 0.02 for k in KINDS}, "software-development": 0.95, "devops": 0.97, "kind": {"value": "devops", "confidence": 0.95}}
    config = _hook_config(tmp_path, answers)
    result = run(_event(tmp_path, "kubectl get pods -n api", "fix the bug then check the pods in staging"), config)
    assert result["decision"] == "allow"
    rec = [json.loads(l) for l in (tmp_path / "ledger.jsonl").read_text(encoding="utf-8").splitlines() if '"judgment"' in l][-1]
    purpose = rec["envelope"]["grant"]["purpose"]
    assert purpose.startswith("This session covers: Software development") and "DevOps" in purpose
    assert "fix the bug then check the pods in staging" in purpose


def test_hook_kind_check_never_touches_a_deny_or_gate(tmp_path):
    from semgate.antigravity_hook import run
    answers = {**ALLOWING, **{k: 0.02 for k in KINDS}, "software-development": 0.95, "kind": {"value": "devops", "confidence": 0.95}}
    assert run(_event(tmp_path, "rm -rf /", "fix the test"), _hook_config(tmp_path, answers))["decision"] == "deny"
    r = run(_event(tmp_path, "cat ~/.ssh/id_rsa", "fix the test"), _hook_config(tmp_path, answers))
    assert r["decision"] == "force_ask" and "unrequested_kind" not in r["reason"]
