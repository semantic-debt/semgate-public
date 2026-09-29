"""Approval by chat reply, three outcomes on one probability (owner
decision 2026-09-29, semgate/chatapproval.py): allow once (the record is
removed), clarify (the deny stays, the record is kept, the agent asks one
clear yes/no question), declined; a provider error, a timeout or no provider
is "unchecked", never "declined". Ledger records carry the outcome and p,
never the user's text."""
import json
import time
from pathlib import Path

from semgate import chatapproval as ca, serve
from semgate.judge import Decision
from semgate.policy import Policy

ROOT = Path(__file__).resolve().parents[1]
DEV = ROOT / "policies" / "router_policy_dev.json"
Q = ca.QUESTION
T0 = 1_790_000_000.0
CMD = "python scripts/migrate.py --apply"
ASKING = {"route": {"value": "review", "confidence": 0.7, "probabilities": {"run": 0.2, "review": 0.7, "block": 0.1}},
          "effect": {"value": 2.0, "confidence": 0.8}, "user_asked": 0.5}


# ------------------------------------------------------------------ C. three chat outcomes


def test_outcome_for_uses_two_thresholds_on_one_probability():
    assert [ca.outcome_for(p, 0.85, 0.15) for p in (0.97, 0.85, 0.84, 0.5, 0.15, 0.149, 0.02)] == \
        ["allow", "allow", "clarify", "clarify", "clarify", "declined", "declined"]
    assert ca.outcome_for(0.5, 0.85, None) == "declined"                  # no clarify threshold: no band
    pol = Policy.load(str(DEV))
    assert ca.threshold(pol) == 0.85 and ca.clarify_threshold(pol) == 0.15


def _v1(*extra):
    msgs = [{"info": {"id": "m1", "role": "user", "time": {"created": T0 * 1000 - 60000}},
             "parts": [{"type": "text", "text": "run the database migration"}]},
            {"info": {"id": "m2", "role": "assistant", "time": {"created": T0 * 1000 - 50000}},
             "parts": [{"type": "text", "text": "Running it."},
                       {"type": "tool", "tool": "bash", "callID": "c1", "state": {"status": "error", "input": {"command": CMD},
                                                                                "error": "semgate needs a human decision"}}]}]
    return msgs + list(extra)


def _agent(mid, text, at):
    return {"info": {"id": mid, "role": "assistant", "time": {"created": int((T0 + at) * 1000)}},
            "parts": [{"type": "text", "text": text}]}


def _user(mid, text, at):
    return {"info": {"id": mid, "role": "user", "time": {"created": int((T0 + at) * 1000)}},
            "parts": [{"type": "text", "text": text}]}


def _req(messages, call):
    return {"tool": "bash", "args": {"command": CMD}, "sessionID": "ses1", "callID": call, "cwd": "/p", "messages": messages}


def _cfg(tmp_path, p, p_no=None):
    """The dev policy asks both questions in one call (2026-09-29): P_yes = p,
    P_no = p_no (default: 0.95 for a low p, as a clear no, else 0.02)."""
    grant = tmp_path / "grant.json"
    grant.write_text(json.dumps({"grant_id": "g", "principal": "p", "purpose": "Software development in this project",
                                 "expires_at": "2099-01-01T00:00:00Z"}))
    p_no = (0.95 if p < 0.15 else 0.02) if p_no is None else p_no
    return {"mode": "enforce", "grant_file": str(grant), "policy_file": str(DEV), "provider": "fake",
            "fake_answers": dict(ASKING, **{Q: p, ca.DECLINE_QUESTION: p_no}),
            "ledger_file": str(tmp_path / "state" / "ledger.jsonl"),
            "enforcement": {"enabled": True, "auto_allow_tools": ["bash", "read"], "block_when_unsure": False}}


def _blocks(tmp_path):
    files = list((tmp_path / "state" / "chat_approvals").glob("*.json"))
    assert len(files) == 1
    return json.loads(files[0].read_text(encoding="utf-8"))["blocks"]


def _events(tmp_path):
    rows = [json.loads(x) for x in (tmp_path / "state" / "ledger.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]
    return [(r["event"], r["detail"]) for r in rows if r.get("record_type") == "chat_approval"]


def _first_block(tmp_path, monkeypatch, cfg):
    monkeypatch.setattr(time, "time", lambda: T0)
    first = serve.judge_request("opencode", _req(_v1(), "c1"), cfg)
    assert first["decision"] == "ask" and first["reason"].startswith(ca.HINT)
    (key, rec), = _blocks(tmp_path).items()
    return key, rec


def test_clear_yes_allows_once_and_removes_the_record(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, 0.95)
    _first_block(tmp_path, monkeypatch, cfg)
    msgs = _v1(_agent("m3", "semgate blocked the migration. Shall I run it?", 5), _user("m4", "yeah okay, makes sense", 60))
    monkeypatch.setattr(time, "time", lambda: T0 + 90)
    out = serve.judge_request("opencode", _req(msgs, "c2"), cfg)
    assert out["decision"] == "allow" and "[chat_approved]" in out["reason"]
    assert _blocks(tmp_path) == {}                                        # consumed
    event, detail = _events(tmp_path)[-1]
    assert event == "approved" and detail["outcome"] == "allow" and detail["p"] == 0.95
    assert "yeah okay" not in json.dumps(_events(tmp_path))               # never the user's text


def test_unclear_reply_clarifies_keeps_the_record_and_a_later_yes_approves(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, 0.5)
    key, rec = _first_block(tmp_path, monkeypatch, cfg)
    msgs = _v1(_agent("m3", "semgate blocked the migration. Shall I run it?", 5), _user("m4", "hmm, what does it do?", 60))
    monkeypatch.setattr(time, "time", lambda: T0 + 90)
    out = serve.judge_request("opencode", _req(msgs, "c2"), cfg)
    assert out["decision"] == "ask"                                      # OpenCode refuses it: still blocked
    assert out["reason"].startswith("semgate chat approval: the user's reply is not a clear yes or no")
    assert f"Do you approve running exactly `{CMD}` in `/p`? Please answer yes or no." in out["reason"]
    assert "\u2014" not in out["reason"] and "\u2013" not in out["reason"]
    kept = _blocks(tmp_path)[key]
    assert kept["block_id"] == rec["block_id"] and kept["ts"] == rec["ts"] and kept["last_outcome"] == "clarify"
    assert kept["anchor"] != rec["anchor"]                               # the unclear reply is never judged again
    event, detail = _events(tmp_path)[-1]
    assert event == "not_approved" and detail["outcome"] == "clarify" and detail["p"] == 0.5
    # a retry with no new user turn repeats the question, it does not ask the judge
    monkeypatch.setattr(time, "time", lambda: T0 + 100)
    again = serve.judge_request("opencode", _req(msgs, "c3"), cfg)
    assert again["reason"].startswith("semgate chat approval: the user's reply is not a clear yes or no")
    assert _events(tmp_path)[-2][0] == "code_rejected"
    # the clear question, then a clear yes: approved once
    msgs = msgs + [_agent("m5", f"Do you approve running exactly `{CMD}` in `/p`? Please answer yes or no.", 110),
                   _user("m6", "yes", 150)]
    cfg["fake_answers"][Q] = 0.97
    monkeypatch.setattr(time, "time", lambda: T0 + 180)
    out = serve.judge_request("opencode", _req(msgs, "c4"), cfg)
    assert out["decision"] == "allow"
    event, detail = _events(tmp_path)[-1]
    assert event == "approved" and detail["outcome"] == "allow" and detail["user_turns_sha"] == ca.text_sha("yes")
    assert _blocks(tmp_path) == {}


def test_clear_no_is_declined_and_stays_declined_on_a_retry(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, 0.02)
    key, rec = _first_block(tmp_path, monkeypatch, cfg)
    msgs = _v1(_agent("m3", "Shall I run it?", 5), _user("m4", "no, stop", 60))
    monkeypatch.setattr(time, "time", lambda: T0 + 90)
    out = serve.judge_request("opencode", _req(msgs, "c2"), cfg)
    assert out["decision"] == "ask" and out["reason"].startswith(ca.DECLINED_NOTE)
    assert "did not approve" in out["reason"] and "Do not run it again" in out["reason"]
    assert _blocks(tmp_path)[key]["last_outcome"] == "declined"
    assert _events(tmp_path)[-1][1]["outcome"] == "declined"
    monkeypatch.setattr(time, "time", lambda: T0 + 100)                  # the agent retries anyway, no new user turn
    again = serve.judge_request("opencode", _req(msgs, "c3"), cfg)
    assert again["reason"].startswith(ca.DECLINED_NOTE) and not again["reason"].startswith(ca.HINT)


def test_provider_error_is_unchecked_not_declined_and_keeps_the_record(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, 0.95)
    key, rec = _first_block(tmp_path, monkeypatch, cfg)
    msgs = _v1(_agent("m3", "Shall I run it?", 5), _user("m4", "all right, continue", 60))
    real = ca.ask_judge_all                                              # dev asks both questions in one call
    monkeypatch.setattr(ca, "ask_judge_all", lambda *a, **k: (None, "provider error: ProviderError"))
    monkeypatch.setattr(time, "time", lambda: T0 + 90)
    out = serve.judge_request("opencode", _req(msgs, "c2"), cfg)
    assert out["decision"] == "ask"
    assert out["reason"].startswith("semgate chat approval: semgate could not check the user's reply (provider error")
    assert "This is not a no from the user" in out["reason"] and "feedback allow" in out["reason"]
    assert "did not approve" not in out["reason"]
    assert _blocks(tmp_path)[key] == rec                                  # unchanged: the same reply counts later
    event, detail = _events(tmp_path)[-1]
    assert event == "not_approved" and detail["outcome"] == "unchecked" and detail["p"] is None
    monkeypatch.setattr(ca, "ask_judge_all", real)                       # the judge answers again
    monkeypatch.setattr(time, "time", lambda: T0 + 120)
    assert serve.judge_request("opencode", _req(msgs, "c3"), cfg)["decision"] == "allow"


def test_try_approve_reports_each_outcome(tmp_path):
    pol = Policy.load(str(DEV))
    conv0 = ca.Conversation((ca.Item("user", "run the migration", T0 - 60, msg_id="u1"), ca.Item("call", "bash", T0 - 5, call_id="k")),
                            complete=True, timestamps=True, source="t")
    later = ca.Conversation(conv0.items + (ca.Item("user", "maybe", T0 + 60, msg_id="u2"),), complete=True, timestamps=True,
                            source="t")

    class P:
        def __init__(self, p, fail=False):
            self.p, self.fail = p, fail

        def evaluate(self, state, questions):
            if self.fail:
                raise RuntimeError("down")
            from semgate.providers.base import PredicateAnswer
            return {q: PredicateAnswer(q, probability=self.p) for q in questions}

    for provider, want in ((P(0.9), "allow"), (P(0.4), "clarify"), (P(0.05), "declined"), (P(0, fail=True), "unchecked"),
                           (None, "unchecked")):
        st = ca.Store(tmp_path / f"{want}-{id(provider)}.json", ttl_s=1800)
        ca.record_block(st, "k1", conv0, call_id="k", tool="bash", command=CMD, cwd="/p", reason="r", reason_code="x",
                        stage="semantic", judgment_id="j", now=T0)
        out = ca.try_approve(st, "k1", later, blocked_action=CMD, provider=provider, q=ca.question(pol),
                             min_p=ca.threshold(pol), lim=ca.limits(pol), now=T0 + 120, clarify_p=ca.clarify_threshold(pol))
        assert out.outcome == want and out.approved is (want == "allow")
        assert (st.current("k1", T0 + 120) is None) is (want == "allow")   # only an allow consumes the block


def test_report_lists_the_outcomes(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path, 0.5)
    _first_block(tmp_path, monkeypatch, cfg)
    msgs = _v1(_agent("m3", "Shall I run it?", 5), _user("m4", "ok but first explain", 60))
    monkeypatch.setattr(time, "time", lambda: T0 + 90)
    serve.judge_request("opencode", _req(msgs, "c2"), cfg)
    from semgate import report
    rep = report.build(cfg["ledger_file"])
    assert rep["chat_approvals"]["outcomes"] == {"clarify": 1}
    text = report.render(rep)
    assert "judged replies: clarify 1" in text and "first explain" not in text


def test_never_approvable_rules_are_unchanged():
    config = {"mode": "enforce", "enforcement": {"enabled": True, "block_when_unsure": True}}
    for sem in (Decision("deny", stage="hard_rules", reason_code="hard_deny"),
                Decision("deny", stage="semantic", reason_code="misaligned_unrequested_deny"),
                Decision("deny", stage="human_blocked"),
                Decision("ask", stage="grant_validity"),
                Decision("ask", stage="human_gate", reason_code="human_gate:untrusted_instruction",
                         gate_hits=[{"gate_class": "untrusted_instruction", "matched": "x"}])):
        assert ca.approvable(sem, "deny", "force_ask", config, host_shows_ask=False)[0] is False
    assert ca.approvable(Decision("ask", stage="semantic"), "deny", "force_ask", config, host_shows_ask=False,
                         store_trouble=True)[0] is False


# ------------------------------------------------------------------ the second question (user_declined_blocked_action)


CANDIDATE = ROOT / "policies" / "router_policy_dev_chatdecline.json"
NO = ca.DECLINE_QUESTION


def test_outcome_for_with_the_second_question():
    f = ca.outcome_for
    assert f(0.95, 0.85, 0.15, p_no=0.02, decline_p=0.5) == "allow"
    assert f(0.95, 0.85, 0.15, p_no=0.9, decline_p=0.5) == "declined"      # a clear no wins over P_yes
    assert f(0.03, 0.85, 0.15, p_no=0.05, decline_p=0.5) == "clarify"      # neither: ask one clear question
    assert f(0.03, 0.85, 0.15, p_no=0.95, decline_p=0.5) == "declined"
    pol = Policy.load(str(CANDIDATE))       # 0.85: from the one live run (EVALS.md 2026-09-29)
    assert ca.decline_threshold(pol) == 0.85 and ca.threshold(pol) == 0.85


class _Both:
    """Answers both questions; records every call's question ids."""

    def __init__(self, p_yes, p_no, only_yes=False):
        self.p_yes, self.p_no, self.only_yes, self.calls = p_yes, p_no, only_yes, []

    def evaluate(self, state, questions):
        from semgate.providers.base import PredicateAnswer
        self.calls.append(sorted(questions))
        out = {Q: PredicateAnswer(Q, probability=self.p_yes)}
        if not self.only_yes and NO in questions:
            out[NO] = PredicateAnswer(NO, probability=self.p_no)
        return out


def _try(tmp_path, provider, name):
    pol = Policy.load(str(CANDIDATE))
    conv0 = ca.Conversation((ca.Item("user", "run the migration", T0 - 60, msg_id="u1"),
                             ca.Item("call", "bash", T0 - 5, call_id="k")), complete=True, timestamps=True, source="t")
    later = ca.Conversation(conv0.items + (ca.Item("user", "what does it do?", T0 + 60, msg_id="u2"),),
                            complete=True, timestamps=True, source="t")
    st = ca.Store(tmp_path / f"{name}.json", ttl_s=1800)
    ca.record_block(st, "k1", conv0, call_id="k", tool="bash", command=CMD, cwd="/p", reason="r", reason_code="x",
                    stage="semantic", judgment_id="j", now=T0)
    return st, ca.try_approve(st, "k1", later, blocked_action=CMD, provider=provider, q=ca.question(pol),
                              min_p=ca.threshold(pol), lim=ca.limits(pol), now=T0 + 120,
                              clarify_p=ca.clarify_threshold(pol), decline_q=ca.decline_question(pol),
                              decline_p=ca.decline_threshold(pol))


def test_both_questions_go_in_one_call_and_decide_three_ways(tmp_path):
    for (p_yes, p_no), want in (((0.95, 0.02), "allow"), ((0.02, 0.95), "declined"), ((0.03, 0.05), "clarify"),
                                ((0.95, 0.90), "declined")):
        judge = _Both(p_yes, p_no)
        st, out = _try(tmp_path, judge, f"{p_yes}-{p_no}")
        assert judge.calls == [sorted([Q, NO])], judge.calls           # one call, both questions
        assert out.outcome == want and out.p == p_yes and out.p_no == p_no
        assert (st.current("k1", T0 + 120) is None) is (want == "allow")


def test_a_missing_second_answer_is_unchecked(tmp_path):
    st, out = _try(tmp_path, _Both(0.99, None, only_yes=True), "missing")
    assert out.outcome == "unchecked" and not out.approved and out.why == "missing answer"
    assert st.current("k1", T0 + 120) is not None


def _cand_cfg(tmp_path, p_yes, p_no):
    cfg = _cfg(tmp_path, p_yes)
    cfg["policy_file"] = str(CANDIDATE)
    cfg["fake_answers"][NO] = p_no
    return cfg


def test_serve_unclear_reply_clarifies_with_the_second_question(tmp_path, monkeypatch):
    """The one-question judge gave "what does it do?" about the same low p
    as a no; with P_no low too, the outcome is clarify, not declined."""
    cfg = _cand_cfg(tmp_path, 0.03, 0.05)
    key, rec = _first_block(tmp_path, monkeypatch, cfg)
    msgs = _v1(_agent("m3", "Shall I run it?", 5), _user("m4", "hmm, what does it do?", 60))
    monkeypatch.setattr(time, "time", lambda: T0 + 90)
    out = serve.judge_request("opencode", _req(msgs, "c2"), cfg)
    assert out["reason"].startswith("semgate chat approval: the user's reply is not a clear yes or no")
    assert _blocks(tmp_path)[key]["last_outcome"] == "clarify"
    event, detail = _events(tmp_path)[-1]
    assert detail["outcome"] == "clarify" and detail["p"] == 0.03 and detail["p_no"] == 0.05
    assert detail["decline_min"] == ca.decline_threshold(Policy.load(str(CANDIDATE)))


def test_serve_clear_no_and_a_conflicting_yes_are_declined(tmp_path, monkeypatch):
    for n, (p_yes, p_no) in enumerate(((0.02, 0.95), (0.95, 0.95))):
        sub = tmp_path / str(n)
        sub.mkdir()
        cfg = _cand_cfg(sub, p_yes, p_no)
        _first_block(sub, monkeypatch, cfg)
        msgs = _v1(_agent("m3", "Shall I run it?", 5), _user("m4", "no, stop", 60))
        monkeypatch.setattr(time, "time", lambda: T0 + 90)
        out = serve.judge_request("opencode", _req(msgs, "c2"), cfg)
        assert out["decision"] == "ask" and out["reason"].startswith(ca.DECLINED_NOTE), (p_yes, p_no)


def test_scripted_eval_of_the_public_set_follows_the_three_way_labels():
    from semgate.eval import chat_approval as cae
    cases = [json.loads(x) for x in (ROOT / "fixtures" / "eval" / "chat-approval.jsonl").read_text(encoding="utf-8").splitlines()
             if x.strip()]
    rep = cae.evaluate(cases, Policy.load(str(CANDIDATE)), scripted=True)
    m = rep["metrics"]
    assert m["reply_outcomes"]["approve"]["allow"] == 23
    assert m["reply_outcomes"]["decline"]["declined"] == 13 and m["reply_outcomes"]["unclear"]["clarify"] == 9
    assert m["allowed_decline"] == [] and m["allowed_unclear"] == []
    assert m["false_approved"] == 0 and rep["code_path_failures"] == [] and rep["provider_errors"] == 0
    rows = cae.rescore_outcomes(rep["cases"], 0.85, 0.99)                 # at a higher decline threshold
    assert {r["outcome"] for r in rows if r.get("reply") == "decline"} == {"clarify"}
