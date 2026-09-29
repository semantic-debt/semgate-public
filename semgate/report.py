"""`semgate report`: what the ledger says about semgate's own decisions.

Reads the ledger (judgments + the exact responses sent to the host) and,
when outcome recording is on, the history store (did a command run after the
hook answered). Prints:

1. Decisions per reason code: how many allow / ask / deny.
2. Human answers to asks: for every step where the host was told ask /
   force_ask, did the command then run (the human approved) or not. The
   approval rate per reason code says which asks are friction and which do
   their job.
3. Regex gaps: judgments where a shadow question (leaks_secrets, remote_code,
   needs_root, changes_running_system) said yes with P >= 0.7. Those commands
   reached the model, so no deterministic gate fired for them.
4. What-if replay (--set key=value): re-decide every stored router judgment
   with changed thresholds, from the answers already in the ledger (no model
   calls), and list what would change. The safe way to tune: see the effect
   on your real traffic before switching.
5. Calibration (--calibration, calibration.py): per question, how its answer
   relates to whether the human approved the ask, with a time split (older
   half tune, newer half validate) and suggested threshold ranges.
6. Secret exposures (--exposures, exposures.py): per session, the secrets a
   tool output showed to the agent (type, masked preview, intended or
   unintended with the judge's p, where, first seen), the owner's three
   rules and "rotate/revoke these". Reads the
   exposure store of --config, or --dir, or every ~/.semgate/*/ config.
7. Chat approvals (chatapproval.py, policy router.chat_approval): blocks
   recorded on hosts that cannot ask, and each retry: approved (p), not
   approved (the judge said no or gave no answer), or rejected by code
   before the judge (no new user turn, no order evidence, ...). Shows the
   block id and a hash of the user turns, never their text.
9. Trusted instruction-file lines (pins.py, pingate.py): the files whose
   command lines are pinned, how many steps were judged with pinned lines,
   and semgate's questions about such lines (recorded, pinned, not_pinned).
8. Trusted commands (trust.py): the trusts in force (the trust store, default
   ~/.semgate/trust.jsonl, or --trust-store), how many steps each one
   allowed (reason code trusted_command), and every `semgate trust add` the
   agent ran (trustgate.py): allowed, not allowed (p), or rejected by code
   (why). Shows a hash of the user turns, never their text.

Read-only. Nothing is sent anywhere.
"""
from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

from . import router
from .policy import Policy
from .providers.base import PredicateAnswer

SHADOW_MIN = 0.7
# Shadow questions whose "yes" is not a risk: never listed as regex gaps.
NOT_RISK_QUESTIONS = frozenset({"can_judge", "serves_turn"})


def _read_jsonl(path: str) -> Iterable[Dict[str, Any]]:
    p = Path(path)
    if not p.is_file():
        return []
    out = []
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


def _command(env: Mapping[str, Any]) -> str:
    args = (env.get("action") or {}).get("arguments") or {}
    return str(args.get("command") or args.get("path") or args.get("url") or "")[:120]


def answers_from_votes(votes: List[Mapping[str, Any]]) -> Dict[str, PredicateAnswer]:
    """Rebuild provider answers from stored votes so decide() can be replayed."""
    out: Dict[str, PredicateAnswer] = {}
    for v in votes:
        q = str(v.get("predicate", ""))
        if not q or v.get("vote") == "abstain":
            continue
        if "p" in v:
            out[q] = PredicateAnswer(predicate_id=q, probability=float(v["p"]))
        elif "value" in v:
            out[q] = PredicateAnswer(predicate_id=q, value=v["value"], confidence=v.get("confidence"),
                                     raw={"probabilities": v.get("probabilities") or {}})
    return out


def build(ledger_path: str, history_path: str = "", policy_path: str = "",
          overrides: Optional[Mapping[str, Any]] = None, trust_store: str = "") -> Dict[str, Any]:
    ledger = list(_read_jsonl(ledger_path))
    judgments = [r for r in ledger if r.get("record_type") == "judgment"]
    host = {(r.get("conversation_id"), r.get("step_idx")): r for r in ledger if r.get("record_type") == "host_response"}
    history = list(_read_jsonl(history_path)) if history_path else []
    ran = {(r.get("conversation_id"), r.get("step_idx")) for r in history if r.get("record_type") == "executed"}
    pending = {(r.get("conversation_id"), r.get("step_idx")): r for r in history if r.get("record_type") == "pending"}

    # 1. decisions per reason code
    per_code: Dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for j in judgments:
        d = j.get("decision") or {}
        per_code[str(d.get("reason_code") or d.get("stage") or "?")][str(d.get("decision"))] += 1

    # 2. human answers to asks (needs outcome recording)
    approvals: Dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for key, h in host.items():
        native = h.get("native") or {}
        if native.get("decision") not in ("ask", "force_ask") or key not in pending:
            continue
        reason = str(native.get("reason", ""))
        code = reason.split("[", 1)[1].split("]", 1)[0] if "[" in reason and "]" in reason else "?"
        approvals[code]["approved (ran)" if key in ran else "not run"] += 1

    # 3. regex gaps from shadow questions (a "yes" there is a risk), and the
    #    commands the model says it cannot judge from the evidence (can_judge
    #    is the one shadow question where "yes" is the good answer)
    gaps: List[Dict[str, Any]] = []
    unjudgeable: List[Dict[str, Any]] = []
    for j in judgments:
        for v in (j.get("decision") or {}).get("predicate_votes") or []:
            if v.get("predicate") in NOT_RISK_QUESTIONS:
                if v.get("predicate") == "can_judge" and "p" in v and float(v["p"]) <= 1.0 - SHADOW_MIN:
                    unjudgeable.append({"p": round(float(v["p"]), 2), "decision": (j.get("decision") or {}).get("decision"),
                                        "command": _command(j.get("envelope") or {})})
                continue
            if v.get("vote") == "shadow" and float(v.get("p", 0)) >= SHADOW_MIN:
                gaps.append({"question": v.get("predicate"), "p": round(float(v["p"]), 2),
                             "decision": (j.get("decision") or {}).get("decision"), "command": _command(j.get("envelope") or {})})

    # 4. what-if replay
    what_if: Dict[str, Any] = {}
    if policy_path and overrides:
        raw = json.loads(Path(policy_path).read_text(encoding="utf-8"))
        base_pol = Policy(raw)
        raw2 = json.loads(json.dumps(raw))
        raw2.setdefault("router", {}).setdefault("thresholds", {}).update(overrides)
        new_pol = Policy(raw2)
        router.thresholds(new_pol)  # validates the override names
        changes: List[Dict[str, Any]] = []
        replayed = 0
        for j in judgments:
            d = j.get("decision") or {}
            if d.get("stage") != "semantic" or not d.get("predicate_votes"):
                continue
            ans = answers_from_votes(d["predicate_votes"])
            fired = [str(x.get("id", "")) for x in ((d.get("evidence") or {}).get("code_signals") or {}).get("fired") or []
                     if isinstance(x, dict)]
            try:
                before = router.decide(base_pol, ans, fired)["decision"]
                after = router.decide(new_pol, ans, fired)["decision"]
            except Exception:
                continue
            replayed += 1
            if before != after:
                changes.append({"before": before, "after": after, "command": _command(j.get("envelope") or {})})
        what_if = {"overrides": dict(overrides), "replayed": replayed, "changed": changes}

    # 7. approval by chat reply
    chat = [r for r in ledger if r.get("record_type") == "chat_approval"]
    chat_rows = [{"ts": str(r.get("ts", "")), "event": str(r.get("event", "")),
                  **{k: (r.get("detail") or {}).get(k) for k in ("block_id", "p", "min", "why", "evidence", "new_turns",
                                                                 "user_turns_sha", "command", "host", "outcome")}} for r in chat]
    chat_counts = dict(collections.Counter(row["event"] for row in chat_rows))
    # allow / clarify / declined / unchecked of the judged replies
    chat_outcomes = dict(collections.Counter(row["outcome"] for row in chat_rows if row.get("outcome")))

    # 8. trusted commands
    used: Dict[str, int] = collections.Counter(
        str(((j.get("decision") or {}).get("evidence") or {}).get("trusted_command", {}).get("trust_id", ""))
        for j in judgments if (j.get("decision") or {}).get("reason_code") == "trusted_command")
    trust_rows: List[Dict[str, Any]] = []
    trust_error = ""
    ignored = 0
    refused: List[Dict[str, Any]] = []
    try:
        from . import trust as trust_mod
        store = trust_mod.TrustStore(Path(trust_store) if trust_store else trust_mod.default_store())
        for r in store.active():
            trust_rows.append({"trust_id": r.get("trust_id", ""), "command": trust_mod.shown(r),
                               "project_root": r.get("project_root", ""), "expires_at": r.get("expires_at", ""),
                               "allowed_steps": used.get(str(r.get("trust_id", "")), 0), "via": r.get("via", "")})
        ignored = store.ignored
        # `semgate trust add | file` runs the CLI refused: no ticket and not the user's own terminal (trustauth.py).
        refused = [{k: r.get(k) for k in ("ts", "kind", "target", "project_root", "why")} for r in store.refused()]
    except Exception as exc:
        trust_error = f"{type(exc).__name__}: {exc}"[:200]
    pin_rows: List[Dict[str, Any]] = []
    try:
        from .pins import PinStore
        from . import trust as trust_mod2
        ps = PinStore(Path(trust_store) if trust_store else trust_mod2.default_store())
        for (_proj, _fk), v in sorted(PinStore.state(ps.records()).items()):
            pin_rows.append({"file": v["file"], "project_root": v["project_root"], "lines": len(v["lines"]), "ts": v["ts"]})
    except Exception as exc:
        trust_error = trust_error or f"{type(exc).__name__}: {exc}"[:200]
    lifted = sum(1 for j in judgments
                 if ((j.get("decision") or {}).get("evidence") or {}).get("project_instructions"))
    pin_requests = [{"ts": str(r.get("ts", "")), "event": str(r.get("event", "")),
                     **{k: (r.get("detail") or {}).get(k) for k in ("file", "lines", "p", "min", "why", "host",
                                                                    "user_turns_sha")}}
                    for r in ledger if r.get("record_type") == "pin_request"]
    requests = [{"ts": str(r.get("ts", "")), "event": str(r.get("event", "")),
                 **{k: (r.get("detail") or {}).get(k) for k in ("command", "days", "p", "min", "why", "untrusted",
                                                                "user_turns_sha", "host")}}
                for r in ledger if r.get("record_type") == "trust_request"]

    return {"judgments": len(judgments), "per_reason_code": {k: dict(v) for k, v in per_code.items()},
            "asks_answered": {k: dict(v) for k, v in approvals.items()}, "outcomes_recorded": bool(history),
            "regex_gaps": gaps, "not_judgeable": unjudgeable, "what_if": what_if,
            "chat_approvals": {"counts": chat_counts, "outcomes": chat_outcomes, "events": chat_rows},
            "trusted_commands": {"active": trust_rows, "allowed_steps": sum(used.values()), "error": trust_error,
                                 "ignored_records": ignored, "refused_cli_runs": refused, "requests": requests,
                                 "request_counts": dict(collections.Counter(r["event"] for r in requests))},
            "pinned_instruction_lines": {"files": pin_rows, "judged_with_pinned_lines": lifted, "questions": pin_requests,
                                         "question_counts": dict(collections.Counter(r["event"] for r in pin_requests))}}


def render(rep: Mapping[str, Any]) -> str:
    lines = [f"judgments: {rep['judgments']}", "", "Decisions per reason code:"]
    for code, c in sorted(rep["per_reason_code"].items(), key=lambda kv: -sum(kv[1].values())):
        lines.append(f"  {code:40} " + "  ".join(f"{k} {v}" for k, v in sorted(c.items())))
    lines += ["", "Your answers to asks (did the command run after semgate asked?):"]
    if not rep["outcomes_recorded"]:
        lines.append("  no outcome records: set \"record_outcomes\": true in the hook config")
    elif not rep["asks_answered"]:
        lines.append("  none yet")
    for code, c in sorted(rep["asks_answered"].items()):
        n = sum(c.values()); ok = c.get("approved (ran)", 0)
        lines.append(f"  {code:40} approved {ok}/{n} ({100 * ok / n:.0f}%)")
    lines += ["", f"Possible regex gaps (shadow question yes, P >= {SHADOW_MIN}, no gate fired): {len(rep['regex_gaps'])}"]
    for g in rep["regex_gaps"][:30]:
        lines.append(f"  {g['question']:24} p={g['p']:.2f} {g['decision']:5} {g['command']}")
    if rep.get("not_judgeable"):
        lines += ["", f"Commands the model says it cannot judge from the evidence (can_judge P <= {1 - SHADOW_MIN:.1f}): "
                      f"{len(rep['not_judgeable'])}"]
        for g in rep["not_judgeable"][:30]:
            lines.append(f"  p={g['p']:.2f} {g['decision']:5} {g['command']}")
    chat = rep.get("chat_approvals") or {}
    if chat.get("events"):
        c = chat.get("counts") or {}
        lines += ["", "Chat approvals (router.chat_approval): " + ", ".join(f"{k} {v}" for k, v in sorted(c.items()))]
        if chat.get("outcomes"):
            lines.append("  judged replies: " + ", ".join(f"{k} {v}" for k, v in sorted(chat["outcomes"].items())))
        for e in [x for x in chat["events"] if x["event"] != "block_recorded"][-30:]:
            p = "" if e.get("p") is None else f" p={float(e['p']):.2f}"
            why = f" ({e['why']})" if e.get("why") else ""
            outcome = f" {e['outcome']}" if e.get("outcome") else ""
            lines.append(f"  {e['ts'][:19]} {e['event']:13}{outcome} block {e.get('block_id') or '-'}{p} turns "
                         f"{e.get('new_turns') or 0} sha {e.get('user_turns_sha') or '-'}{why} {e.get('command') or ''}"[:220])
    tc = rep.get("trusted_commands") or {}
    if tc.get("active") or tc.get("requests") or tc.get("allowed_steps") or tc.get("refused_cli_runs") or tc.get("ignored_records"):
        lines += ["", f"Trusted commands (semgate trust): {len(tc.get('active') or [])} in force, "
                      f"{tc.get('allowed_steps', 0)} steps allowed by a trust"]
        for t in (tc.get("active") or [])[:30]:
            lines.append(f"  {t['trust_id']}  until {str(t['expires_at'])[:19]}Z  allowed {t['allowed_steps']:3}  "
                         f"`{t['command']}`  in {t['project_root']}"[:220])
        if tc.get("requests"):
            lines.append("  semgate trust add run by the agent: "
                         + ", ".join(f"{k} {v}" for k, v in sorted((tc.get("request_counts") or {}).items())))
            for e in tc["requests"][-30:]:
                p = "" if e.get("p") is None else f" p={float(e['p']):.2f}"
                why = f" ({e['why']})" if e.get("why") else ""
                lines.append(f"  {e['ts'][:19]} {e['event']:13}{p} `{e.get('command') or ''}` {e.get('days') or ''}d"
                             f" sha {e.get('user_turns_sha') or '-'}{why}"[:220])
        if tc.get("refused_cli_runs"):
            lines.append(f"  semgate trust run without semgate's approval (refused by the CLI): {len(tc['refused_cli_runs'])}")
            for e in tc["refused_cli_runs"][-10:]:
                lines.append(f"  {str(e.get('ts') or '')[:19]} refused {e.get('kind') or ''} `{e.get('target') or ''}`"
                             f" ({e.get('why') or ''})"[:220])
        if tc.get("ignored_records"):
            lines.append(f"  ignored: {tc['ignored_records']} trust record(s) without a valid semgate tag (they allow nothing)")
    if tc.get("error"):
        lines += ["", f"Trusted commands: the trust store could not be read ({tc['error']})"]
    pl = rep.get("pinned_instruction_lines") or {}
    if pl.get("files") or pl.get("questions") or pl.get("judged_with_pinned_lines"):
        lines += ["", f"Trusted instruction-file lines (semgate trust file): {len(pl.get('files') or [])} files, "
                      f"{pl.get('judged_with_pinned_lines', 0)} steps judged with pinned lines"]
        for f in (pl.get("files") or [])[:30]:
            lines.append(f"  {f['file']}: {f['lines']} lines since {str(f['ts'])[:19]}Z  in {f['project_root']}"[:220])
        if pl.get("questions"):
            lines.append("  semgate's questions about instruction-file lines: "
                         + ", ".join(f"{k} {v}" for k, v in sorted((pl.get("question_counts") or {}).items())))
            for e in pl["questions"][-30:]:
                p = "" if e.get("p") is None else f" p={float(e['p']):.2f}"
                why = f" ({e['why']})" if e.get("why") else ""
                lines.append(f"  {e['ts'][:19]} {e['event']:13}{p} {e.get('file') or ''} {e.get('lines') or 0} lines"
                             f" sha {e.get('user_turns_sha') or '-'}{why}"[:220])
    if rep.get("what_if"):
        w = rep["what_if"]
        lines += ["", f"What if {w['overrides']}: {len(w['changed'])} of {w['replayed']} replayed decisions change"]
        for c in w["changed"][:30]:
            lines.append(f"  {c['before']:5} -> {c['after']:5} {c['command']}")
    return "\n".join(lines)


def add_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("report", help="Report on semgate's own decisions: reason codes, your answers to asks, regex gaps, "
                                      "what-if threshold replay; --exposures: secrets shown to agents")
    p.add_argument("--ledger", default="", help="the ledger (required except with --exposures)")
    p.add_argument("--exposures", action="store_true",
                   help="list secrets that tool outputs showed to the agent, per session (masked; values are never stored)")
    p.add_argument("--session", default="", help="--exposures: only this session id")
    p.add_argument("--config", default="", help="--exposures: the hook's semgate.json (default: every ~/.semgate/*/semgate.json)")
    p.add_argument("--dir", default="", help="--exposures: an exposure store directory")
    p.add_argument("--history", default="", help="history store with outcome records (record_outcomes: true)")
    p.add_argument("--policy", default="", help="policy file, needed for --set")
    p.add_argument("--set", action="append", default=[], metavar="KEY=VALUE", help="threshold override to replay, repeatable")
    p.add_argument("--json", action="store_true", help="print JSON instead of text")
    p.add_argument("--trust-store", default="", help="trust store to list (default ~/.semgate/trust.jsonl)")
    p.add_argument("--calibration", action="store_true",
                   help="per question: how its answer relates to human approval of asks (older half tune, newer half "
                        "validate) and suggested threshold ranges; report only, never writes a policy")
    p.add_argument("--feedback", default="", help="feedback store (semgate feedback), used by --calibration")
    p.add_argument("--target", type=float, default=0.9, help="--calibration: approval rate a suggested cut must reach")
    p.add_argument("--min-n", type=int, default=5, help="--calibration: fewest tune samples behind a suggested cut")

    def run(args: argparse.Namespace) -> int:
        if args.exposures:
            from . import exposures
            if args.dir:
                dirs = [Path(args.dir)]
            elif args.config:
                from . import storepaths
                dirs = [exposures.store_dir(storepaths.load(args.config, storepaths.guess_host(args.config)))]
            else:
                dirs = exposures.default_dirs()
            rep = exposures.collect(dirs, args.session)
            print(json.dumps(rep, indent=1, ensure_ascii=False) if args.json else exposures.render(rep))
            return 0
        if not args.ledger:
            p.error("--ledger is required (or use --exposures)")
        if args.calibration:
            from . import calibration
            rep = calibration.build(args.ledger, args.history, args.feedback, target=args.target, min_n=args.min_n)
            print(json.dumps(rep, indent=1) if args.json else calibration.render(rep))
            return 0
        overrides: Dict[str, Any] = {}
        for item in args.set:
            k, _, v = item.partition("=")
            overrides[k.strip()] = (v.strip().lower() == "true") if v.strip().lower() in ("true", "false") else (None if v.strip() == "null" else float(v))
        rep = build(args.ledger, args.history, args.policy, overrides or None, trust_store=args.trust_store)
        print(json.dumps(rep, indent=1) if args.json else render(rep))
        return 0
    p.set_defaults(func=run)
