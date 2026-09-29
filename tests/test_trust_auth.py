"""Who may write the trust store (semgate/trustauth.py): the hook's one-time
approval ticket, a person in their own terminal, keyed tags on every
record and the agent-host record (writes to ~/.semgate: test_semgate_state_rules.py).

Every test runs as a tool call of an agent whose host process is
`testagent` (conftest._trust_process_view) unless it uses the
`human_terminal` fixture or `as_person()`. HOME and USERPROFILE are temp
dirs; nothing here reads the real process tree except
test_the_real_process_tree_is_read."""
import json
import os
from pathlib import Path

import pytest

from conftest import REAL_ANCESTRY, as_person, fake_chain
from semgate import cli, fingerprints, pins, trust, trustauth
from test_trust_gate import ADD, Session, tick

T0 = 1_790_000_000.0
AUTH = trustauth.Auth("test")


def project(tmp_path, name="proj"):
    root = tmp_path / name
    (root / ".git").mkdir(parents=True, exist_ok=True)
    return root


def cli_add(store, root, command="npm run e2e", days=7):
    return cli.main(["trust", "add", command, "--days", str(days), "--store", str(store), "--project", str(root)])


def ticket(store, root, command="npm run e2e", days=7, now=None, host_key="", kind="add", lines=()):
    return trustauth.issue_ticket(store, kind=kind, target=command, days=days, project=trust.project_of(str(root)),
                                  lines=lines, session_id="ses1", judgment_id="j1", host="claude", host_key=host_key,
                                  now=now)


def consume(store, root, command="npm run e2e", days=7, now=None, hosts=(), kind="add", lines=()):
    return trustauth.consume_ticket(store, kind=kind, target=command, days=days, project=trust.project_of(str(root)),
                                    lines=lines, chain_hosts=hosts, now=now)


def lookup(store, root, command="npm run e2e"):
    return trust.TrustStore(store).lookup(command, trust.project_of(str(root)))


# ------------------------------------------------------------------ (a) the approval ticket


def test_a_ticket_works_once(tmp_path):
    store, root = tmp_path / "trust.jsonl", project(tmp_path)
    ticket(store, root, now=T0)
    assert consume(store, root, now=T0 + 3).ticket is not None
    again = consume(store, root, now=T0 + 4)
    assert again.ticket is None and "already used" in again.why


def test_a_ticket_expires(tmp_path):
    store, root = tmp_path / "trust.jsonl", project(tmp_path)
    ticket(store, root, now=T0)
    late = consume(store, root, now=T0 + trustauth.TICKET_TTL_S + 1)
    assert late.ticket is None and "expired" in late.why
    assert consume(store, root, now=T0 + trustauth.TICKET_TTL_S - 1).ticket is not None


@pytest.mark.parametrize("change,why", [
    ({"command": "npm run e2e -- --watch"}, "no approval ticket"),
    ({"command": "npm run E2E"}, "no approval ticket"),
    ({"days": 30}, "approved request was for 7 days"),
    ({"other_project": True}, "no approval ticket"),
])
def test_a_ticket_covers_exactly_the_approved_request(tmp_path, change, why):
    store, root = tmp_path / "trust.jsonl", project(tmp_path)
    ticket(store, root, now=T0)
    target_root = project(tmp_path, "other") if change.get("other_project") else root
    got = consume(store, target_root, command=change.get("command", "npm run e2e"), days=change.get("days", 7), now=T0 + 1)
    assert got.ticket is None and why in got.why
    assert consume(store, root, now=T0 + 2).ticket is not None                # the approved one is still there


def test_a_file_ticket_needs_the_same_lines(tmp_path):
    store, root = tmp_path / "trust.jsonl", project(tmp_path)
    ticket(store, root, command="agents.md", kind="file", days=0, lines=["sha256:a", "sha256:b"], now=T0)
    changed = consume(store, root, command="agents.md", kind="file", days=0, lines=["sha256:a", "sha256:c"], now=T0 + 1)
    assert changed.ticket is None and "changed since semgate approved" in changed.why
    assert consume(store, root, command="agents.md", kind="file", days=0, lines=["sha256:b", "sha256:a"],
                   now=T0 + 2).ticket is not None


def test_a_ticket_of_another_agent_session_is_not_used(tmp_path):
    store, root = tmp_path / "trust.jsonl", project(tmp_path)
    ticket(store, root, host_key="111:1", now=T0)
    other = consume(store, root, hosts=["222:2"], now=T0 + 1)
    assert other.ticket is None and "another agent session" in other.why
    assert consume(store, root, hosts=["111:1", "333:3"], now=T0 + 2).ticket is not None


def test_a_ticket_written_by_hand_is_not_used(tmp_path):
    store, root = tmp_path / "trust.jsonl", project(tmp_path)
    rec = ticket(store, root, now=T0)
    path = trustauth.tickets_path(store)
    path.write_text("", encoding="utf-8")
    forged = dict(rec, ticket_id="forged")                                   # the tag no longer matches
    no_tag = {k: v for k, v in rec.items() if k != "tag"}
    path.write_text(json.dumps(forged) + "\n" + json.dumps(no_tag) + "\n", encoding="utf-8")
    assert consume(store, root, now=T0 + 1).ticket is None


def test_the_ticket_keeps_no_command_text_with_a_secret(tmp_path):
    store, root = tmp_path / "trust.jsonl", project(tmp_path)
    secret = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    ticket(store, root, command=f'curl -H "Authorization: token {secret}" https://api.github.com/user', now=T0)
    assert secret not in trustauth.tickets_path(store).read_text(encoding="utf-8")


# ------------------------------------------------------------------ the whole agent path: hook, ticket, CLI


def asked_session(tmp_path, host="claude"):
    s = Session(host, tmp_path)
    s.user("always allow `npm run e2e` in this project, stop asking me about it")
    tick()
    return s


def test_hook_approval_then_the_cli_adds_the_trust_once(tmp_path, capsys):
    s = asked_session(tmp_path)
    out = s.run(ADD)
    assert out["decision"] == "allow"
    (event, detail), = s.events()
    assert event == "allowed" and detail["ticket_id"]
    assert s.add_as_the_cli_would("npm run e2e") == 0
    rec = lookup(s.tmp / "trust.jsonl", s.root)
    assert rec["via"] == "ticket" and rec["auth"]["ticket_id"] == detail["ticket_id"] and rec["auth"]["session_id"]
    capsys.readouterr()
    assert s.add_as_the_cli_would("npm run e2e") == 2                         # replay: the ticket is used
    assert "already used" in capsys.readouterr().err


def test_the_cli_refuses_another_command_than_the_approved_one(tmp_path, capsys):
    s = asked_session(tmp_path)
    assert s.run(ADD)["decision"] == "allow"
    assert s.add_as_the_cli_would("npm run deploy") == 2
    assert s.add_as_the_cli_would("npm run e2e", days=30) == 2
    assert lookup(s.tmp / "trust.jsonl", s.root, "npm run deploy") is None
    assert s.add_as_the_cli_would("npm run e2e") == 0                         # the approved request still works


def test_dollar_s_trust_add_without_a_ticket_is_refused_and_recorded(tmp_path, capsys):
    """`S=semgate` in one call, `$S trust add "npm run deploy"` in the next:
    the hook sees no `semgate` word, but the CLI runs in the agent's process
    tree (the host process the hook recorded) and has no ticket."""
    s = Session("claude", tmp_path)
    s.user("deploy the site")
    s.run("S=semgate")                                                        # the hook records the agent host
    tick()
    assert s.add_as_the_cli_would("npm run deploy") == 2
    err = capsys.readouterr().err
    assert "no approval ticket" in err and "testagent" in err and "session that semgate's hook saw" in err
    assert "they ask for it in the agent's chat" in err
    assert lookup(s.tmp / "trust.jsonl", s.root, "npm run deploy") is None
    assert cli.main(["trust", "list", "--store", str(s.tmp / "trust.jsonl"), "--project", str(s.root)]) == 0
    out = capsys.readouterr().out
    assert "refused: 1 `semgate trust add` run(s) without semgate's approval" in out and "npm run deploy" in out
    from semgate import report
    rep = report.build(s.cfg["ledger_file"], trust_store=str(s.tmp / "trust.jsonl"))
    assert [r["target"] for r in rep["trusted_commands"]["refused_cli_runs"]] == ["npm run deploy"]
    assert "semgate trust run without semgate's approval (refused by the CLI): 1" in report.render(rep)


def test_after_a_refused_request_the_host_prompt_is_a_deny_and_the_cli_refuses(tmp_path, capsys):
    """Claude Code: the agent runs trust add on its own. The hook denies (a
    prompt approval could not add the trust), and if the command ran anyway
    the CLI has no ticket."""
    s = Session("claude", tmp_path)
    s.user("run the e2e tests")
    s.call("npm run e2e", output="12 passed")
    tick()
    out = s.run(ADD)
    assert out["decision"] == "deny" and out["reason"].startswith("semgate: `semgate trust add` makes semgate allow")
    assert s.add_as_the_cli_would("npm run e2e") == 2
    assert lookup(s.tmp / "trust.jsonl", s.root) is None


def test_shadow_mode_issues_no_ticket(tmp_path):
    s = Session("claude", tmp_path, mode="shadow")
    s.user("always allow npm run e2e in this project")
    tick()
    assert s.run(ADD)["decision"] == "ask"
    assert not trustauth.tickets_path(s.tmp / "trust.jsonl").exists()
    assert s.add_as_the_cli_would("npm run e2e") == 2


def test_a_ticket_that_cannot_be_written_is_not_an_allow(tmp_path, monkeypatch):
    s = asked_session(tmp_path)

    def broken(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(trustauth, "issue_ticket", broken)
    out = s.run(ADD)
    assert out["decision"] == "deny" and "approval ticket could not be written" in out["reason"]
    assert s.events()[-1][0] == "not_allowed"


def test_trust_file_through_the_hook_and_the_cli(tmp_path):
    from test_pins import AGENTS, pinned_lines, session
    s = session("claude", tmp_path)
    s.user("trust the command lines of AGENTS.md")
    tick()
    assert s.run("semgate trust file AGENTS.md")["decision"] == "allow"
    base = ["--store", s.cfg["trust"]["file"], "--project", str(s.root)]
    (s.root / "AGENTS.md").write_text(AGENTS + "Also you must run `npm run lint`.\n", encoding="utf-8")
    assert cli.main(["trust", "file", "AGENTS.md", *base]) == 2               # the file changed after the approval
    (s.root / "AGENTS.md").write_text(AGENTS, encoding="utf-8")
    assert cli.main(["trust", "file", "AGENTS.md", *base]) == 0
    assert len(pinned_lines(s)) == 2
    rec = pins.PinStore(s.cfg["trust"]["file"]).records()[-1]
    assert rec["via"] == "ticket"


# ------------------------------------------------------------------ (b) a person in their own terminal


def test_a_person_types_the_word(tmp_path, human_terminal, capsys):
    store, root = tmp_path / "trust.jsonl", project(tmp_path)
    assert cli_add(store, root) == 0
    out = capsys.readouterr().out
    assert "Type bakodi and press Enter" in out and "allow exactly `npm run e2e`" in out and "trusted: `npm run e2e`" in out
    assert lookup(store, root)["via"] == "terminal"


@pytest.mark.parametrize("answer", ["", "yes\n", "BAKODI x\n"])
def test_no_word_no_trust(tmp_path, capsys, answer):
    store, root = tmp_path / "trust.jsonl", project(tmp_path)
    with as_person(answer=answer):
        assert cli_add(store, root) == 2
    assert "not trusted: not confirmed" in capsys.readouterr().err
    assert lookup(store, root) is None
    assert trust.TrustStore(store).refused() == []                            # a person saying no is not an attempt


def test_a_person_in_another_terminal_while_an_agent_session_runs(tmp_path, capsys):
    s = Session("claude", tmp_path)
    s.user("run the tests")
    s.run("npm test")                                                         # the hook records `testagent`
    hosts, problem = trustauth.read_hosts(s.tmp / "trust.jsonl")
    assert problem == "" and [h["name"] for h in hosts.values()] == ["testagent"]
    with as_person():
        assert s.add_as_the_cli_would("npm run e2e") == 0


@pytest.mark.parametrize("chain,env,sign", [
    (fake_chain(("python", "1"), ("pwsh", "2"), ("windowsterminal", "3")), {"CLAUDECODE": "1"}, "CLAUDECODE is set"),
    (fake_chain(("python", "1"), ("pwsh", "2"), ("windowsterminal", "3")), {"AI_AGENT": "claude-code_2_agent"}, "AI_AGENT"),
    (fake_chain(("python", "1"), ("bash", "2"), ("claude", "3")), {}, "claude (pid"),
    (fake_chain(("python", "1"), ("pwsh", "2"), ("codex-windows-sandbox-service", "3")), {}, "an agent CLI"),
    (fake_chain(("python", "1"), ("python", "2")), {}, "whose parent process has exited"),
])
def test_agent_signs(tmp_path, chain, env, sign, monkeypatch, capsys):
    if sign.startswith("whose parent"):
        chain.parent_gone = True                                             # Start-Process, then the shell exited
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    store, root = tmp_path / "trust.jsonl", project(tmp_path)
    monkeypatch.setattr(trustauth, "ancestry", lambda pid=None, limit=64: chain)
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO("bakodi\n"))
    monkeypatch.setattr(trustauth, "confirm_word", lambda rng=None: "bakodi")
    assert cli_add(store, root) == 2
    err = capsys.readouterr().err
    assert sign in err and "not a terminal the user opened" in err
    assert lookup(store, root) is None


def test_an_unreadable_process_tree_is_not_a_person(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(trustauth, "ancestry", lambda pid=None, limit=64: None)
    assert cli_add(tmp_path / "trust.jsonl", project(tmp_path)) == 2
    assert "cannot read the parent processes" in capsys.readouterr().err


def test_a_changed_agent_host_record_is_not_trusted(tmp_path, monkeypatch, capsys):
    s = Session("claude", tmp_path)
    s.user("run the tests")
    s.run("npm test")
    path = trustauth.hosts_path(s.tmp / "trust.jsonl")
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["hosts"] = {}                                                         # the agent removes its own host
    path.write_text(json.dumps(doc), encoding="utf-8")
    with as_person():
        assert s.add_as_the_cli_would("npm run e2e") == 2
    assert "changed outside semgate" in capsys.readouterr().err
    s.run("npm test")                                                         # the next hook call writes it again
    assert trustauth.read_hosts(s.tmp / "trust.jsonl")[1] == ""


# ------------------------------------------------------------------ the agent-host record


@pytest.mark.parametrize("names,host", [
    (("python", "python", "cmd", "claude", "claude"), "claude"),              # venv launcher, cmd /c, Claude Code
    (("python", "bash", "node", "pwsh", "windowsterminal"), "node"),          # Pi / Gemini CLI run as node
    (("python", "uv", "opencode2"), "opencode2"),
    (("python", "pwsh", "windowsterminal"), None),                            # a terminal is never an agent host
    (("python", "bash", "sshd"), None),
    (("python",), None),
])
def test_the_agent_host_is_the_nearest_parent_that_is_not_a_shell(names, host):
    chain = fake_chain(*[(n, str(100 + i)) for i, n in enumerate(names)])
    got = trustauth.host_process(chain)
    assert (got.name if got else None) == host


def test_the_real_process_tree_is_read():
    chain = REAL_ANCESTRY()
    assert chain is not None and chain[0].pid == os.getpid()
    if len(chain) > 1:
        assert chain[1].pid == os.getppid()
        assert all(p.name for p in chain)


def test_note_agent_host_writes_once_then_refreshes(tmp_path):
    store = tmp_path / "trust.jsonl"
    chain = fake_chain(("python", "1"), ("bash", "2"), ("claude", "3"))
    key = trustauth.note_agent_host(store, host="claude", session_id="s1", now=T0, chain=chain)
    assert key == f"{chain[2].pid}:3"
    mtime = trustauth.hosts_path(store).stat().st_mtime_ns
    assert trustauth.note_agent_host(store, host="claude", session_id="s2", now=T0 + 10, chain=chain) == key
    assert trustauth.hosts_path(store).stat().st_mtime_ns == mtime            # fresh enough: not written again
    trustauth.note_agent_host(store, host="claude", session_id="s2", now=T0 + trustauth.HOST_REFRESH_S + 1, chain=chain)
    hosts, problem = trustauth.read_hosts(store)
    assert problem == "" and hosts[key]["sessions"] == ["s1", "s2"]


# ------------------------------------------------------------------ keyed tags: records not written by semgate are ignored


def _hand_record(proj, command="make deploy"):
    return {"record_type": "trust", "schema": trust.SCHEMA, "event": "add", "trust_id": "byhand",
            "match": trust.sha_match(command), "command": command, "project_root": proj, "days": 7,
            "ts": trust._iso(T0), "expires_at": trust._iso(T0 + 7 * 86400)}


def test_a_record_written_by_hand_is_ignored(tmp_path, capsys, human_terminal):
    store, root = tmp_path / "trust.jsonl", project(tmp_path)
    proj = trust.project_of(str(root))
    st = trust.TrustStore(store, clock=lambda: T0 + 60)
    st.add("npm run e2e", proj, auth=AUTH, now=T0)
    with open(store, "a", encoding="utf-8") as h:                            # echo '{...}' >> ~/.semgate/trust.jsonl
        h.write(json.dumps(_hand_record(proj)) + "\n")
        h.write(json.dumps(dict(_hand_record(proj, "make publish"), schema=1)) + "\n")   # the format before tags
    assert st.lookup("make deploy", proj) is None and st.lookup("make publish", proj) is None
    assert st.lookup("npm run e2e", proj) is not None and st.ignored == 2
    assert "ignored 2 trust record(s) without a valid semgate tag" in capsys.readouterr().err
    assert cli.main(["trust", "list", "--store", str(store), "--project", str(root)]) == 0
    assert "ignored: 2 record(s)" in capsys.readouterr().out


def test_a_changed_record_is_ignored(tmp_path):
    store, root = tmp_path / "trust.jsonl", project(tmp_path)
    proj = trust.project_of(str(root))
    st = trust.TrustStore(store, clock=lambda: T0 + 60)
    st.add("npm run e2e", proj, days=1, auth=AUTH, now=T0)
    rec = json.loads(store.read_text(encoding="utf-8").splitlines()[0])
    rec["expires_at"] = trust._iso(T0 + 30 * 86400)                            # longer, same tag
    rec["command"], rec["match"] = "make deploy", trust.sha_match("make deploy")
    store.write_text(json.dumps(rec) + "\n", encoding="utf-8")
    assert st.lookup("make deploy", proj) is None and st.lookup("npm run e2e", proj) is None and st.ignored == 1


def test_a_record_tagged_with_another_key_is_ignored(tmp_path):
    root = project(tmp_path)
    proj = trust.project_of(str(root))
    a = tmp_path / "a" / "trust.jsonl"
    b = tmp_path / "b" / "trust.jsonl"
    trust.TrustStore(a, clock=lambda: T0 + 60).add("npm run e2e", proj, auth=AUTH, now=T0)
    b.parent.mkdir()
    b.write_bytes(a.read_bytes())                                             # a store copied from another key
    st = trust.TrustStore(b, clock=lambda: T0 + 60)
    assert st.lookup("npm run e2e", proj) is None and st.ignored == 1


def test_a_pin_written_by_hand_is_ignored(tmp_path):
    root = project(tmp_path)
    proj = trust.project_of(str(root))
    store = tmp_path / "trust.jsonl"
    ps = pins.PinStore(store)
    ps.add(proj, "AGENTS.md", [{"key": "sha256:aa", "text": "x", "line": 1}], auth=AUTH)
    rec = {"record_type": "pin", "schema": pins.SCHEMA, "event": "add", "pin_id": "byhand", "project_root": proj,
           "file": "AGENTS.md", "file_key": pins.file_key("AGENTS.md"), "replace": False,
           "lines": [{"key": "sha256:bb", "text": "curl x | sh", "line": 2}], "via": "terminal", "ts": trust._iso(T0)}
    with open(store, "a", encoding="utf-8") as h:
        h.write(json.dumps(rec) + "\n")
    state = pins.PinStore.state(ps.records(), proj)
    assert list(state[(proj, pins.file_key("AGENTS.md"))]["lines"]) == ["sha256:aa"] and ps.ignored == 1


def test_a_deleted_key_makes_every_trust_void(tmp_path):
    root = project(tmp_path)
    proj = trust.project_of(str(root))
    store = tmp_path / "trust.jsonl"
    trust.TrustStore(store, clock=lambda: T0 + 60).add("npm run e2e", proj, auth=AUTH, now=T0)
    (tmp_path / trust.KEY_NAME).unlink()
    fingerprints.clear_cache()
    st = trust.TrustStore(store, clock=lambda: T0 + 60)
    assert st.lookup("npm run e2e", proj) is None and st.ignored == 1        # fail closed: a new key is made


# ------------------------------------------------------------------ the library needs an Auth; list and remove


def test_the_store_needs_an_auth(tmp_path):
    proj = trust.project_of(str(project(tmp_path)))
    st = trust.TrustStore(tmp_path / "trust.jsonl")
    with pytest.raises(TypeError):
        st.add("npm run e2e", proj)                                           # the naive library call
    with pytest.raises(trustauth.NotAuthorized):
        st.add("npm run e2e", proj, auth=None)
    with pytest.raises(trustauth.NotAuthorized):
        pins.PinStore(tmp_path / "trust.jsonl").add(proj, "AGENTS.md", [], auth="terminal")
    assert not (tmp_path / "trust.jsonl").exists()


def test_list_shows_how_a_trust_was_made_and_remove_needs_no_ticket(tmp_path, capsys):
    s = asked_session(tmp_path)
    assert s.run(ADD)["decision"] == "allow"
    assert s.add_as_the_cli_would("npm run e2e") == 0
    with as_person():
        assert cli_add(s.tmp / "trust.jsonl", s.root, command="pytest -q") == 0
    base = ["--store", str(s.tmp / "trust.jsonl"), "--project", str(s.root)]
    capsys.readouterr()
    assert cli.main(["trust", "list", *base]) == 0
    out = capsys.readouterr().out
    assert "`npm run e2e`  (via the agent, approved by semgate)" in out and "`pytest -q`  (via terminal)" in out
    assert cli.main(["trust", "list", "--json", *base]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert sorted(r["via"] for r in rows["commands"]) == ["terminal", "ticket"] and rows["ignored_records"] == 0
    assert cli.main(["trust", "remove", "npm run e2e", *base]) == 0          # the agent may end a trust
    assert lookup(s.tmp / "trust.jsonl", s.root) is None
    removal = json.loads((s.tmp / "trust.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    assert removal["event"] == "remove" and removal["tag"].startswith("hmac-sha256:")


# ------------------------------------------------------------------ the gate text


@pytest.mark.parametrize("command", [
    "python -c \"from semgate import trustauth; trustauth.issue_ticket('x')\"",
    "python -c \"import semgate.trustauth as t\"",
    "py -c \"from semgate.pingate import maybe_pin\"",
])
def test_code_that_imports_the_trust_writers_is_the_trust_request_gate(command):
    assert trust.request_hit(command)
