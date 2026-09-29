"""`semgate init <host>`: one command that wires semgate into an agent CLI with
the safe defaults. Hosts: antigravity, claude (+ VS Code agent mode and Devin
CLI, which read ~/.claude/settings.json), droid, copilot.

Writes, outside any agent workspace (default ~/.semgate/antigravity):
  semgate.json   the hook config: a complete enforce config (mode enforce,
                 enforcement.enabled true, block_when_unsure from the host's
                 manifest, the dev policy with chat approval on). The
                 developer switch `--mode shadow` (record only) is hidden
                 from --help; see docs/development.md.
  grant.json     an operator-authored grant: purpose + expiry, nothing derived
                 from the agent
and registers the hook in ~/.gemini/config/hooks.json (user level: agy 1.2.8
no longer loads project-level .agents/hooks.json), using THIS interpreter so
the hook process has semgate, typesafe-sdk and python-dotenv. It also writes
the `semgate` agent skill into the host's user-level skills folder
(semgate/skill.py; --no-skill skips it): what the agent must do with an ask,
a block, a hard deny, and a user's request to trust a command.

Never overwrites an existing semgate.json / grant.json unless --force. The
per-host logic (which file, which entry) is in semgate/hosts; every host file
edit goes through semgate/safemerge.py: refuse on invalid JSON or an
unexpected shape, keep every byte that is not semgate's entry, never loosen,
backup, atomic write.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import getpass
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict

from .gate import POLICY_ALIASES

READ_ONLY_TOOLS = ["read", "view_file", "read_url_content", "ls", "grep", "glob"]


def _hosts():
    from . import hosts
    return hosts


def _defaults() -> Dict[str, Any]:
    h = _hosts()
    return {n: (h.get(n).default_dir, h.get(n).default_hooks) for n in h.installable()}


# host: (default config dir, default hooks file). claude's file is also read by
# VS Code agent mode and Devin CLI; opencode's is a plugin file, not JSON.
HOST_DEFAULTS = _defaults()


def _hooks_file(host: str, explicit: str, default: str, adapter: Any) -> Path:
    if explicit:
        return Path(explicit).expanduser().resolve()
    if host in ("codex", "pi"):
        from .hosts.base import HostEnv
        configured = adapter.config_paths(HostEnv.current(run_binaries=False)).hooks_file
        if configured is not None:
            return configured.expanduser().resolve()
    return Path(default).expanduser().resolve()


def merge_hooks(host: str, existing: Dict[str, Any], interpreter: Path, config: Path) -> Dict[str, Any]:
    """Return the host's hooks/settings document with semgate registered
    (pure; the file itself is edited by semgate.safemerge)."""
    from .hosts.builtin import InstallRequest
    adapter = _hosts().get(host)
    plan = adapter.merge_plan(InstallRequest(Path("."), Path("."), interpreter, config))
    plan.validate(existing)
    return plan.merged(existing)


def block_when_unsure_for(host: str) -> bool:
    """The block_when_unsure value `init` writes for `host`: off only where the
    host shows semgate's ask to a person in every mode (hosts.host_shows_ask,
    from the manifests: Claude Code today). Everywhere else an ask could run
    the tool unattended or is already a deny, so it is a block the user
    approves in the chat."""
    return not _hosts().host_shows_ask(host)


def _config(target: Path, policy: Path, mode: str, provider: str, host: str = "") -> Dict[str, Any]:
    p = lambda name: str((target / name).as_posix())  # noqa: E731
    return {
        "mode": mode,
        "grant_file": p("grant.json"),
        "policy_file": str(policy.as_posix()),
        "provider": provider or "none",   # cli.main turns --provider none into None (for judge); the hook config needs the name
        "ledger_file": p("ledger.jsonl"),
        "auto_allow_learned": {"enabled": False, "history_file": p("tool_history.jsonl")},
        "feedback": {"enabled": True, "feedback_file": p("feedback.jsonl")},
        # F4 (semgate/scriptsource.py): read the local script a command runs
        # (bash run_tests.sh, python x.py), gate its content and give it to
        # the judge. The dev policy's effect/executes questions are written
        # for it ("When `script_source` is present ..."); without it every
        # script run is judged blind and asks (hookconf e2e run-tests).
        "script_source": True,
        # Code-checked git facts (restore_status, S1 history rewrite, S2
        # manifest edits): a change git can undo is judged as restorable.
        "git_facts": True,
        # F6: files the agent created this session (hash + snapshot), so
        # deleting one it just made, unchanged, counts as restorable. The
        # store lives next to the other stores, not in ~/.semgate.
        "agent_files": {"enabled": True, "dir": str(target.as_posix())},
        "enforcement": {
            "enabled": mode == "enforce",
            # Read-only tools may auto-run on a semgate allow. bash is NOT here on
            # purpose: a shell command auto-runs only after a human approved that
            # exact command (semgate feedback allow "<command>").
            "auto_allow_tools": list(READ_ONLY_TOOLS),
            # True: every ask is a block (approve in the chat). False only on a
            # host that shows the ask as its own prompt in every mode, bypass
            # included (block_when_unsure_for; an unknown host gets True).
            "block_when_unsure": block_when_unsure_for(host),
            "deny_escalation": {"enabled": True, "consecutive": 3, "total": 20, "state_file": p("deny_streak.json")},
        },
    }


def opencode_plugin_source(interpreter: Path, config: Path) -> str:
    """The OpenCode plugin as `semgate init opencode` writes it: the stamp
    line first (codestamp.stamp_line), then the asset with the interpreter,
    the config and the stamp filled in. Same inputs, same bytes."""
    from . import codestamp
    name = codestamp.ASSETS["opencode"]
    src = codestamp.asset_source(name).replace("\r\n", "\n")
    body = (src.replace("__SEMGATE_PYTHON__", interpreter.as_posix()).replace("__SEMGATE_CONFIG__", config.as_posix())
            .replace(codestamp.ASSET_PLACEHOLDER, codestamp.stamp(name)))
    return codestamp.stamp_line(name) + "\n" + body


def pi_extension_source(interpreter: Path, config: Path) -> str:
    from . import codestamp
    name = codestamp.ASSETS["pi"]
    src = codestamp.asset_source(name).replace("\r\n", "\n")
    body = (src.replace("__SEMGATE_PYTHON__", json.dumps(str(interpreter))).replace("__SEMGATE_CONFIG__", json.dumps(str(config)))
            .replace(codestamp.ASSET_PLACEHOLDER, json.dumps(codestamp.stamp(name))))
    return codestamp.stamp_line(name) + "\n" + body


def principal() -> str:
    """The OS user name for grant.json, never an exception. getpass.getuser()
    raises OSError on Windows when USERNAME (and LOGNAME, USER, LNAME) are
    unset (no pwd module there). Fallback: USER, USERNAME, then "unknown"."""
    try:
        name = getpass.getuser()
    except Exception:
        name = ""
    name = (name or os.environ.get("USER") or os.environ.get("USERNAME") or "").strip()
    return name or "unknown"


# grant_id prefix per host; any other host uses its own name ("pi-20260927").
# antigravity keeps "agy-", the prefix every grant written before had.
GRANT_ID_PREFIX = {"antigravity": "agy"}


def _grant(purpose: str, days: int, project: str, host: str = "antigravity") -> Dict[str, Any]:
    """The grant `semgate init <host>` writes. grant_id and provenance name the
    real host. Nothing reads either value to decide anything (grant loading
    checks only that they are strings), so grants written before, with
    "agy-" and "semgate init antigravity" for every host, still load."""
    now = _dt.datetime.now(_dt.timezone.utc)
    g: Dict[str, Any] = {
        "grant_id": f"{GRANT_ID_PREFIX.get(host, host)}-{now.strftime('%Y%m%d')}",
        "principal": principal(),
        "purpose": purpose,
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + _dt.timedelta(days=days)).isoformat().replace("+00:00", "Z"),
        "allowed_domains": [],
        "forbidden_patterns": [],
        "provenance": f"written by `semgate init {host}`; edit by hand, never from the agent",
    }
    if project:
        g["allowed_path_prefixes"] = [str(Path(project).resolve().as_posix())]
    return g


def _check_interpreter(provider: str) -> list:
    problems = []
    for mod, why in (("semgate", "the hook itself"), ("typesafe_sdk", "the Jev provider"), ("dotenv", "reading TYPESAFE_API_KEY from .env")):
        if provider != "typesafe" and mod != "semgate":
            continue
        if importlib.util.find_spec(mod) is None:
            problems.append(f"{mod} is not importable from {sys.executable} ({why}); run: pip install 'semgate[typesafe]'")
    # The key: the same places, in the same order, as the provider reads it
    # (providers/keys.py: SEMGATE_<NAME>, ~/.semgate/.env, the checkout .env,
    # in a git worktree the main checkout's .env, then the environment).
    # OpenRouter is standard library HTTP: no typesafe-sdk, no python-dotenv.
    from .providers import keys
    if provider in keys.KEY_ENV and not keys.key_status(provider)["found"]:
        name, home_env = keys.KEY_ENV[provider], keys.env_files()[0][1]
        problems.append(f"{name} not found: put '{name}=...' in {home_env} (or set it as a user "
                        "environment variable). Without it the hook abstains (asks) on every semantic call.")
    return problems


def _pi_trust_notice(hooks_file: Path) -> None:
    """A project-level Pi extension (<project>/.pi/extensions/semgate.ts)
    loads only when Pi trusts the project; `pi -p` skips it without a
    message. Say so, with the fix, unless Pi's trust.json or
    defaultProjectTrust says trusted. Reads Pi's files; never writes them."""
    from .hosts import pitrust
    from .hosts.base import HostEnv
    env = HostEnv.current(run_binaries=False)
    project = pitrust.project_of(hooks_file, env)
    if project is None:
        return
    st = pitrust.trust_status(project, env)
    lines = pitrust.warning_lines(hooks_file, st)
    if not lines:
        print(f"{'Pi project trust: trusted':42} {st.project} ({st.why})")
        return
    print(f"WARNING: {lines[0]}")
    for line in lines[1:]:
        print(line)


def _announce(state: str, path: Path) -> None:
    print(f"{state:42} {path}")


DEMO_PURPOSE = "semgate demo: software development in this project: read, edit, build, test"
DEMO_BLOCK_WARNING = ("WARNING: demo mode: most commands get 'ask'; this host turns an ask into a block, so most commands "
                      "will be blocked; Claude Code shows them as prompts instead")


def _resolve_demo(args: argparse.Namespace) -> str:
    """--demo: provider recorded (no key) and a default purpose. The mode is
    enforce, with or without --demo, unless the hidden developer switch
    --mode shadow is given. Returns an error text, or ""."""
    demo = bool(getattr(args, "demo", False))
    # --provider not given: "" (the parser default). `--provider none` arrives as
    # None (cli.main turns "none" into None) and stays None: deterministic layers only.
    provider = getattr(args, "provider", "")
    if demo and provider not in ("", "recorded"):
        return "--demo uses the recorded provider; do not combine it with --provider"
    if demo:
        args.provider = "recorded"
    elif provider == "":
        args.provider = "typesafe"
    if getattr(args, "mode", None) is None:
        # Production has one mode: enforce. Shadow is the hidden developer switch.
        args.mode = "enforce"
    if not getattr(args, "purpose", ""):
        if not demo:
            return "--purpose is required (what the operator authorises), e.g. 'Software development in ~/code/myapp'"
        args.purpose = DEMO_PURPOSE
    return ""


def run_refresh(args: argparse.Namespace) -> int:
    """`semgate init <host> --refresh`: write semgate's plugin / extension /
    hook entry and the agent skill again from THIS semgate. Never touches
    semgate.json, grant.json, the ledger or any store, and never
    installed_files.json. Targets: --hooks-file F only; else every installed
    copy (hosts.builtin installed_files: user level, --project P or the
    current folder, recorded by init). Each copy keeps the interpreter and
    config it names. A rewritten file is backed up first (timestamped
    .semgate-bak-*). A file without semgate's stamp or marker is refused
    unless --force (then this python and <--dir or default>/semgate.json)."""
    from .hosts.base import HostEnv
    from .hosts.builtin import apply_plan
    from .safemerge import MergeRefused
    adapter = _hosts().get(args.host)
    if not hasattr(adapter, "plan_refresh"):
        print(f"semgate init {args.host} --refresh: no refresh for this host", file=sys.stderr)
        return 2
    default_dir, _ = HOST_DEFAULTS[args.host]
    fallback = (Path(os.path.abspath(sys.executable)), Path(args.dir or default_dir).expanduser().resolve() / "semgate.json")
    env = HostEnv.current(project=args.project or None, run_binaries=False)
    if args.hooks_file:
        targets = [Path(args.hooks_file).expanduser().resolve()]
    else:
        targets = adapter.installed_files(env)
    status = 0
    if not targets:
        print(f"semgate init {args.host} --refresh: no installed copy found (looked at user level, "
              f"{', '.join(str(p) for p in env.project_dirs()) or 'no project'} and the files init recorded); "
              f"install with `semgate init {args.host} --purpose \"...\"`", file=sys.stderr)
        status = 2
    rewritten = 0
    for path in targets:
        try:
            plan = adapter.plan_refresh(path, bool(args.force), fallback)
            if not plan.changed:
                print(f"{'unchanged (current)':42} {path}")
                continue
            if args.dry_run:
                print(f"{'would refresh':42} {path}")
                continue
            apply_plan(plan, _announce)
            print(f"{'refreshed':42} {path}")
            rewritten += 1
        except MergeRefused as exc:
            print(f"semgate init {args.host} --refresh: {exc}", file=sys.stderr)
            status = 2
    if not getattr(args, "no_skill", False):
        from . import skill
        where = skill.path_for(args.host)
        if where is not None and where.is_file():          # refresh an installed skill; never add a missing one
            state, where = skill.install(args.host, dry_run=args.dry_run, announce=_announce)
            print(f"{'skill: ' + state:42} {where if where is not None else ''}".rstrip())
        else:
            print(f"{'skill: not installed, not written':42} {where if where is not None else ''}".rstrip())
    print("semgate.json, grant.json, the ledger and the stores were not touched.")
    if rewritten:
        print(f"Restart {adapter.display}: a running host keeps the plugin or hook it loaded at start.")
    return status


def chat_approval_line(policy: Path) -> str:
    """One line for `semgate init`: is approval by chat reply on in the
    policy the config names (router.chat_approval)?"""
    try:
        from .policy import Policy
        from . import chatapproval
        pol = Policy.load(str(policy))
        on = chatapproval.enabled(pol) and chatapproval.threshold(pol) is not None
    except Exception as exc:
        return f"WARNING: chat approval: the policy {policy} could not be read ({type(exc).__name__})"
    if on:
        clarify = chatapproval.clarify_threshold(pol)
        band = f", unclear replies from p {clarify:.2f}" if clarify is not None else ""
        return (f"{'chat approval: on':42} a clear yes in the chat approves one blocked action "
                f"(p >= {chatapproval.threshold(pol):.2f}{band})")
    return (f"WARNING: chat approval is off in {policy.name} (router.chat_approval): a block is approved only with "
            "`semgate feedback allow` in your own terminal. The default policy (--policy dev) has it on.")


def _config_mode(path: Path) -> str:
    """The `mode` of a semgate.json ("" when it cannot be read)."""
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    return str(doc.get("mode") or "") if isinstance(doc, dict) else ""


def weakening_lines(args: argparse.Namespace, cfg_path: Path, grant_path: Path, adapter: Any) -> list:
    """What this `semgate init` run lowers ([] when nothing): an overwrite of
    an existing semgate.json or grant.json (--force), or a switch of the
    installed hook from an enforce config to a shadow one (the developer
    switch). The CLI then asks for the typed word (adminguard.guard)."""
    out = []
    if args.force and cfg_path.exists():
        old = _config_mode(cfg_path) or "unreadable"
        out.append(f"--force replaces {cfg_path} (mode {old} -> {args.mode}).")
    if args.force and grant_path.exists():
        out.append(f"--force replaces {grant_path} (the grant: purpose, paths, expiry).")
    if args.mode == "shadow" and not (args.force and cfg_path.exists()):
        from .hosts.base import HostEnv
        try:
            current = adapter.hook_configs(HostEnv.current(run_binaries=False))
        except Exception:
            current = []
        for raw in current:
            old_path = Path(os.path.expanduser(raw))
            same = os.path.normcase(os.path.abspath(old_path)) == os.path.normcase(os.path.abspath(cfg_path))
            if not same and _config_mode(old_path) == "enforce":
                out.append(f"the installed {args.host} hook uses {old_path} (mode enforce); after this it uses "
                           f"{cfg_path} in developer shadow mode: semgate records and never denies.")
    if out:
        out.insert(0, f"semgate init {args.host} lowers the protection semgate gives now:")
    return out


def run(args: argparse.Namespace, guard: bool = True) -> int:
    """`semgate init <host>`. `guard`: the CLI's check that a person runs
    this in their own terminal (adminguard.guard); False only for callers
    that are the person's own test harness in-process (scripts/live_*.py)."""
    from .hosts.builtin import InstallRequest, apply_plan, record_installed
    from .safemerge import MergeRefused, check_write_allowed, safe_write
    from . import adminguard
    if getattr(args, "refresh", False):
        if guard and not args.dry_run:
            code = adminguard.guard(f"init {args.host} --refresh")
            if code:
                return code
        return run_refresh(args)
    problem = _resolve_demo(args)
    if problem:
        print(f"semgate init {args.host}: {problem}", file=sys.stderr)
        return 2
    adapter = _hosts().get(args.host)
    default_dir, default_hooks = HOST_DEFAULTS[args.host]
    target = Path(args.dir or default_dir).expanduser().resolve()
    hooks_file = _hooks_file(args.host, args.hooks_file, default_hooks, adapter)
    if guard and not args.dry_run:
        code = adminguard.guard(f"init {args.host}",
                                weakening_lines(args, target / "semgate.json", target / "grant.json", adapter))
        if code:
            return code
    # Absolute, NOT resolved: a Linux venv's bin/python is a symlink to
    # /usr/bin/python3.x, which cannot import the semgate installed in the
    # venv (the hook then fails on every call).
    interpreter = Path(os.path.abspath(sys.executable))
    policy = POLICY_ALIASES.get(args.policy, Path(args.policy)).resolve()
    if not policy.is_file():
        print(f"policy not found: {policy}", file=sys.stderr)
        return 2
    cfg_path, grant_path = target / "semgate.json", target / "grant.json"
    cfg = _config(target, policy, args.mode, args.provider, args.host)
    grant = _grant(args.purpose, args.days, args.project, args.host)
    req = InstallRequest(target, hooks_file, interpreter, cfg_path, args.mode, args.provider)
    try:
        # Computes the new host file; writes nothing. Refuses on invalid JSON,
        # an unexpected shape, or any change outside semgate's own entry.
        plan = adapter.plan_install(req)
    except MergeRefused as exc:
        print(f"semgate init {args.host}: {exc}", file=sys.stderr)
        if exc.snippet:
            print(exc.snippet)
        return 2
    keep_cfg = cfg_path.exists() and not args.force
    keep_grant = grant_path.exists() and not args.force
    for path, kept in ((cfg_path, keep_cfg), (grant_path, keep_grant), (hooks_file, False)):
        state = "keep (exists; use --force to overwrite)" if kept else ("would write" if args.dry_run else "write")
        if path == hooks_file and not plan.changed:
            state = "unchanged (semgate entry is current)"
        print(f"{state:42} {path}")
    if plan.note:
        print(f"{'note':42} {plan.note}")
    if args.dry_run:
        shown: Dict[str, Any] = {"semgate.json": cfg, "grant.json": grant}
        if plan.doc is not None:
            shown[hooks_file.name] = plan.doc
        print(json.dumps(shown, indent=2))
    else:
        try:
            for path in (cfg_path, grant_path, hooks_file):
                check_write_allowed(path)
            target.mkdir(parents=True, exist_ok=True)
            if not keep_cfg:
                safe_write(cfg_path, json.dumps(cfg, indent=2) + "\n", backup=True, announce=_announce)
            if not keep_grant:
                safe_write(grant_path, json.dumps(grant, indent=2) + "\n", backup=True, announce=_announce)
            apply_plan(plan, _announce)
            # Where this copy is, so doctor and `init --refresh` find it from any folder.
            record_installed(target, args.host, hooks_file, _announce)
        except MergeRefused as exc:
            print(f"semgate init {args.host}: {exc}", file=sys.stderr)
            return 2

    if not getattr(args, "no_skill", False):
        from . import skill
        state, where = skill.install(args.host, dry_run=args.dry_run, announce=_announce)
        print(f"{'skill: ' + state:42} {where if where is not None else ''}".rstrip())
        cmd = skill.command()
        print(f"{'skill: the agent runs semgate as':42} {cmd}")
        # A program path outside the project is fine: rules.check_grant_scope
        # lets exactly this install's own command through (own_program_words).

    for problem in _check_interpreter(args.provider):
        print(f"WARNING: {problem}")
    if args.host == "pi":
        _pi_trust_notice(hooks_file)
    if args.provider == "recorded":
        if keep_cfg:
            print(f"WARNING: {cfg_path} exists and was kept, so demo mode is NOT on. Rerun with --force, or use --dir <another folder>.")
        print()
        print("DEMO MODE (no key). semgate's fixed rules and human gates run for real. A model question gets an answer")
        print("only for the exact inputs recorded for `semgate demo`; everything else asks (fails closed). Every reason")
        print("the agent or you see starts with [semgate DEMO ...]. Run `semgate demo` to see the recorded scenarios.")
        print("For live Jev: put TYPESAFE_API_KEY=... in ~/.semgate/.env and run this again without --demo, with --force")
        print("(or OPENROUTER_API_KEY=... and --provider openrouter).")
        if args.mode == "enforce" and cfg["enforcement"]["block_when_unsure"] and not keep_cfg:
            print(DEMO_BLOCK_WARNING)
    print(chat_approval_line(policy))
    if args.mode == "shadow":
        print("DEVELOPER SHADOW MODE: semgate records every call and answers ask for every call, it never denies "
              "(docs/development.md). Production uses enforce: run this again without --mode shadow, with --force.")
    m = adapter.manifest()
    print(f"Host capabilities (semgate/data/hosts): {m.conformance_line() if m.loaded else f'no manifest for {args.host} (not measured)'}")
    if args.host == "opencode":
        print("\nNext: restart OpenCode (1.18.29+ or 2.x) and ask the agent to run `git status`; the ledger should record it:")
        print(f"  {target / 'ledger.jsonl'}")
        print("  OpenCode has no reliable plugin 'ask': semgate's asks are refused with the reason. To let one exact command run:")
        print(f"  semgate feedback allow \"<command>\" --store {target / 'feedback.jsonl'}")
        return 0
    print()
    print("Next:")
    print(f"  1. Edit {grant_path} - the purpose is what the agent is allowed to do; keep the expiry short.")
    if args.host == "antigravity":
        print(f"  2. Try it headless: agy --add-dir <project folder> -p \"list the files in the project\"")
    else:
        print(f"  2. Restart {args.host} and ask the agent to run `git status`; the ledger should record it.")
    print(f"  3. Read the judgments: {target / 'ledger.jsonl'}")
    print("  Keep this folder OUT of any workspace you hand to the agent; it will read whatever it can see.")
    return 0


def _uninstall_skill(args: argparse.Namespace) -> None:
    from . import skill
    state, where = skill.uninstall(args.host, dry_run=args.dry_run)
    if where is not None:
        print(f"{'skill: ' + state:42} {where}")


def run_uninstall(args: argparse.Namespace, guard: bool = True) -> int:
    from .hosts.builtin import apply_plan
    from .safemerge import MergeRefused
    from . import adminguard
    adapter = _hosts().get(args.host)
    default_dir, default_hooks = HOST_DEFAULTS[args.host]
    hooks_file = _hooks_file(args.host, args.hooks_file, default_hooks, adapter)
    if guard and not args.dry_run:
        refused = adminguard.refuse_agent(f"uninstall {args.host}")
        if refused:
            print(refused, file=sys.stderr)
            return 2
    try:
        plan = adapter.plan_uninstall(hooks_file)
        if not plan.changed:
            print(f"{'nothing to remove':42} {hooks_file}")
            _uninstall_skill(args)
            return 0
        print(f"{'would remove semgate from' if args.dry_run else 'remove semgate from':42} {hooks_file}")
        if not args.dry_run:
            if guard:
                code = adminguard.guard(f"uninstall {args.host}", [
                    f"semgate uninstall {args.host} removes semgate from {hooks_file}.",
                    f"{adapter.display} then runs its tools without semgate."])
                if code:
                    return code
            apply_plan(plan, _announce)
    except MergeRefused as exc:
        print(f"semgate uninstall {args.host}: {exc}", file=sys.stderr)
        if exc.snippet:
            print(exc.snippet)
        return 2
    _uninstall_skill(args)
    print(f"semgate.json, grant.json and the ledger in {Path(default_dir).expanduser()} (or your --dir) are kept.")
    return 0


def add_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("init", help="Wire semgate into a host with safe defaults (writes config + grant, registers the hook)")
    p.add_argument("host", choices=sorted(HOST_DEFAULTS), help="antigravity (agy 1.2.8+); claude (also covers VS Code agent mode and Devin CLI); codex (0.153.1 hooks); droid (Factory); copilot (GitHub Copilot CLI); opencode (V1 and V2); pi (0.86.0 extension)")
    p.add_argument("--purpose", default="", help="what the operator authorises, e.g. 'Software development in ~/code/myapp: read, edit, build, test' (required, except with --demo)")
    p.add_argument("--dir", default="", help="where semgate.json, grant.json and the ledger live (default ~/.semgate/<host>, outside any workspace)")
    p.add_argument("--project", default="", help="optional project folder; becomes the grant's allowed_path_prefixes")
    # Enforce is the only production mode. `--mode shadow` is the developer
    # switch (record only): accepted, hidden from --help (docs/development.md).
    p.add_argument("--mode", choices=["enforce", "shadow"], default=None, help=argparse.SUPPRESS)
    p.add_argument("--policy", default="dev", help="'dev' (autonomous dev agent), 'default' (strict), or a policy file path")
    p.add_argument("--provider", choices=["typesafe", "openrouter", "none", "recorded"], default="", help="'typesafe' (default) = live Jev with a TypeSafe key; 'openrouter' = live Jev through OpenRouter (OPENROUTER_API_KEY, model typesafe/jev-1.13); 'none' = deterministic layers only, everything else asks; 'recorded' = demo mode (same as --demo)")
    p.add_argument("--demo", action="store_true", help="try semgate without a key: the recorded provider (only the demo's recorded inputs get a model answer, everything else asks) and a default purpose")
    p.add_argument("--days", type=int, default=30, help="grant validity in days")
    p.add_argument("--hooks-file", default="", help="the host's user-level hooks/settings file (default per host)")
    p.add_argument("--force", action="store_true", help="overwrite an existing semgate.json / grant.json")
    p.add_argument("--dry-run", action="store_true", help="print what would be written; write nothing")
    p.add_argument("--no-skill", action="store_true", help="do not write the semgate agent skill (docs/skill.md)")
    p.add_argument("--refresh", action="store_true",
                   help="rewrite only semgate's plugin / extension / hook entry and the skill from this semgate (backup "
                        "first); every installed copy, or only --hooks-file; --project (default: the current folder) for "
                        "project copies. Never touches semgate.json, grant.json, the ledger or the stores. With --force it "
                        "also replaces a file that has no semgate stamp or marker")
    p.set_defaults(func=run)

    u = sub.add_parser("uninstall", help="Remove semgate's hook/plugin from a host (backup first; keeps semgate.json, grant and ledger)")
    u.add_argument("host", choices=sorted(HOST_DEFAULTS))
    u.add_argument("--hooks-file", default="", help="the host's user-level hooks/settings file (default per host)")
    u.add_argument("--dry-run", action="store_true", help="print what would change; write nothing")
    u.set_defaults(func=run_uninstall)

