"""The host adapters semgate ships: install / uninstall / verify / detect.

Installable (unchanged from `semgate init` before this module):
  antigravity  ~/.gemini/config/hooks.json, key "semgate"
  claude       ~/.claude/settings.json, hooks.PreToolUse / PostToolUse / Stop (also read by VS Code agent mode and Devin CLI)
  droid        ~/.factory/hooks.json, PreToolUse / PostToolUse at the top level
  copilot      ~/.copilot/hooks/semgate.json (a file only semgate writes)
  opencode     ~/.config/opencode/plugins/semgate.js (a plugin file only semgate writes)
  codex        $CODEX_HOME/hooks.json, PreToolUse / PostToolUse
  pi           $PI_CODING_AGENT_DIR/extensions/semgate.ts
Detect / doctor only (no semgate installer yet): vscode.

Every JSON edit goes through semgate.safemerge: shape check, text edit that
keeps every other byte, never-looser check, backup, atomic write.

Installed copies (doctor, `semgate init <host> --refresh`): installed_files()
finds every file that holds semgate's hook or plugin: the user-level file,
project-level copies (OpenCode <project>/.opencode/plugin(s)/semgate.js, Pi
<project>/.pi/extensions/semgate.ts; project = --project or the current
folder) and the files `semgate init` recorded in <semgate dir>/
installed_files.json. A file counts only when it carries semgate's mark: the
stamp line (codestamp) or `semgate.serve` for a plugin, a semgate hook entry
for a JSON hooks file. plan_refresh() renders the file again from this
semgate with the interpreter and config the file already names.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .. import codestamp, safemerge
from ..safemerge import Editor, MergePlan, MergeRefused, Parsed
from .base import ConfigPaths, Detection, Finding, HostAdapter, HostEnv, Manifest, load_manifest
from .. import proc

EVENTS = ("PreToolUse", "PostToolUse")
# Claude Code also gets a Stop hook: the secret exposure summary for the user
# (semgate.exposures, manifest C34). It never blocks the stop.
CLAUDE_EVENTS = EVENTS + ("Stop",)
_SEMGATE_MODULES = ("semgate.claude_hook", "semgate.antigravity_hook", "semgate.antigravity_post_hook")


def is_semgate_command(cmd: Any) -> bool:
    return isinstance(cmd, str) and any(m in cmd for m in _SEMGATE_MODULES)


def _is_semgate_hook(h: Any) -> bool:
    return isinstance(h, Mapping) and is_semgate_command(h.get("command"))


# ------------------------------------------------------------ hook documents


def antigravity_entry(interpreter: Path, config: Path) -> Dict[str, Any]:
    pre = f'"{interpreter}" -m semgate.antigravity_hook --config "{config}"'
    post = f'"{interpreter}" -m semgate.antigravity_post_hook --config "{config}"'
    return {
        "enabled": True,
        "PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": pre}]}],
        "PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": post}]}],
    }


def claude_command(interpreter: Path, config: Path, host: str) -> str:
    """The hook command with an explicit --host: init knows which host's
    file it writes. (Before 2026-09-24 claude used --host auto, and
    detect_host answered Claude Code 2.1.281 in Devin's format because the
    event carries prompt_id.) Devin CLI and VS Code also run the hooks in
    ~/.claude/settings.json: with --host claude a Devin-shaped event still
    gets Devin's format (claude_family.resolve_host); VS Code takes Claude's
    format."""
    return f'"{interpreter}" -m semgate.claude_hook --config "{config}" --host {host}'


def claude_groups(interpreter: Path, config: Path, host: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    cmd = claude_command(interpreter, config, host)
    pre_hook = {"type": "command", "command": cmd, "timeout": 30}
    post_hook = {"type": "command", "command": cmd + " --event post", "timeout": 30}
    if host == "codex":
        # Codex uses PowerShell on Windows; the call operator runs a quoted
        # interpreter path, and an explicit exit preserves a nonzero status.
        pre_hook["commandWindows"] = "& " + cmd + "; exit $LASTEXITCODE"
        post_hook["commandWindows"] = "& " + cmd + " --event post; exit $LASTEXITCODE"
    entry = {"matcher": "*", "hooks": [pre_hook]}
    # PostToolUse only records (F6 agent-created files, F4 script changes);
    # it does nothing unless agent_files / script_source are on in semgate.json.
    post = {"matcher": "*", "hooks": [post_hook]}
    return entry, post


def claude_stop_group(interpreter: Path, config: Path) -> Dict[str, Any]:
    """Stop has no matcher. The hook prints {} or {"systemMessage": ...}."""
    return {"hooks": [{"type": "command", "command": claude_command(interpreter, config, "claude") + " --event stop",
                       "timeout": 10}]}


def copilot_doc(interpreter: Path, config: Path) -> Dict[str, Any]:
    cmd = claude_command(interpreter, config, "copilot")
    ps = f'& "{interpreter}" -m semgate.claude_hook --config "{config}" --host copilot'
    return {"version": 1, "hooks": {"preToolUse": [{"type": "command", "bash": cmd, "powershell": ps, "timeoutSec": 30}]}}


# ------------------------------------------------------------ group helpers


def without_semgate(groups: Any) -> list:
    """A hook-group list with semgate's hooks removed. A group that held a
    semgate hook and nothing else is dropped; every other group is kept as is."""
    out = []
    for g in groups if isinstance(groups, list) else []:
        hooks = g.get("hooks") if isinstance(g, Mapping) else None
        if not isinstance(hooks, list) or not any(_is_semgate_hook(h) for h in hooks):
            out.append(g)
            continue
        rest = [h for h in hooks if not _is_semgate_hook(h)]
        if rest:
            g2 = dict(g)
            g2["hooks"] = rest
            out.append(g2)
    return out


def _check_groups(where: str, groups: Any) -> None:
    if groups is None:
        return
    if not isinstance(groups, list):
        raise MergeRefused(f"{where} is a {type(groups).__name__}, expected a list of hook groups; semgate will not guess, fix it by hand")
    for n, g in enumerate(groups):
        if not isinstance(g, Mapping):
            raise MergeRefused(f"{where}[{n}] is a {type(g).__name__}, expected an object with \"hooks\"")
        if not isinstance(g.get("hooks"), list):
            raise MergeRefused(f"{where}[{n}].hooks is missing or not a list")
        for m, h in enumerate(g["hooks"]):
            if not isinstance(h, Mapping):
                raise MergeRefused(f"{where}[{n}].hooks[{m}] is a {type(h).__name__}, expected an object")


def _root_object(doc: Any, path_label: str) -> None:
    if not isinstance(doc, Mapping):
        raise MergeRefused(f"{path_label} holds a JSON {type(doc).__name__}, expected an object")


def _edit_event_arrays(editor: Editor, container, new_container: Mapping[str, Any], append: Mapping[str, Any],
                       events: Sequence[str] = EVENTS) -> None:
    """Text edits for the event arrays (`events`) inside `container` (a
    parsed object node): drop semgate hooks, drop groups that held only
    semgate hooks, append semgate's new group (when given)."""
    missing: List[Tuple[str, Any]] = []
    for ev in events:
        arr = container.member(ev)
        if arr is None:
            if ev in new_container:
                missing.append((ev, new_container[ev]))
            continue
        drop: List[int] = []
        for i, g in enumerate(arr.children):
            hooks_node = g.member("hooks")
            hooks = g.value.get("hooks") or []
            idx = [j for j, h in enumerate(hooks) if _is_semgate_hook(h)]
            if not idx:
                continue
            if len(idx) == len(hooks):
                drop.append(i)
            else:
                editor.rewrite_array(hooks_node, idx, [])
        editor.rewrite_array(arr, drop, [append[ev]] if ev in append else [])
    if missing:
        editor.set_members(container, missing)


def _strip_events(container: Any, events: Sequence[str] = EVENTS) -> Any:
    """`container` without semgate's hooks; empty event lists removed."""
    if not isinstance(container, Mapping):
        return container
    out = dict(container)
    for ev in events:
        if ev in out:
            kept = without_semgate(out[ev])
            if kept:
                out[ev] = kept
            else:
                del out[ev]
    return out


# ------------------------------------------------------------ install request / plan


@dataclass
class InstallRequest:
    target: Path              # semgate's config dir for this host
    hooks_file: Path          # the host file semgate edits (or the plugin file)
    interpreter: Path
    cfg_path: Path            # semgate.json
    mode: str = "enforce"
    provider: str = "typesafe"


@dataclass
class HostPlan:
    """What install/uninstall would write to the host file. `text` None:
    delete the file (uninstall of a semgate-owned file)."""
    path: Path
    text: Optional[str]
    doc: Any                  # the parsed new document (for --dry-run); None for a plugin file
    method: str = "edit"
    note: str = ""
    changed: bool = True


RECORD_FILE = "installed_files.json"
RECORD_SCHEMA = "semgate-installed-files/1"


def _path_key(p: Path) -> str:
    try:
        return os.path.normcase(str(Path(p).resolve()))
    except OSError:
        return os.path.normcase(os.path.abspath(str(p)))


def _existing_unique(paths: Iterable[Optional[Path]]) -> List[Path]:
    out: List[Path] = []
    seen = set()
    for p in paths:
        if p is None:
            continue
        key = _path_key(Path(p))
        if key in seen:
            continue
        try:
            ok = Path(p).is_file()
        except OSError:
            ok = False
        if ok:
            seen.add(key)
            out.append(Path(p))
    return out


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def home_dir(env: HostEnv, where: str) -> Path:
    """A "~/..." default of an adapter, under env.home (tests give a temp home)."""
    return env.home / where[2:] if where.startswith("~/") else Path(where).expanduser()


def recorded_files(folder: Path, host: str) -> List[Path]:
    """The files `semgate init <host>` recorded in <folder>/installed_files.json."""
    try:
        doc = json.loads((Path(folder) / RECORD_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return []
    files = doc.get("files") if isinstance(doc, Mapping) else None
    return [Path(f["path"]) for f in files if isinstance(f, Mapping) and f.get("host") == host
            and isinstance(f.get("path"), str)] if isinstance(files, list) else []


def record_installed(folder: Path, host: str, path: Path, announce: Optional[Callable[[str, Path], None]] = None) -> bool:
    """Add `path` to <folder>/installed_files.json (written by `semgate init`
    only, never by --refresh). True when the record changed."""
    rec = Path(folder) / RECORD_FILE
    try:
        doc = json.loads(rec.read_text(encoding="utf-8")) if rec.is_file() else {}
    except (OSError, ValueError, UnicodeDecodeError):
        doc = {}
    files = [f for f in (doc.get("files") or []) if isinstance(f, Mapping)] if isinstance(doc, Mapping) else []
    if any(f.get("host") == host and _path_key(Path(str(f.get("path", "")))) == _path_key(path) for f in files):
        return False
    files.append({"host": host, "path": str(path)})
    safemerge.safe_write(rec, json.dumps({"schema": RECORD_SCHEMA, "files": files}, indent=2) + "\n", backup=False,
                         announce=announce)
    return True


def refresh_hint(adapter: "HostAdapter", env: HostEnv, path: Path) -> str:
    """The `semgate init <host> --refresh ...` command that rewrites `path`."""
    default = adapter.config_paths(env).hooks_file
    if default is not None and _path_key(default) == _path_key(path):
        return f"semgate init {adapter.name} --refresh"
    for proj in env.project_dirs():
        try:
            Path(path).resolve().relative_to(Path(proj).resolve())
            return f'semgate init {adapter.name} --refresh --project "{proj}"'
        except (ValueError, OSError):
            continue
    return f'semgate init {adapter.name} --refresh --hooks-file "{path}"'


def apply_plan(plan: HostPlan, announce: Callable[[str, Path], None]) -> None:
    if not plan.changed:
        return
    if plan.text is None:
        if plan.path.is_file():
            safemerge.check_write_allowed(plan.path)
            saved = safemerge.backup_path(plan.path)
            safemerge.check_write_allowed(saved)
            plan.path.replace(saved)
            announce("backup", saved)
        return
    safemerge.safe_write(plan.path, plan.text, backup=True, announce=announce)


# ------------------------------------------------------------ JSON hook hosts


class JsonHookHost(HostAdapter):
    """A host whose semgate hook is an entry in a JSON settings/hooks file."""
    jsonc = False

    def merge_plan(self, req: Optional[InstallRequest], remove_only: bool = False) -> MergePlan:
        raise NotImplementedError

    def plan_install(self, req: InstallRequest) -> HostPlan:
        r = safemerge.merge_file(req.hooks_file, self.merge_plan(req))
        return HostPlan(req.hooks_file, r.new_text, r.new_doc, r.method, r.note, r.old_text != r.new_text)

    def plan_uninstall(self, hooks_file: Path) -> HostPlan:
        if not hooks_file.is_file():
            return HostPlan(hooks_file, None, None, "none", "no file", False)
        r = safemerge.merge_file(hooks_file, self.merge_plan(None, remove_only=True))
        return HostPlan(hooks_file, r.new_text, r.new_doc, r.method, r.note, r.old_text != r.new_text)

    # verify -----------------------------------------------------------
    def semgate_commands(self, doc: Any) -> List[str]:
        raise NotImplementedError

    def verify(self, env: HostEnv) -> Tuple[List[Finding], Dict[str, Any]]:
        paths = self.config_paths(env)
        f = paths.hooks_file
        facts: Dict[str, Any] = {"hooks_file": str(f) if f else "", "hook": None}
        if f is None or not f.is_file():
            return [Finding("FAIL", f"semgate hook not installed ({f} missing); run: semgate init {self.name} --purpose \"...\"")], facts
        try:
            doc = safemerge.parse(f.read_text(encoding="utf-8"), jsonc=True).value
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            return [Finding("FAIL", f"{f} cannot be read as JSON ({exc})")], facts
        cmds = self._pre_commands(doc)
        if not cmds:
            return [Finding("FAIL", f"semgate hook not found in {f}")], facts
        out, facts = check_hook_command(cmds[0], facts, self.name, probe=env.version_probe is not None)
        out += self._staleness(env, f, cmds[0])
        for other in self.installed_files(env):
            if _path_key(other) != _path_key(f):
                cmd = next(iter(self._pre_commands(_read_json_quiet(other))), "")
                if cmd:
                    out += self._staleness(env, other, cmd)
        return out, facts

    def _pre_commands(self, doc: Any) -> List[str]:
        return [c for c in (self.semgate_commands(doc) if doc is not None else [])
                if isinstance(c, str) and "--event post" not in c and "--event stop" not in c and "antigravity_post_hook" not in c]

    def _staleness(self, env: HostEnv, path: Path, cmd: str) -> List[Finding]:
        """WARN when `semgate init <host> --refresh` would change semgate's
        entry in `path` (an older command); read only."""
        interp, config = parse_hook_command(cmd)
        if not interp or not config:
            return []
        try:
            plan = self.plan_install(InstallRequest(Path(config).parent, path, Path(interp), Path(config)))
        except (MergeRefused, OSError, ValueError):
            return []
        if not plan.changed:
            return []
        return [Finding("WARN", f"semgate's hook entry in {path} differs from what the installed semgate writes (an older "
                                f"command); run `{refresh_hint(self, env, path)}`")]

    def installed_files(self, env: HostEnv) -> List[Path]:
        paths = self.config_paths(env)
        cands = [paths.hooks_file] + recorded_files(home_dir(env, self.default_dir), self.name)
        return [p for p in _existing_unique(cands) if self._pre_commands(_read_json_quiet(p))]

    def plan_refresh(self, path: Path, force: bool, fallback: Tuple[Path, Path]) -> HostPlan:
        """semgate's entry in `path` written again by this semgate, with the
        interpreter and config the entry names. Refuses a file without a
        semgate entry unless force (then `fallback`: interpreter, config)."""
        doc = _read_json_quiet(path)
        if doc is None and path.is_file():
            raise MergeRefused(f"{path} cannot be read as JSON; semgate will not guess, fix it by hand")
        cmds = self._pre_commands(doc)
        interp, config = parse_hook_command(cmds[0]) if cmds else ("", "")
        if not interp or not config:
            if not force:
                raise MergeRefused(f"{path} has no semgate hook entry; not refreshed (install with `semgate init {self.name}`, "
                                   "or --refresh --force to add it)")
            interp, config = str(fallback[0]), str(fallback[1])
        return self.plan_install(InstallRequest(Path(config).parent, path, Path(interp), Path(config)))

    def hook_configs(self, env: HostEnv) -> List[str]:
        f = self.config_paths(env).hooks_file
        doc = _read_json_quiet(f) if f else None
        if doc is None:
            return []
        out: List[str] = []
        for cmd in self.semgate_commands(doc):
            config = parse_hook_command(cmd)[1]
            if config and config not in out:
                out.append(config)
        return out


def check_hook_command(cmd: str, facts: Dict[str, Any], host: str = "", probe: bool = False) -> Tuple[List[Finding], Dict[str, Any]]:
    """probe: also run `<interpreter> -c "import semgate"` (doctor without
    --no-exec). An interpreter that exists but cannot import semgate (a
    Linux venv hook written as the resolved /usr/bin/python3.x) errors on
    every call."""
    interp, config = parse_hook_command(cmd)
    facts["hook"] = {"interpreter": interp, "config": config}
    interp_ok = bool(interp) and Path(interp).is_file()
    config_ok = bool(config) and Path(config).is_file()
    out: List[Finding] = []
    import_error = _import_error(interp) if probe and interp_ok else ""
    if interp_ok and config_ok and not import_error:
        out.append(Finding("OK", f"hook installed -> {interp}"))
    if not interp_ok:
        out.append(Finding("FAIL", f"hook interpreter missing: {interp or '(not found in the command)'}; the host fails open or errors on every call"))
    if import_error:
        out.append(Finding("FAIL", f"hook interpreter {interp} cannot import semgate ({import_error}); the hook errors on every call "
                                   f"(Claude Code and Codex then run the tool); run `semgate init {host or '<host>'} --force` "
                                   "with the python that has semgate installed"))
    if not config_ok:
        out.append(Finding("FAIL", f"hook config missing: {config or '(no --config in the command)'}"))
    else:
        out += check_semgate_config(Path(config), facts, host)
    return out, facts


def _import_error(interp: str) -> str:
    """"" when `interp -c "import semgate"` works, else the last error line."""
    import subprocess
    try:
        p = proc.run([interp, "-c", "import semgate"], capture_output=True, text=True, timeout=30,
                           stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError) as exc:
        return f"{type(exc).__name__}: {exc}"
    if p.returncode == 0:
        return ""
    lines = [ln for ln in (p.stderr or "").splitlines() if ln.strip()]
    return (lines[-1] if lines else f"exit {p.returncode}")[:200]


_CMD_INTERP = re.compile(r'^\s*(?:&\s*)?"([^"]+)"|^\s*(?:&\s*)?(\S+)')
_CMD_CONFIG = re.compile(r"""--config(?:\s+|=)(?:"([^"]+)"|'([^']+)'|([^\s"']+))""")


def parse_hook_command(cmd: str) -> Tuple[str, str]:
    """(interpreter, --config path) of a hook command. The path may be in
    double or single quotes (spaces allowed inside) or bare, after
    `--config ` or `--config=`."""
    m = _CMD_INTERP.match(cmd or "")
    interp = (m.group(1) or m.group(2) or "") if m else ""
    c = _CMD_CONFIG.search(cmd or "")
    config = (c.group(1) or c.group(2) or c.group(3) or "") if c else ""
    return interp, config


def _block_when_unsure_finding(host: str, on: bool) -> Finding:
    """Doctor's line for enforcement.block_when_unsure, by the same rule as
    `semgate init` (hosts.host_shows_ask): warn when it is off only on a host
    that would not show the ask to a person in every mode."""
    from . import ADAPTERS, host_shows_ask
    shows = host_shows_ask(host)
    name = ADAPTERS[host].display if host in ADAPTERS else "this host"
    if on:
        if shows:
            return Finding("OK", "enforce, block_when_unsure on: every ask is a block you approve in the chat "
                                 f"({name} would show it as its own prompt with block_when_unsure off)")
        return Finding("OK", "enforce, block_when_unsure on")
    if shows:
        return Finding("OK", f"enforce, block_when_unsure off: {name} shows semgate's ask as its own prompt "
                             "(bypass mode included; headless it is a deny)")
    return Finding("WARN", f"enforce without block_when_unsure: {name} does not show semgate's ask as a prompt "
                           "in every mode, so an unsure decision can run unattended; set enforcement.block_when_unsure to true")


def check_semgate_config(path: Path, facts: Dict[str, Any], host: str = "") -> List[Finding]:
    """Fail-closed settings in semgate.json (read only). facts["store_paths"]:
    the absolute store paths the hook uses (semgate.storepaths)."""
    try:
        cfg = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [Finding("FAIL", f"{path} is not valid JSON ({exc}); the hook blocks every call (Claude Code: asks)")]
    if not isinstance(cfg, dict):
        return [Finding("FAIL", f"{path} is not a JSON object")]
    enf = cfg.get("enforcement") if isinstance(cfg.get("enforcement"), dict) else {}
    from .. import enforcement as _enf
    mode = _enf.mode(cfg)          # no "mode" is enforce (the production default)
    facts["semgate"] = {"mode": mode, "enforcement_enabled": enf.get("enabled") is True,
                        "block_when_unsure": enf.get("block_when_unsure") is True,
                        "provider": str(cfg.get("provider", "none"))}
    from .. import storepaths
    host = host or storepaths.guess_host(str(path))
    cfg = storepaths.resolve(cfg, str(path), host)     # the paths as the hook resolves them
    facts["store_base"] = storepaths.base_dir(str(path))
    facts["store_paths"] = [[label, p] for label, p in storepaths.store_paths(cfg, host)]
    out: List[Finding] = []
    fix = f"run `semgate init {host or '<host>'} --force --purpose \"...\"` for a complete enforce config"
    if mode == "enforce" and enf.get("enabled") is True:
        out.append(_block_when_unsure_finding(host, _enf.block_when_unsure(cfg, host or None)))
        tools = [str(t) for t in enf.get("auto_allow_tools") or []]
        if "bash" in tools:
            out.append(Finding("WARN", "bash is in enforcement.auto_allow_tools: a model allow runs any shell command without a human"))
    elif mode == "enforce":
        out.append(Finding("FAIL", "enforcement.enabled is not true: the config is incomplete, so semgate blocks every "
                                   "call on a host that cannot show an ask (asks on Claude Code); " + fix))
    elif mode == "shadow":
        out.append(Finding("WARN", "developer shadow mode: semgate records every call and answers ask, it never "
                                   "denies; production uses enforce: " + fix))
    else:
        out.append(Finding("FAIL", f"unknown mode {mode!r}: semgate blocks every call on a host that cannot show an ask; "
                                   + fix))
    grant = str(cfg.get("grant_file", ""))
    if not grant or not Path(grant).is_file():
        out.append(Finding("FAIL", f"grant file missing: {grant or '(grant_file not set)'}; the hook blocks every call (Claude Code: asks)"))
    else:
        try:
            g = json.loads(Path(grant).read_text(encoding="utf-8"))
            from ..envelope import parse_ts
            import datetime as _dt
            exp = parse_ts(str(g.get("expires_at") or ""))
            if exp is not None and exp <= _dt.datetime.now(_dt.timezone.utc):
                out.append(Finding("WARN", f"grant expired at {g.get('expires_at')}: every call asks"))
        except (OSError, ValueError, AttributeError):
            out.append(Finding("WARN", f"grant file {grant} is not valid JSON"))
    return out


def _read_json_quiet(path: Path) -> Any:
    try:
        return safemerge.load_jsonc(path) if path.is_file() else None
    except (OSError, ValueError, UnicodeDecodeError):
        return None


class AntigravityHost(JsonHookHost):
    name, display = "antigravity", "Antigravity CLI (agy)"
    binary_names = ("agy",)
    manifest_names = ("antigravity",)
    installable = True
    default_dir, default_hooks = "~/.semgate/antigravity", "~/.gemini/config/hooks.json"

    def config_paths(self, env: HostEnv) -> ConfigPaths:
        g = env.home / ".gemini"
        project = [env.project / ".agents" / "hooks.json"] if env.project else []
        return ConfigPaths(user=[g / "config", g], project=project, hooks_file=g / "config" / "hooks.json")

    def merge_plan(self, req: Optional[InstallRequest], remove_only: bool = False) -> MergePlan:
        entry = None if remove_only else antigravity_entry(req.interpreter, req.cfg_path)

        def validate(doc: Any) -> None:
            _root_object(doc, "the hooks file")
            if "semgate" in doc and not isinstance(doc["semgate"], Mapping):
                raise MergeRefused("the \"semgate\" key is not an object; semgate will not overwrite it, fix it by hand")

        def merged(doc: Any) -> Any:
            out = dict(doc)
            if remove_only:
                out.pop("semgate", None)
            else:
                out["semgate"] = entry
            return out

        def strip(doc: Any) -> Any:
            return {k: v for k, v in doc.items() if k != "semgate"} if isinstance(doc, Mapping) else doc

        def edit(ed: Editor, parsed: Parsed) -> None:
            if remove_only:
                ed.remove_members(parsed.root, ["semgate"])
            else:
                ed.set_member(parsed.root, "semgate", entry)

        return MergePlan(validate, merged, strip, edit, jsonc=self.jsonc)

    def semgate_commands(self, doc: Any) -> List[str]:
        entry = doc.get("semgate") if isinstance(doc, Mapping) else None
        if not isinstance(entry, Mapping):
            return []
        return [h.get("command") for ev in EVENTS for g in entry.get(ev) or [] if isinstance(g, Mapping)
                for h in g.get("hooks") or [] if _is_semgate_hook(h)]

    def verify(self, env: HostEnv) -> Tuple[List[Finding], Dict[str, Any]]:
        out, facts = super().verify(env)
        if env.project and (env.project / ".agents" / "hooks.json").is_file():
            out.append(Finding("INFO", "project .agents/hooks.json exists but agy 1.2.8 does not load project hooks"))
        return out, facts

    def mode_warnings(self, env: HostEnv) -> List[Finding]:
        out = []
        for f in (env.home / ".gemini" / "settings.json", env.home / ".gemini" / "config" / "config.json"):
            doc = _read_json_quiet(f)
            mode = _approval_mode(doc)
            if mode:
                out.append(Finding("WARN", f"{f.name}: approval mode {mode!r} runs tools without agy's own prompts; semgate is then the only gate "
                                           "(key names from Gemini CLI settings; not verified on agy 1.2.8)"))
        return out


def _approval_mode(doc: Any) -> str:
    if not isinstance(doc, Mapping):
        return ""
    general = doc.get("general") if isinstance(doc.get("general"), Mapping) else {}
    tools = doc.get("tools") if isinstance(doc.get("tools"), Mapping) else {}
    for value in (general.get("defaultApprovalMode"), doc.get("defaultApprovalMode"), doc.get("approvalMode")):
        if isinstance(value, str) and value.lower() in ("yolo", "auto_edit"):
            return value
    for key, value in (("yolo", doc.get("yolo")), ("autoAccept", doc.get("autoAccept")), ("tools.autoAccept", tools.get("autoAccept"))):
        if value is True:
            return key
    return ""


class ClaudeFamilyHost(JsonHookHost):
    """Claude Code (hooks under "hooks") and Droid (hooks at the top level)."""
    nested = True     # hooks live under the "hooks" key
    events: Tuple[str, ...] = EVENTS
    stop_hook = False

    def merge_plan(self, req: Optional[InstallRequest], remove_only: bool = False) -> MergePlan:
        append: Dict[str, Any] = {}
        events = self.events
        if not remove_only:
            entry, post = claude_groups(req.interpreter, req.cfg_path, self.name)
            append = {"PreToolUse": entry, "PostToolUse": post}
            if self.stop_hook:
                append["Stop"] = claude_stop_group(req.interpreter, req.cfg_path)
        nested = self.nested
        label = "hooks" if nested else "the hooks file"

        def container_of(doc: Any) -> Any:
            return doc.get("hooks") if nested else doc

        def validate(doc: Any) -> None:
            _root_object(doc, "the settings file" if nested else "the hooks file")
            c = container_of(doc)
            if nested and c is not None and not isinstance(c, Mapping):
                raise MergeRefused(f"\"hooks\" is a {type(c).__name__}, expected an object; semgate will not guess, fix it by hand")
            for ev in events:
                _check_groups(f"{label}.{ev}" if nested else ev, (c or {}).get(ev))

        def merged_container(c: Any) -> Dict[str, Any]:
            out = dict(c or {})
            for ev in events:
                if ev in append:
                    out[ev] = without_semgate(out.get(ev)) + [append[ev]]
                elif ev in out:
                    out[ev] = without_semgate(out[ev])
            return out

        def merged(doc: Any) -> Any:
            out = dict(doc)
            if nested:
                if remove_only and "hooks" not in out:
                    return out
                out["hooks"] = merged_container(out.get("hooks"))
                return out
            return merged_container(out)

        def strip(doc: Any) -> Any:
            if not isinstance(doc, Mapping):
                return doc
            if not nested:
                return _strip_events(doc, events)
            out = dict(doc)
            if isinstance(out.get("hooks"), Mapping):
                h = _strip_events(out["hooks"], events)
                if h:
                    out["hooks"] = h
                else:
                    del out["hooks"]
            return out

        def edit(ed: Editor, parsed: Parsed) -> None:
            root = parsed.root
            if nested:
                node = root.member("hooks")
                if node is None:
                    if not remove_only:
                        ed.set_member(root, "hooks", merged(parsed.value)["hooks"])
                    return
            else:
                node = root
            new_c = merged_container(node.value)
            _edit_event_arrays(ed, node, new_c, append, events)

        return MergePlan(validate, merged, strip, edit, jsonc=self.jsonc)

    def semgate_commands(self, doc: Any) -> List[str]:
        c = (doc.get("hooks") if self.nested else doc) if isinstance(doc, Mapping) else None
        if not isinstance(c, Mapping):
            return []
        return [h.get("command") for ev in self.events for g in c.get(ev) or [] if isinstance(g, Mapping)
                for h in g.get("hooks") or [] if _is_semgate_hook(h)]


class ClaudeHost(ClaudeFamilyHost):
    name, display = "claude", "Claude Code"
    binary_names = ("claude",)
    manifest_names = ("claude",)
    installable = True
    default_dir, default_hooks = "~/.semgate/claude", "~/.claude/settings.json"
    events = CLAUDE_EVENTS
    stop_hook = True

    def _dir(self, env: HostEnv) -> Path:
        return env.dir_from("CLAUDE_CONFIG_DIR", env.home / ".claude")

    def config_paths(self, env: HostEnv) -> ConfigPaths:
        d = self._dir(env)
        project = [env.project / ".claude" / "settings.json", env.project / ".claude" / "settings.local.json"] if env.project else []
        return ConfigPaths(user=[d], project=project, hooks_file=d / "settings.json")

    def mode_warnings(self, env: HostEnv) -> List[Finding]:
        paths = self.config_paths(env)
        out = []
        for f in [paths.hooks_file] + paths.project:
            doc = _read_json_quiet(f) if f else None
            perms = doc.get("permissions") if isinstance(doc, Mapping) and isinstance(doc.get("permissions"), Mapping) else {}
            if perms.get("defaultMode") == "bypassPermissions":
                out.append(Finding("WARN", f"{f}: permissions.defaultMode is bypassPermissions, Claude Code shows none of its own prompts; semgate's hook is the only gate"))
        return out


class DroidHost(ClaudeFamilyHost):
    name, display = "droid", "Factory Droid"
    nested = False
    binary_names = ("droid",)
    manifest_names = ("droid",)
    installable = True
    default_dir, default_hooks = "~/.semgate/droid", "~/.factory/hooks.json"

    def config_paths(self, env: HostEnv) -> ConfigPaths:
        d = env.home / ".factory"
        return ConfigPaths(user=[d], hooks_file=d / "hooks.json")


class CopilotHost(JsonHookHost):
    """Deprioritized by the owner: kept exactly as it was, nothing new."""
    name, display = "copilot", "GitHub Copilot CLI"
    binary_names = ("copilot",)
    manifest_names = ()
    installable = True
    default_dir, default_hooks = "~/.semgate/copilot", "~/.copilot/hooks/semgate.json"

    def manifest(self, version: str = "") -> Manifest:
        return load_manifest("copilot")

    def config_paths(self, env: HostEnv) -> ConfigPaths:
        d = env.home / ".copilot"
        return ConfigPaths(user=[d], hooks_file=d / "hooks" / "semgate.json")

    def merge_plan(self, req: Optional[InstallRequest], remove_only: bool = False) -> MergePlan:
        # The file is semgate's own (hooks/semgate.json): it is replaced whole.
        new = {} if remove_only else copilot_doc(req.interpreter, req.cfg_path)

        def edit(ed: Editor, parsed: Parsed) -> None:
            ed.replace_value(parsed.root, new)

        return MergePlan(lambda doc: None, lambda doc: new, lambda doc: None, edit)

    def semgate_commands(self, doc: Any) -> List[str]:
        hooks = ((doc or {}).get("hooks") or {}).get("preToolUse") if isinstance(doc, Mapping) else None
        return [h.get("bash") for h in hooks or [] if isinstance(h, Mapping) and is_semgate_command(h.get("bash"))]


# ------------------------------------------------------------ OpenCode (plugin file)


# The interpreter and config a copy names. Copies written before 2026-09-27
# read them as `process.env.SEMGATE_PYTHON || "..."` (an environment
# override, removed: a variable of the host's environment could pick the
# program and the config); newer copies have the value only. Both are read.
_PLUGIN_PY = re.compile(r'const PYTHON = (?:process\.env\.SEMGATE_PYTHON \|\| )?"([^"]*)"')
_PLUGIN_CFG = re.compile(r'const CONFIG = (?:process\.env\.SEMGATE_CONFIG \|\| )?"([^"]*)"')
_PLUGIN_PY_PI = re.compile(r'const PYTHON = (?:process\.env\.SEMGATE_PYTHON \|\| )?("(?:\\.|[^"\\])*")')
_PLUGIN_CFG_PI = re.compile(r'const CONFIG = (?:process\.env\.SEMGATE_CONFIG \|\| )?("(?:\\.|[^"\\])*")')


class PluginFileHost(HostAdapter):
    """A host whose semgate hook is a plugin file only semgate writes
    (OpenCode, Pi): rendered from semgate/assets with the interpreter and
    config filled in and a stamp line first (codestamp)."""

    def _candidates(self, env: HostEnv) -> List[Path]:
        raise NotImplementedError

    def wiring(self, text: str) -> Tuple[str, str]:
        """(interpreter, config) written in a copy."""
        raise NotImplementedError

    def render(self, interpreter: Path, config: Path) -> str:
        raise NotImplementedError

    @property
    def asset(self) -> str:
        return codestamp.ASSETS[self.name]

    def detect(self, env: HostEnv) -> Detection:
        """Also installed when only a project-level copy exists (no binary
        under a known name on PATH, no user config folder)."""
        det = super().detect(env)
        if not det.installed and self.installed_files(env):
            return Detection(True, "", "", "", "semgate plugin copy")
        return det

    def installed_files(self, env: HostEnv) -> List[Path]:
        def ours(paths: Iterable[Optional[Path]]) -> List[Path]:
            return [p for p in _existing_unique(paths) if codestamp.is_semgate_copy(_read_text(p))]
        found = ours(list(self._candidates(env)) + recorded_files(home_dir(env, self.default_dir), self.name))
        extra: List[Path] = []
        for p in found:            # `semgate init --dir D` recorded its copies in D
            config = self.wiring(_read_text(p))[1]
            if config:
                extra += recorded_files(Path(os.path.expanduser(config)).parent, self.name)
        return ours(found + extra) if extra else found

    def plan_refresh(self, path: Path, force: bool, fallback: Tuple[Path, Path]) -> HostPlan:
        """The copy at `path` rendered again from this semgate's asset, with
        the interpreter and config it names. Refuses a missing file or one
        without semgate's stamp or marker unless force (then `fallback`:
        interpreter, config)."""
        text = _read_text(path) if path.is_file() else None
        if text is None and not force:
            raise MergeRefused(f"{path} does not exist; nothing to refresh (install with `semgate init {self.name}`)")
        if text is not None and not codestamp.is_semgate_copy(text) and not force:
            raise MergeRefused(f"{path} carries no semgate stamp or marker; not overwritten (--refresh --force replaces it)")
        interp, config = self.wiring(text or "")
        if not interp or not config:
            if not force:
                raise MergeRefused(f"{path}: the interpreter and config it uses cannot be read; not refreshed "
                                   f"(--refresh --force writes {fallback[0]} and {fallback[1]})")
            interp, config = str(fallback[0]), str(fallback[1])
        new = self.render(Path(interp), Path(config))
        return HostPlan(path, new, None, "plugin", "", new != text)


def verify_plugin_copies(adapter: PluginFileHost, env: HostEnv, missing: str, install: str) -> Tuple[List[Finding], Dict[str, Any]]:
    """Doctor for a plugin host: every installed copy (user level, project,
    recorded), its interpreter and config (checked once per pair), its stamp
    against the asset in this semgate, and the plugin the running host
    loaded (the latest serve_event `client` in the ledger)."""
    copies = adapter.installed_files(env)
    default = adapter.config_paths(env).hooks_file
    facts: Dict[str, Any] = {"hooks_file": str(copies[0] if copies else default), "hook": None, "copies": []}
    if not copies:
        where = ", ".join(str(p) for p in adapter._candidates(env))
        return [Finding("FAIL", f"{missing} (looked in {where}); run: {install}")], facts
    out: List[Finding] = []
    checked = set()
    probe = env.version_probe is not None
    for p in copies:
        text = _read_text(p)
        interp, config = adapter.wiring(text)
        status, detail = codestamp.copy_status(text, adapter.asset)
        facts["copies"].append({"path": str(p), "status": status, "detail": detail, "interpreter": interp, "config": config})
        if (interp, config) not in checked:
            cmd = f'"{interp}" -m semgate.serve --stdio --config "{config}"'
            if not checked:
                found, facts = check_hook_command(cmd, facts, adapter.name, probe=probe)
            else:
                found, _ = check_hook_command(cmd, {}, adapter.name, probe=probe)
                found = [Finding(f.level, f"{p}: {f.text}") for f in found]
            checked.add((interp, config))
            out += found
        if status != "current":
            out.append(Finding("WARN", f"plugin copy {p} is older than the installed semgate ({detail}); run "
                                       f"`{refresh_hint(adapter, env, p)}`, then restart {adapter.display}"))
    out += running_plugin_findings(adapter, [c["config"] for c in facts["copies"]])
    return out, facts


def last_serve_client(ledger_path: str, host: str, tail: int = 512 * 1024) -> Optional[Dict[str, Any]]:
    """The latest serve_event `client` record of `host` in the last `tail`
    bytes of the ledger (read only), or None."""
    try:
        with open(ledger_path, "rb") as handle:
            handle.seek(0, 2)
            end = handle.tell()
            handle.seek(max(0, end - tail))
            data = handle.read()
    except OSError:
        return None
    for line in reversed(data.decode("utf-8", "replace").splitlines()):
        if '"serve_event"' not in line:
            continue
        try:
            r = json.loads(line)
        except ValueError:
            continue
        detail = r.get("detail") if isinstance(r, Mapping) else None
        if r.get("record_type") == "serve_event" and r.get("event") == "client" and isinstance(detail, Mapping) \
                and detail.get("host") == host:
            return r
    return None


def running_plugin_findings(adapter: HostAdapter, configs: Sequence[str]) -> List[Finding]:
    from .. import storepaths
    out: List[Finding] = []
    for cfg in dict.fromkeys(c for c in configs if c):
        try:
            config = storepaths.load(cfg, adapter.name)
        except (OSError, ValueError, UnicodeDecodeError):
            continue
        rec = last_serve_client(storepaths.ledger_file(config), adapter.name)
        detail = rec.get("detail") if rec else None
        if isinstance(detail, Mapping) and detail.get("outdated") is True:
            out.append(Finding("WARN", f"the plugin loaded in a running {adapter.display} is older than the installed semgate "
                                       f"(serve pid {detail.get('pid')} at {rec.get('ts')}: "
                                       f"{detail.get('plugin_stamp') or 'no stamp'}); {adapter.display} keeps the plugin it "
                                       f"loaded at start: refresh the copy if it is old, then restart {adapter.display}"))
    return out


class OpenCodeHost(PluginFileHost):
    name, display = "opencode", "OpenCode"
    binary_names = ("opencode", "opencode2")      # opencode2: the V2 preview binary (docs/skill.md)
    manifest_names = ("opencode-v1", "opencode-v2")
    installable = True
    default_dir, default_hooks = "~/.semgate/opencode", "~/.config/opencode/plugins/semgate.js"

    def manifest(self, version: str = "") -> Manifest:
        return load_manifest("opencode-v2" if version.startswith("2.") else "opencode-v1")

    def config_paths(self, env: HostEnv) -> ConfigPaths:
        d = env.config_home() / "opencode"
        project = [env.project / "opencode.json", env.project / "opencode.jsonc", env.project / ".opencode"] if env.project else []
        return ConfigPaths(user=[d], project=project, hooks_file=d / "plugins" / "semgate.js")

    def plan_install(self, req: InstallRequest) -> HostPlan:
        from ..init_antigravity import opencode_plugin_source
        text = opencode_plugin_source(req.interpreter, req.cfg_path)
        return HostPlan(req.hooks_file, text, None, "plugin", "", True)

    def plan_uninstall(self, hooks_file: Path) -> HostPlan:
        if not hooks_file.is_file():
            return HostPlan(hooks_file, None, None, "none", "no file", False)
        text = hooks_file.read_text(encoding="utf-8", errors="replace")
        if "semgate.serve" not in text:
            raise MergeRefused(f"{hooks_file} does not look like semgate's plugin; not removed")
        return HostPlan(hooks_file, None, None, "delete")

    def _candidates(self, env: HostEnv) -> List[Path]:
        """OpenCode loads plugins from {plugin,plugins}/ in its config folder
        and in <project>/.opencode/."""
        d = env.config_home() / "opencode"
        home_d = env.home / ".config" / "opencode"
        out = [d / sub / "semgate.js" for sub in ("plugins", "plugin")]
        out += [home_d / sub / "semgate.js" for sub in ("plugins", "plugin")]
        for proj in env.project_dirs():
            out += [proj / ".opencode" / sub / "semgate.js" for sub in ("plugins", "plugin")]
        return out

    def wiring(self, text: str) -> Tuple[str, str]:
        py, cfg = _PLUGIN_PY.search(text), _PLUGIN_CFG.search(text)
        return (py.group(1) if py else ""), (cfg.group(1) if cfg else "")

    def render(self, interpreter: Path, config: Path) -> str:
        from ..init_antigravity import opencode_plugin_source
        return opencode_plugin_source(interpreter, config)

    def verify(self, env: HostEnv) -> Tuple[List[Finding], Dict[str, Any]]:
        out, facts = verify_plugin_copies(self, env, "semgate plugin not installed",
                                          "semgate init opencode --purpose \"...\"")
        out.append(Finding("INFO", "the plugin refuses semgate's asks (OpenCode has no plugin ask); timeouts and crashes refuse too"))
        return out, facts

    def hook_configs(self, env: HostEnv) -> List[str]:
        paths = self.config_paths(env)
        out: List[str] = []
        for f in (paths.hooks_file, env.home / ".config" / "opencode" / "plugins" / "semgate.js"):
            try:
                text = f.read_text(encoding="utf-8", errors="replace") if f and f.is_file() else ""
            except OSError:
                continue
            cfg = _PLUGIN_CFG.search(text)
            if cfg and cfg.group(1) and cfg.group(1) not in out:
                out.append(cfg.group(1))
        return out

    def mode_warnings(self, env: HostEnv) -> List[Finding]:
        d = env.config_home() / "opencode"
        files = [d / "opencode.json", d / "opencode.jsonc", d / "config.json"]
        if env.project:
            files += [env.project / "opencode.json", env.project / "opencode.jsonc"]
        out = []
        for f in files:
            what = _opencode_allows_bash(_read_json_quiet(f))
            if what:
                out.append(Finding("WARN", f"{f}: {what}, OpenCode runs shell commands without its own prompt; semgate's plugin is the only gate"))
        return out


def _opencode_allows_bash(doc: Any) -> str:
    if not isinstance(doc, Mapping):
        return ""
    perm = doc.get("permission")
    if perm == "allow":
        return 'permission is "allow"'
    if isinstance(perm, Mapping):
        bash = perm.get("bash")
        if bash == "allow":
            return 'permission.bash is "allow"'
        if isinstance(bash, Mapping) and bash.get("*") == "allow":
            return 'permission.bash "*" is "allow"'
        if perm.get("*") == "allow" and "bash" not in perm:
            return 'permission "*" is "allow"'
    return ""


# ------------------------------------------------------------ Codex and detect/doctor-only hosts


class CodexHost(ClaudeFamilyHost):
    name, display = "codex", "Codex CLI"
    binary_names = ("codex",)
    manifest_names = ("codex",)
    installable = True
    default_dir, default_hooks = "~/.semgate/codex", "~/.codex/hooks.json"

    def config_paths(self, env: HostEnv) -> ConfigPaths:
        d = env.dir_from("CODEX_HOME", env.home / ".codex")
        return ConfigPaths(user=[d], project=[env.project / ".codex"] if env.project else [], hooks_file=d / "hooks.json")

    def mode_warnings(self, env: HostEnv) -> List[Finding]:
        f = self.config_paths(env).user[0] / "config.toml"
        vals = _toml_top_level(f)
        out = []
        if vals.get("approval_policy") == "never":
            out.append(Finding("WARN", f"{f}: approval_policy = \"never\", Codex never asks; a hook is then the only gate"))
        if vals.get("sandbox_mode") == "danger-full-access":
            out.append(Finding("WARN", f"{f}: sandbox_mode = \"danger-full-access\", no sandbox"))
        return out


def _toml_top_level(path: Path) -> Dict[str, Any]:
    """Top-level string keys of a TOML file (read only; tomllib when present)."""
    if not path.is_file():
        return {}
    try:
        import tomllib  # Python 3.11+
        with open(path, "rb") as handle:
            data = tomllib.load(handle)
        return {k: v for k, v in data.items() if not isinstance(v, dict)}
    except ImportError:
        pass
    except (OSError, ValueError):
        return {}
    out: Dict[str, Any] = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if s.startswith("["):
                break
            m = re.match(r'^([A-Za-z0-9_\-]+)\s*=\s*"([^"]*)"', s)
            if m:
                out[m.group(1)] = m.group(2)
    except (OSError, UnicodeDecodeError):
        return {}
    return out


class PiHost(PluginFileHost):
    name, display = "pi", "Pi"
    binary_names = ("pi",)
    manifest_names = ("pi",)
    installable = True
    default_dir, default_hooks = "~/.semgate/pi", "~/.pi/agent/extensions/semgate.ts"

    def config_paths(self, env: HostEnv) -> ConfigPaths:
        d = env.dir_from("PI_CODING_AGENT_DIR", env.home / ".pi" / "agent")
        return ConfigPaths(user=[d], project=[env.project / ".pi"] if env.project else [],
                           hooks_file=d / "extensions" / "semgate.ts")

    def plan_install(self, req: InstallRequest) -> HostPlan:
        from ..init_antigravity import pi_extension_source
        path = req.hooks_file
        if path.is_file() and "semgate.serve" not in path.read_text(encoding="utf-8", errors="replace"):
            raise MergeRefused(f"{path} is not semgate's Pi extension; it will not be replaced")
        text = pi_extension_source(req.interpreter, req.cfg_path)
        old = path.read_text(encoding="utf-8") if path.is_file() else None
        return HostPlan(path, text, None, "plugin", changed=old != text)

    def plan_uninstall(self, hooks_file: Path) -> HostPlan:
        if not hooks_file.is_file():
            return HostPlan(hooks_file, None, None, "none", "no file", False)
        if "semgate.serve" not in hooks_file.read_text(encoding="utf-8", errors="replace"):
            raise MergeRefused(f"{hooks_file} is not semgate's Pi extension; it will not be removed")
        return HostPlan(hooks_file, None, None, "delete")

    def _candidates(self, env: HostEnv) -> List[Path]:
        out = [self.config_paths(env).hooks_file]
        out += [proj / ".pi" / "extensions" / "semgate.ts" for proj in env.project_dirs()]
        return out

    def wiring(self, text: str) -> Tuple[str, str]:
        py, cfg = _PLUGIN_PY_PI.search(text), _PLUGIN_CFG_PI.search(text)
        try:
            return (json.loads(py.group(1)) if py else ""), (json.loads(cfg.group(1)) if cfg else "")
        except ValueError:
            return "", ""

    def render(self, interpreter: Path, config: Path) -> str:
        from ..init_antigravity import pi_extension_source
        return pi_extension_source(interpreter, config)

    def verify(self, env: HostEnv) -> Tuple[List[Finding], Dict[str, Any]]:
        out, facts = verify_plugin_copies(self, env, "semgate Pi extension not installed", "semgate init pi --purpose \"...\"")
        out += self.trust_findings(env, facts)
        out.append(Finding("INFO", "Pi has no permission prompts; semgate's asks are blocked by the extension"))
        return out, facts

    @staticmethod
    def trust_findings(env: HostEnv, facts: Dict[str, Any]) -> List[Finding]:
        """A project-level copy loads only when Pi trusts the project
        (hosts/pitrust.py). WARN, with the fix, unless trust.json or
        defaultProjectTrust says trusted; "unknown" also warns."""
        from . import pitrust
        out: List[Finding] = []
        facts["pi_trust"] = []
        for copy in facts.get("copies") or []:
            path = Path(copy["path"])
            project = pitrust.project_of(path, env)
            if project is None:
                continue
            st = pitrust.trust_status(project, env)
            facts["pi_trust"].append({"path": str(path), "project": str(st.project), "status": st.status, "why": st.why})
            lines = pitrust.warning_lines(path, st)
            if lines:
                out.append(Finding("WARN", "\n      ".join(lines)))
            else:
                out.append(Finding("INFO", f"{path}: Pi trusts project {st.project} ({st.why})"))
        return out

    def hook_configs(self, env: HostEnv) -> List[str]:
        path = self.config_paths(env).hooks_file
        if path is None or not path.is_file():
            return []
        cfg = _PLUGIN_CFG_PI.search(path.read_text(encoding="utf-8", errors="replace"))
        try:
            return [json.loads(cfg.group(1))] if cfg else []
        except ValueError:
            return []

    def mode_warnings(self, env: HostEnv) -> List[Finding]:
        return [Finding("INFO", "Pi has no permission prompts at all: any hook is the only gate (docs/usage.md)")]


class VSCodeHost(HostAdapter):
    """Settings check only: VS Code agent mode reads ~/.claude/settings.json hooks."""
    name, display = "vscode", "VS Code agent mode"
    binary_names = ("code",)
    manifest_names = ()          # no manifest: its hook rendering is the legacy one (hosts.base.LEGACY_UNMANIFESTED)

    def settings_files(self, env: HostEnv) -> List[Path]:
        out = []
        appdata = env.environ.get("APPDATA", "")
        bases = [Path(appdata)] if appdata else []
        bases += [env.home / "Library" / "Application Support", env.config_home()]
        for base in bases:
            for flavor in ("Code", "Code - Insiders"):
                out.append(base / flavor / "User" / "settings.json")
        return out

    def config_paths(self, env: HostEnv) -> ConfigPaths:
        files = self.settings_files(env)
        return ConfigPaths(user=[f.parent for f in files], project=[env.project / ".vscode" / "settings.json"] if env.project else [])

    def verify(self, env: HostEnv) -> Tuple[List[Finding], Dict[str, Any]]:
        return [Finding("INFO", "hooks come from ~/.claude/settings.json (see the claude line)")], {"hook": None}

    def mode_warnings(self, env: HostEnv) -> List[Finding]:
        out = []
        files = self.settings_files(env) + (self.config_paths(env).project or [])
        for f in files:
            doc = _read_json_quiet(f)
            if not isinstance(doc, Mapping):
                continue
            for key in ("chat.tools.autoApprove", "chat.tools.global.autoApprove"):
                if doc.get(key) is True:
                    out.append(Finding("WARN", f"{f}: {key} is true, VS Code runs agent tools without its own prompts; a hook is then the only gate"))
        return out
