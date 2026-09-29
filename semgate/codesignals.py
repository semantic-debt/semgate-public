"""Code-checked signals (policy `router.code_signals`, off by default: `true`
means S1+S2, a list names the signals to compute; S6 is in no default).

Facts that code checks about the proposed action, given to the model as the
state key `code_signals`, like `restore_status`. The model still decides; a
signal is evidence it weighs, never a decision and never an instruction.
Each line starts with "checked by code:". Only signals that fire are sent;
with none, the key is omitted and the state is exactly as before.

S1 history rewrite. The command amends, resets, rebases, force-pushes,
   filter-branches or update-refs, i.e. it rewrites commits. A history object
   (gitstate.GitHistory live, gitstate.SyntheticHistory in evals) says whether
   the commits it changes were made before the session started. Fires when at
   least one was, or when that cannot be checked (the text says so). Does not
   fire when every changed commit was made in this session or the command
   changes no existing commit. `git reset --hard` with no commit (discard
   working changes) is not S1; the restore logic covers it.

S2 unrequested dependency manifest edit. The command writes a dependency
   manifest or lockfile (sed -i, >, >>, tee, an editor tool, mv/cp onto it,
   rm), and no user turn, no earlier step and the operator purpose mention
   that file name or the package being changed (taken from the edit when it
   names one). Tool output is not searched: it is untrusted and could be
   written to suppress the signal.

S3 the agent's stated claim contradicts the tool results (opt-in: only when the
   policy lists "S3_claim_contradicts_results" in router.code_signals). A
   short, fixed set of English patterns reads claims from agent_intent (the
   agent's own latest text): tests fail / tests pass, build fails / build
   passes, the previous command failed, the fix works, and a file permission
   or write access problem. Sentences with a condition, a hedge, a negation or
   a time shift ("if", "might", "no longer", "before", ...) give no claim, and
   a text that claims both pass and fail for the same thing gives none either.
   Evidence is the exit status in recent step results ("exit N", "ok",
   "error"; never the output text, which the tested code can print). A test
   or build command counts only when its exit status is its own: it is the
   last command of its line, there is no `||`, no `!`, no background `&` (so
   `pytest | tail` or `pytest || true` is not evidence), and it is not stale
   (no later step wrote a code file: editor tools, redirects, tee, sed -i,
   cp/mv/rm, patch, git checkout/restore/...; docs, images, logs, lockfiles
   and /tmp do not count). Fires only on a contradiction with evidence present
   (e.g. "tests fail" while the latest test command exited 0 and no test
   command in the window failed). The permission claim is the one case where
   absence is the evidence: it fires when none of the recent step results or
   outputs shows a permission error, at least one result exists, and no user
   turn talks about permissions. Unknown phrasing, no test command, or an
   unknown exit status: no signal.

S3_last_check (opt-in, separate id): with agent_intent present, the status of
   the latest test and build command as a neutral fact ("... exited 0, and no
   step after it changed a code file" / "... may be out of date" / "has no
   exit status"), for the model to compare with agent_intent. No line when
   the latest such command's exit status is not its own, or when an S3 line
   already states it.

S4 test damage (opt-in: only when the policy lists "S4_test_damage"). The
   action weakens the project's tests: an editor edit (old/new text, a full
   write, or a diff) or a shell command (sed/perl -i, rm, git rm, mv, git mv,
   find -delete, truncate, a redirect or heredoc into the file) that removes
   or renames test functions or cases, adds a skip / xfail / focus marker
   (pytest.mark.skip/skipif/xfail, pytest.skip(), unittest skip, skipTest,
   collect_ignore, @Disabled, @Ignore, it.skip/describe.skip/test.skip,
   xit/xdescribe, .only, fit/fdescribe, t.Skip, #[ignore], __test__ = False),
   deletes a test file or moves it out of test collection, or empties it.
   Fires only when no user turn has a skip/disable/remove word together with
   that file, folder or test name. Not checked: files the agent created in
   this session (by the trajectory, or by the git facts when they are on:
   agent_created, untracked, missing, ignored) and Python test_*.py files
   directly in the project root (SWE agents write their scratch reproduce and
   test scripts there). Ordinary test edits (a new test, a changed assertion)
   give no signal.

S6 link placement (opt-in: only when the policy lists "S6_link_placement").
   The command creates a link (ln, cp -s/-l; linkplace.py) at a path that is
   not written in the command: ln was given an existing folder as its last
   path (/, ., .., ~, a path ending in /, or a folder the workspace confirms
   on disk), more than two paths, one path, or -t DIR. The line says which
   link is created, what it points to, why it lands there, that the path
   given first is the target and not a new link, and whether the link is
   outside the project folder. Example (nl2sh:253, `ln /workspace/dir1 -s /`):
   "checked by code: this command creates the symbolic link /dir1, pointing
   to /workspace/dir1. / is an existing folder (the root folder), and when
   the last path given to ln is an existing folder, ln creates the link
   inside that folder, named after the other path; /workspace/dir1 is the
   link's target, not a new link; /dir1 is outside the project folder
   /workspace/project". A link at a path the command names (`ln -s AGENTS.md
   CLAUDE.md`), and a last path not known to be a folder, give no line. The
   human gate persistence_link (rules.py) is separate and always on.
   Links made by Python or Node code (inline `python -c` / `node -e` /
   heredocs, or a script file F4 read; linkplace.code_links) give one line
   per source when the link path is a literal, e.g. "checked by code: this
   command runs Python code that calls os.symlink and creates the symbolic
   link /tmp/x, pointing to /workspace/dir1; os.symlink(a, b) creates the
   link b, pointing to a; /tmp/x is outside the project folder
   /workspace/project". Not for a script file with instruction markers.

S1, S2 and S4 need only the command or editor arguments, the user's turns,
the trajectory, the cwd and (for S1) git; S3 needs agent_intent and the
trajectory results. All work the same for every host adapter.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from . import shellparse
from .envelope import Envelope

MAX_SIGNALS = 4

S1_ID = "S1_history_rewrite"
S2_ID = "S2_dependency_manifest"
S3_ID = "S3_claim_contradicts_results"
S3F_ID = "S3_last_check"
S4_ID = "S4_test_damage"
# S5 payload size (opt-in): computed by semgate.payloadsize from the hook
# payload, not from the envelope; listed here so a policy can switch it on.
S5_ID = "S5_payload_size"
S6_ID = "S6_link_placement"
ALL_IDS = (S1_ID, S2_ID, S3_ID, S3F_ID, S4_ID, S5_ID, S6_ID)
# What `router.code_signals: true` means: the signals adopted into dev on
# 2026-09-23. S3 is only on when a policy lists it.
DEFAULT_IDS = frozenset({S1_ID, S2_ID})

# ---------- shared shell walking ----------


def _base(word: str) -> str:
    return word.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _join(cwd: str, path: str) -> str:
    """Resolve `path` against `cwd` without touching the disk. "" when either
    is unknown or the path uses a variable."""
    if not path or "$" in path or "`" in path:
        return ""
    if path.startswith("~"):
        import os
        return os.path.expanduser(path)
    if path.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", path):
        return path
    if not cwd:
        return ""
    sep = "\\" if (re.match(r"^[A-Za-z]:[\\/]", cwd) and "/" not in cwd) else "/"
    return (cwd.rstrip("/\\") + sep + path) if path not in (".", "./") else cwd


def _simples(command: str, cwd: str) -> Iterable[Tuple[List[str], List[shellparse.Token], str]]:
    """(argv values, tokens, cwd) per simple command, top level first, then
    code the command runs from strings (bash -c '...', $(...)). A `cd X` at
    top level changes the cwd for the commands after it."""
    try:
        top = shellparse.split_commands(command)
    except Exception:
        top = []
    here = cwd
    for simple in top:
        argv = [t.value for t in shellparse.effective_argv(simple.tokens)]
        if argv and _base(argv[0]) in ("cd", "pushd", "set-location", "sl", "chdir"):
            target = next((a for a in argv[1:] if not a.startswith("-")), "")
            here = _join(here, target) if target else here
            continue
        yield argv, simple.tokens, here
    try:
        inner = shellparse.extract_scripts(command)
    except Exception:
        inner = []
    for code in inner:
        try:
            for simple in shellparse.split_commands(code):
                argv = [t.value for t in shellparse.effective_argv(simple.tokens)]
                yield argv, simple.tokens, cwd
        except Exception:
            continue


# ---------- S1: history rewrite ----------

_GIT_VALUE_OPTS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env"}
_RESET_MODES = {"--hard", "--soft", "--mixed", "--keep", "--merge"}
_COMMITISH = re.compile(r"^(?:HEAD|@|ORIG_HEAD|FETCH_HEAD)(?:[~^]\d*)+$|^[0-9a-fA-F]{7,40}(?:[~^]\d*)*$")
_REBASE_STOP = {"--abort", "--quit", "--continue", "--skip", "--edit-todo", "--show-current-patch"}
_REBASE_VALUE_OPTS = {"--onto", "-x", "--exec", "-s", "--strategy", "-X", "--strategy-option", "-C", "--whitespace"}


@dataclass(frozen=True)
class Rewrite:
    kind: str                     # amend | reset | rebase | force_push | filter | update_ref
    what: str                     # plain words for the signal text
    info: Mapping[str, Any]       # revs etc. for gitstate.GitHistory
    cwd: str                      # where git runs ("" = unknown)


def _git_call(argv: Sequence[str], cwd: str) -> Optional[Tuple[str, List[str], str]]:
    if not argv:
        return None
    prog = _base(argv[0])
    if prog in ("git-filter-repo", "git-filter-repo.exe"):
        return "filter-repo", list(argv[1:]), cwd
    if prog not in ("git", "git.exe"):
        return None
    i = 1
    while i < len(argv):
        a = argv[i]
        if a in _GIT_VALUE_OPTS and i + 1 < len(argv):
            if a == "-C":
                cwd = _join(cwd, argv[i + 1])
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        break
    if i >= len(argv):
        return None
    return argv[i], list(argv[i + 1:]), cwd


def _positional(args: Sequence[str], value_opts: Iterable[str] = ()) -> List[str]:
    out, skip = [], False
    opts = set(value_opts)
    for a in args:
        if skip:
            skip = False
            continue
        if a == "--":
            break
        if a in opts:
            skip = True
            continue
        if a.startswith("-"):
            continue
        out.append(a)
    return out


def rewrite_of(sub: str, args: Sequence[str], cwd: str) -> Optional[Rewrite]:
    if sub == "commit" and "--amend" in args:
        return Rewrite("amend", "amends the last commit", {}, cwd)
    if sub == "reset":
        pos = _positional(args)
        target = pos[0] if pos else ""
        if not target or target in ("HEAD", "@"):
            return None                 # discard working changes: covered by restore logic, not S1
        mode = any(a in _RESET_MODES for a in args)
        if mode or _COMMITISH.match(target):
            return Rewrite("reset", f"moves the branch to {target[:40]}", {"revs": [target]}, cwd)
        return None
    if sub == "rebase":
        if any(a in _REBASE_STOP for a in args):
            return None
        pos = _positional(args, _REBASE_VALUE_OPTS)
        return Rewrite("rebase", "rebases commits", {"revs": pos[:2], "root": "--root" in args}, cwd)
    if sub == "push":
        pos = _positional(args, {"--repo", "-o", "--push-option", "--receive-pack", "--exec"})
        forced = any(a in ("-f", "--force") or a.startswith("--force-with-lease")
                     or (a.startswith("-") and not a.startswith("--") and "f" in a[1:]) for a in args)
        forced = forced or any(p.startswith("+") for p in pos[1:])
        if not forced:
            return None
        info: Dict[str, Any] = {}
        if len(pos) >= 2:
            spec = pos[1].lstrip("+")
            src, _, dst = spec.partition(":")
            dst = dst or src
            if dst.startswith("refs/heads/"):
                dst = dst[len("refs/heads/"):]
            if dst and dst != "HEAD":
                info["tracking"] = f"refs/remotes/{pos[0]}/{dst}"
            if src and src != "HEAD":
                info["source"] = src
        return Rewrite("force_push", "force-pushes over the remote branch", info, cwd)
    if sub in ("filter-branch", "filter-repo"):
        return Rewrite("filter", "rewrites every commit of the branch history", {}, cwd)
    if sub == "update-ref":
        if "--stdin" in args:
            return Rewrite("update_ref", "moves refs directly", {"stdin": True}, cwd)
        pos = _positional(args, {"-m"})
        return Rewrite("update_ref", "moves a ref directly", {"revs": pos[:2], "delete": "-d" in args}, cwd)
    return None


def history_rewrites(command: str, cwd: str) -> List[Rewrite]:
    out: List[Rewrite] = []
    for argv, _tokens, here in _simples(command, cwd):
        call = _git_call(argv, here)
        if call is None:
            continue
        rw = rewrite_of(*call)
        if rw is not None and all((rw.kind, rw.what) != (o.kind, o.what) for o in out):
            out.append(rw)
    return out


# ---------- S2: dependency manifest edit ----------

MANIFESTS = frozenset(n.lower() for n in (
    "pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock", "pdm.lock",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.toml", "Cargo.lock", "go.mod", "go.sum",
    "Gemfile", "Gemfile.lock", "composer.json", "composer.lock"))
_REQUIREMENTS = re.compile(r"^requirements[\w.\-]*\.txt$", re.I)

_IN_PLACE = {"sed", "gsed", "perl"}
_DELETE = {"rm", "unlink", "shred", "truncate", "del", "erase", "remove-item", "ri"}
_DEST = {"mv", "cp", "install", "move", "copy", "move-item", "copy-item", "mi", "cpi"}
_PS_WRITE = {"set-content", "add-content", "out-file", "clear-content", "sc", "ac"}
_TEE = {"tee", "tee-object"}
_EDITOR_TOOLS = {"edit", "write", "multiedit", "str_replace_editor", "str_replace_based_edit_tool", "create",
                 "replace_file_content", "multi_replace_file_content", "write_to_file", "write_file", "replace"}
_PATH_KEYS = ("path", "file_path", "filePath", "TargetFile", "AbsolutePath", "target_file")
_NEW_KEYS = {"new_string", "newstring", "new_str", "content", "file_text", "codecontent", "replacementcontent", "text"}
_OLD_KEYS = {"old_string", "oldstring", "old_str", "targetcontent"}

# A package name directly followed by a version constraint, as written in
# requirements files, sed patterns over them, pyproject/Cargo tables
# (name = "1.2") and package.json ("name": "^1.2").
_PKG_RE = re.compile(
    r"(?<![\w.\-/\\@])([A-Za-z][A-Za-z0-9_.\-]*[A-Za-z0-9])"
    r"(?:\[[A-Za-z][\w,.\- ]*\])?"
    r"[\s)\\]*"
    r"(?:===?|>=|<=|~=|!=|<|>|\^|@\s*\^?\d|\[[<>=!~^]|=\s*[\"']\s*[\^~<>=]?\s*\d|\"\s*:\s*\"\s*[\^~<>=]?\s*\d)")
_NOT_PACKAGES = {"version", "name", "python_requires", "requires-python", "line-length"}
_BARE_REQ = re.compile(r"^\s*([A-Za-z][A-Za-z0-9_.\-]*[A-Za-z0-9])(?:\[[\w,.\- ]*\])?\s*$")


def is_manifest(path: str) -> bool:
    name = _base(path.strip().strip("'\""))
    return bool(name) and (name in MANIFESTS or bool(_REQUIREMENTS.match(name)))


def package_names(text: str) -> List[str]:
    out: List[str] = []
    for m in _PKG_RE.finditer(text or ""):
        name = m.group(1)
        if name.lower() in _NOT_PACKAGES or is_manifest(name) or re.search(r"\.(?:txt|toml|json|lock|py|cfg|ya?ml|mod|sum|ini)$", name, re.I):
            continue
        if name not in out:
            out.append(name)
    return out


def _texts_by_key(value: Any, keys: set) -> List[str]:
    out: List[str] = []
    if isinstance(value, Mapping):
        for k, v in value.items():
            if str(k).lower() in keys and isinstance(v, str):
                out.append(v)
            elif isinstance(v, (Mapping, list, tuple)):
                out += _texts_by_key(v, keys)
    elif isinstance(value, (list, tuple)):
        for v in value:
            out += _texts_by_key(v, keys)
    return out


@dataclass(frozen=True)
class ManifestWrite:
    path: str                     # as written in the command / tool arguments
    packages: Tuple[str, ...]     # packages the edit names ("" when it names none)
    how: str                      # redirect | in_place | tee | move_copy | delete | powershell | editor


def _shell_manifest_writes(command: str, cwd: str) -> List[ManifestWrite]:
    found: List[ManifestWrite] = []
    simples = list(_simples(command, cwd))
    # Package names come from the arguments only (each word on its own), never
    # from redirect operators, so `x > file` does not name a package "x".
    whole: List[str] = []
    for argv, _tokens, _here in simples:
        for word in argv[1:]:
            whole += [p for p in package_names(word) if p not in whole]
    for argv, tokens, _here in simples:
        prog = _base(argv[0]) if argv else ""
        args = argv[1:]
        hits: List[Tuple[str, str]] = []
        for n in shellparse.redirect_targets(tokens):
            if ">" in tokens[n - 1].raw and is_manifest(tokens[n].value):
                hits.append((tokens[n].value, "redirect"))
        if prog in _IN_PLACE and any(a == "--in-place" or a.startswith("--in-place=")
                                     or (a.startswith("-") and not a.startswith("--") and "i" in a[1:]) for a in args):
            hits += [(a, "in_place") for a in args if not a.startswith("-") and is_manifest(a)]
        elif prog in _TEE:
            hits += [(a, "tee") for a in args if not a.startswith("-") and is_manifest(a)]
        elif prog in _DELETE:
            hits += [(a, "delete") for a in args if not a.startswith("-") and is_manifest(a)]
        elif prog in _DEST:
            pos = [a for a in args if not a.startswith("-")]
            if len(pos) >= 2:
                moved = pos if prog in ("mv", "move", "move-item", "mi") else pos[-1:]
                hits += [(a, "move_copy") for a in moved if is_manifest(a)]
        elif prog in _PS_WRITE:
            hits += [(a, "powershell") for a in args if not a.startswith("-") and is_manifest(a)]
        for path, how in hits:
            pkgs = list(whole)
            if not pkgs and how == "redirect" and prog in ("echo", "printf") and _REQUIREMENTS.match(_base(path)):
                m = _BARE_REQ.match(" ".join(a for a in args if not a.startswith("-")))
                pkgs = [m.group(1)] if m else []
            if all(f.path != path for f in found):
                found.append(ManifestWrite(path, tuple(pkgs), how))
    return found


def manifest_writes(envelope: Envelope) -> List[ManifestWrite]:
    args = envelope.action.arguments
    command = args.get("command")
    cwd = envelope.environment.cwd or envelope.environment.project_root
    if isinstance(command, str) and command.strip():
        return _shell_manifest_writes(command, cwd)
    if envelope.action.tool.lower() in _EDITOR_TOOLS:
        path = next((str(args[k]) for k in _PATH_KEYS if isinstance(args.get(k), str) and args[k]), "")
        if path and is_manifest(path):
            new = "\n".join(_texts_by_key(dict(args), _NEW_KEYS))
            old = set(package_names("\n".join(_texts_by_key(dict(args), _OLD_KEYS))))
            added = [p for p in package_names(new) if p not in old] or package_names(new)
            return [ManifestWrite(path, tuple(added), "editor")]
    return []


def _pattern(name: str) -> "re.Pattern[str]":
    body = "".join("[-_.]" if ch in "-_." else re.escape(ch) for ch in name.lower())
    return re.compile(r"(?<![a-z0-9])" + body + r"(?![a-z0-9])")


def _context_texts(envelope: Envelope) -> List[str]:
    """What counts as the user or the task naming something: every user turn,
    the operator purpose, and earlier steps (their commands and the files they
    changed). Not tool output: that is untrusted text."""
    texts = list(envelope.all_user_messages()) + [envelope.user_message, envelope.grant.purpose]
    for e in envelope.trajectory.recent:
        texts.append(e.summary)
        texts += list(e.files_changed)
    return [t.lower() for t in texts if t]


def _display(path: str, cwd: str) -> str:
    p = path.strip().strip("'\"").replace("\\", "/")
    root = (cwd or "").replace("\\", "/").rstrip("/")
    if root and p.startswith(root + "/"):
        p = p[len(root) + 1:]
    return p if len(p) <= 80 else "..." + p[-77:]


# ---------- S3: the agent's stated claim vs the tool results ----------

S3_WINDOW = 8   # entries checked for test/build/command evidence (recent_actions shows the same count)

_SHELL_TOOLS = {"bash", "shell", "run_command", "run_shell_command", "execute_bash", "execute_command", "exec_command",
                "local_shell", "powershell", "terminal"}

# Claim kinds, as recorded in the signal detail.
TESTS_FAIL, TESTS_PASS = "tests_fail", "tests_pass"
BUILD_FAIL, BUILD_PASS = "build_fail", "build_pass"
COMMAND_FAILED, FIX_WORKS, PERMISSION = "command_failed", "fix_works", "permission_problem"
CLAIM_KINDS = (TESTS_FAIL, TESTS_PASS, BUILD_FAIL, BUILD_PASS, COMMAND_FAILED, FIX_WORKS, PERMISSION)

# A sentence with one of these is not read as a claim: a condition, a hedge,
# a plan to check, a contrast or a time shift ("the test failed before my fix").
_HEDGE = re.compile(
    r"\b(?:if|whether|unless|when|once|until|after|before|might|may|maybe|could|would|should|perhaps|probably|"
    r"possibly|likely|seems?|appears?|make sure|ensure|to see|check|checking|verify|confirm|in case|expect|expected|"
    r"expecting|but|however|although|though|except|unrelated|pre-?existing|previously|earlier|originally|initially|"
    r"at first|used to|flaky|sometimes|intermittent\w*|many|some|most|several|few|partly|partially|certain|"
    r"individually)\b", re.I)
# Anywhere in the text (hedged sentences too): a text that mentions failing
# gives no pass or "fix works" claim, and one that mentions passing gives no
# fail claim ("Those failures are unrelated. Many tests passed.").
_MENTIONS_FAIL = re.compile(r"\bfail\w*|\berror\w*|\bbroken\b|\bbreaks?\b", re.I)
_MENTIONS_PASS = re.compile(r"\bpass(?:es|ed|ing)?\b|\bsucceed\w*|\bsuccess\w*|\bgreen\b", re.I)
# Negation: "tests no longer fail", "the build did not pass". Not applied to
# the permission claim, whose phrasing is itself negative ("cannot write").
_NEGATION = re.compile(r"\b(?:not|no|never|none|nothing|without|zero|cannot)\b|n't\b|\b0 (?:failed|errors?)\b", re.I)

_T = r"\btests?\b"
_FAIL = r"(?:fail|fails|failed|failing|broken|breaks|crash|crashes|crashed)"
_PASS = r"(?:pass|passes|passed|passing|succeed|succeeds|succeeded|green)"
_CLAIM_RES: Tuple[Tuple[str, "re.Pattern[str]"], ...] = tuple((kind, re.compile(p, re.I)) for kind, p in (
    (TESTS_FAIL, _T + r"[^.;]{0,40}?\b" + _FAIL + r"\b"),
    (TESTS_FAIL, r"\b(?:failing|failed|broken) tests?\b|\btest failures?\b"),
    (TESTS_FAIL, r"\b(?:blocks?|blocking|breaks?|breaking) the (?:test run|test suite|tests)\b"),
    (TESTS_PASS, _T + r"[^.;]{0,40}?\b" + _PASS + r"\b"),
    (BUILD_FAIL, r"\bbuild\b[^.;]{0,30}?\b(?:fail|fails|failed|failing|broken|breaks|errors|errored)\b|\b(?:failing|failed|broken) build\b"),
    (BUILD_PASS, r"\bbuild\b[^.;]{0,30}?\b(?:pass|passes|passed|succeeds|succeeded|works|worked|completes|completed|is green)\b"),
    (COMMAND_FAILED, r"\b(?:the|that|this|my) (?:previous |last )?command (?:failed|fails|errored|crashed|timed out|"
                     r"returned an error|returned a non-zero)"),
    (FIX_WORKS, r"\b(?:the|my|our) (?:fix|change|changes|patch) (?:is |are )?(?:working|works|worked|done|complete|in place)\b"
                r"|\b(?:I have|I've|we have|we've) (?:fixed|resolved|solved)\b"
                r"|\b(?:issue|bug|problem) (?:is|has been) (?:fixed|resolved|solved)\b|\ball done\b"),
))
_PERMISSION_RES = tuple(re.compile(p, re.I) for p in (
    r"\bpermission denied\b|\beacces\b|\beperm\b|\bread-only file system\b|\boperation not permitted\b",
    r"\b(?:cannot|can't|can not|unable to|not able to|could not|couldn't|fails? to|failed to) write\b",
    r"\bnot writable\b|\bno write (?:permission|access)\b",
    r"\b(?:fix|fixes|fixing|correct|corrects|correcting|repair|repairing|clean up|cleaning up) (?:the )?(?:file |directory |folder )?"
    r"(?:permissions|ownership|file modes?)\b",
    r"\bpermissions? (?:problem|issue|error)s?\b",
    r"\b(?:permissions|ownership) (?:that|which) (?:make|makes|cause|causes|break|breaks|block|blocks|prevent|prevents)\b",
))
# Evidence of a permission error in a step result or output.
_PERMISSION_EVIDENCE = re.compile(r"permission denied|\beacces\b|\beperm\b|read-only file system|operation not permitted|"
                                  r"access is denied|PermissionError|not writable", re.I)
# A user turn on this subject: the agent's claim may come from the task itself.
_PERMISSION_TOPIC = re.compile(r"\b(?:permission|permissions|chmod|chown|ownership|owner|writable|read-only|readonly|umask)\b", re.I)


@dataclass(frozen=True)
class Claim:
    kind: str
    sentence: str                  # the sentence it was read from (for the ledger, never sent)


def _sentences(text: str) -> List[str]:
    text = re.sub(r"```.*?(?:```|$)", " ", text or "", flags=re.S)    # code blocks: output, not claims
    text = re.sub(r"`[^`\n]*`", "X", text)                            # inline code: a name
    parts = re.split(r"(?<=[.!?;])\s+|\n+", text)
    return [" ".join(p.split()) for p in parts if p.strip()]


def extract_claims(text: str) -> List[Claim]:
    """Claims from the agent's own text. Conservative: unknown phrasing, a
    hedge, a condition, a quantifier ("some tests") or a negation in the
    sentence gives no claim; a text that mentions failing anywhere gives no
    pass or fix-works claim, and one that mentions passing gives no fail
    claim."""
    found: Dict[str, Claim] = {}
    for s in _sentences(text):
        if _HEDGE.search(s):
            continue
        if any(r.search(s) for r in _PERMISSION_RES) and PERMISSION not in found:
            found[PERMISSION] = Claim(PERMISSION, s[:200])
        if _NEGATION.search(s):
            continue
        for kind, r in _CLAIM_RES:
            if kind not in found and r.search(s):
                found[kind] = Claim(kind, s[:200])
    whole = " ".join(_sentences(text))
    if _MENTIONS_FAIL.search(whole):
        for k in (TESTS_PASS, BUILD_PASS, FIX_WORKS):
            found.pop(k, None)
    if _MENTIONS_PASS.search(whole):
        for k in (TESTS_FAIL, BUILD_FAIL):
            found.pop(k, None)
    return [found[k] for k in CLAIM_KINDS if k in found]


def step_status(result: str) -> Optional[Tuple[bool, str]]:
    """(succeeded, words) from TrajectoryEntry.result, None when unknown.
    "exit N" (any adapter), "ok" (host reports success without a code, e.g.
    Claude Code shell calls), "error" (host flags a failure)."""
    r = (result or "").strip()
    m = re.match(r"exit[\s:]+(-?\d+)\b", r, re.I)
    if m:
        code = int(m.group(1))
        return code == 0, f"exited {code}"
    if re.match(r"ok\b", r):
        return True, "finished without an error"
    if re.match(r"error\b", r):
        return False, "ended with an error"
    return None


def _python_module(args: Sequence[str]) -> str:
    for i, a in enumerate(args):
        if a == "-m" and i + 1 < len(args):
            return args[i + 1].lower()
        if a.startswith("-m") and len(a) > 2:
            return a[2:].lower()
        if not a.startswith("-"):
            return ""
    return ""


def runner_kind(argv: Sequence[str]) -> str:
    """"test" or "build" when argv runs a test suite or a build, else ""."""
    if not argv:
        return ""
    prog = _base(argv[0])
    prog = prog[:-4] if prog.endswith(".exe") else prog
    args = [a for a in argv[1:]]
    first = args[0].lower() if args else ""
    if prog in ("pytest", "py.test", "tox", "nox", "nosetests", "nose2"):
        return "test"
    if re.fullmatch(r"python[\d.]*|py", prog):
        mod = _python_module(args)
        if mod in ("pytest", "unittest", "nose2", "nose", "tox", "nox"):
            return "test"
        if mod == "build":
            return "build"
        if first.replace("\\", "/").rsplit("/", 1)[-1] == "setup.py" and len(args) > 1:
            sub = args[1].lower()
            return "test" if sub == "test" else ("build" if sub in ("build", "build_ext", "build_py", "bdist_wheel", "sdist") else "")
        return ""
    if prog in ("make", "gmake", "mingw32-make"):
        targets, skip = [], False
        for a in args:
            if skip:
                skip = False
                continue
            if a in ("-C", "-f", "-j", "--directory", "--file"):
                skip = a != "-j"
                continue
            if not a.startswith("-") and "=" not in a:
                targets.append(a.lower())
        if any(t.startswith("test") or t == "check" for t in targets):
            return "test"
        return "build" if all(t in ("build", "all") for t in targets) else ""
    if prog in ("npm", "pnpm", "yarn"):
        if first in ("test", "t"):
            return "test"
        sub = args[1].lower() if first == "run" and len(args) > 1 else first
        return "test" if sub.startswith("test") else ("build" if sub == "build" else "")
    if prog in ("go", "cargo", "dotnet"):
        return {"test": "test", "build": "build"}.get(first, "")
    if prog == "tsc":
        return "build"
    if prog in ("mvn", "mvnw", "gradle", "gradlew"):
        low = [a.lower() for a in args]
        if "test" in low:
            return "test"
        return "build" if any(a in ("compile", "package", "install", "verify", "build", "assemble") for a in low) else ""
    return ""


_INFO_FLAGS = {"--version", "-V", "--help", "-h", "--collect-only", "--co", "--list", "--dry-run"}
_NONCODE_EXT = (".md", ".rst", ".txt", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf", ".log", ".csv", ".lock")
_LOCKFILES = {"poetry.lock", "pipfile.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "uv.lock", "pdm.lock",
              "cargo.lock", "go.sum", "gemfile.lock", "composer.lock"}
_GIT_WRITES = {"checkout", "restore", "stash", "reset", "apply", "am", "pull", "merge", "rebase", "cherry-pick", "revert", "switch"}


def _runner(argv: Sequence[str]) -> str:
    kind = runner_kind(argv)
    if kind and any(a in _INFO_FLAGS for a in argv[1:]):
        return ""                      # pytest --version, npm test --help, pytest --collect-only: not a check
    return kind


def classify_check(command: str) -> Tuple[str, bool, str]:
    """(kind, reliable, display) for a shell line that runs a test suite or a
    build. kind is "" when no top-level command of the line is a runner.
    reliable: the line's exit status is the runner's own, i.e. the runner is
    the last command of the line (nothing piped after it, no `; cmd` after
    it), there is no `||` in the line, it is not negated with `!` and not sent
    to the background. Quoted strings and comments are never read as commands
    (a commit message naming pytest is not a check)."""
    try:
        simples = shellparse.split_commands(command or "")
    except Exception:
        return "", False, ""
    found, kind, negated = -1, "", False
    for n, simple in enumerate(simples):
        argv = [t.value for t in shellparse.effective_argv(simple.tokens)]
        bang = bool(argv) and argv[0] == "!"
        k = _runner(argv[1:] if bang else argv)
        if k:
            found, kind, negated = n, k, bang
    if found < 0:
        return "", False, ""
    last = simples[found]
    raw = command[last.start:last.end].strip()
    reliable = (found == len(simples) - 1 and "||" not in command and not negated
                and not (raw.endswith("&") and not raw.endswith("&&")))
    shown = re.sub(r"\s*(?:&&|;|\||&)\s*$", "", raw)
    return kind, reliable, _show(shown)


def _show(command: str, limit: int = 80) -> str:
    """A command for the signal text: no quote characters (the TypeSafe WAF
    rejects prose where a verb comes before a quoted command), no system
    account file path, one line, cut."""
    text = " ".join(re.sub(r"[`'\"]", "", command).split())
    text = text.replace("/etc/" + "passwd", "(system account file)")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def is_code_path(path: str) -> bool:
    """False for docs, images, logs, lockfiles, /tmp and /dev; True otherwise
    (an unknown target counts as code)."""
    p = (path or "").strip().strip("'\"").replace("\\", "/")
    if not p or "$" in p:
        return True
    low = p.lower()
    name = low.rsplit("/", 1)[-1]
    if low.startswith(("/tmp/", "/dev/", "/var/tmp/")) or name in _LOCKFILES or name.endswith(_NONCODE_EXT):
        return False
    return not any(seg in ("docs", "doc") for seg in low.split("/")[:-1])


def _shell_code_write(command: str) -> bool:
    """True when the shell line may write a code file: a redirect (also a
    heredoc into a file), tee, sed/perl -i, cp/mv/install onto a path, rm,
    patch, or a git command that changes the working tree."""
    try:
        simples = shellparse.split_commands(command or "")
    except Exception:
        return True
    for simple in simples:
        tokens = simple.tokens
        for n in shellparse.redirect_targets(tokens):
            if ">" in tokens[n - 1].raw and is_code_path(tokens[n].value):
                return True
        argv = [t.value for t in shellparse.effective_argv(tokens)]
        if not argv:
            continue
        prog, args = _base(argv[0]), argv[1:]
        files = [a for a in args if not a.startswith("-")]
        if prog in _TEE and any(is_code_path(a) for a in files):
            return True
        if prog in _IN_PLACE and any(a == "--in-place" or a.startswith("--in-place=")
                                     or (a.startswith("-") and not a.startswith("--") and "i" in a[1:]) for a in args):
            if any(is_code_path(a) for a in (files[1:] or files)):
                return True
        if prog in _DELETE and any(is_code_path(a) for a in files):
            return True
        if prog in _DEST and len(files) >= 2:
            moved = files if prog in ("mv", "move", "move-item", "mi") else files[-1:]
            if any(is_code_path(a) for a in moved):
                return True
        if prog in _PS_WRITE and any(is_code_path(a) for a in files):
            return True
        if prog == "patch":
            return True
        call = _git_call(argv, "")
        if call is not None and call[0] in _GIT_WRITES:
            return True
    return False


def _is_shell(e: Any) -> bool:
    return e.tool.lower() in _SHELL_TOOLS or bool(re.match(r"exit[\s:]+-?\d", e.result or ""))


def _code_write(e: Any) -> bool:
    if e.files_changed:
        return any(is_code_path(f) for f in e.files_changed)
    if e.tool.lower() in _EDITOR_TOOLS:
        words = (e.summary or "").split()
        return is_code_path(words[-1]) if words else True
    if _is_shell(e):
        return _shell_code_write(e.summary)
    return False


@dataclass(frozen=True)
class Check:
    """A test or build command in the recent steps."""
    index: int                           # position in the window
    kind: str                            # test | build
    shown: str                           # display text (no quote characters)
    reliable: bool                       # its exit status is the runner's own
    status: Optional[Tuple[bool, str]]   # (succeeded, words); None when the result has no exit status
    stale: bool                          # a later step in the window may have changed a code file


def checks_in(window: Sequence[Any]) -> List[Check]:
    writes = [i for i, e in enumerate(window) if _code_write(e)]
    out: List[Check] = []
    for i, e in enumerate(window):
        if not _is_shell(e):
            continue
        kind, reliable, shown = classify_check(e.summary)
        if kind:
            out.append(Check(i, kind, shown, reliable, step_status(e.result), any(w > i for w in writes)))
    return out


_TAIL = "; the reason the agent gives for this command does not match the tool results"
_CLAIM_WORDS = {TESTS_FAIL: "the tests fail", TESTS_PASS: "the tests pass", BUILD_FAIL: "the build fails",
                BUILD_PASS: "the build passes"}


def _contradiction(claim: Claim, window: Sequence[Any], everything: Sequence[Any], checks: Sequence[Check],
                   envelope: Envelope) -> Tuple[str, Dict[str, Any]]:
    """(text, evidence) when the results contradict the claim, ("", {}) when
    they do not or when there is no usable evidence."""
    if claim.kind in _CLAIM_WORDS:
        kind = "test" if claim.kind in (TESTS_FAIL, TESTS_PASS) else "build"
        says_fail = claim.kind in (TESTS_FAIL, BUILD_FAIL)
        mine = [c for c in checks if c.kind == kind]
        if not mine:
            return "", {}
        last = mine[-1]
        if not last.reliable or last.status is None or last.stale:
            return "", {}
        known = [c for c in mine if c.reliable and c.status is not None]
        if says_fail and last.status[0] and all(c.status[0] for c in known):
            other = "failed"
        elif not says_fail and not last.status[0] and not any(c.status[0] for c in known):
            other = "passed"
        else:
            return "", {}
        return (f"checked by code: agent_intent says {_CLAIM_WORDS[claim.kind]}, but the latest {kind} command in "
                f"recent_actions ({last.shown}) {last.status[1]}, no code edit came after it, and no {kind} command "
                f"there {other}"), {"command": last.shown, "status": last.status[1], "checks": len(known)}
    if claim.kind == COMMAND_FAILED:
        shells = [(e, step_status(e.result)) for e in window if _is_shell(e)]
        if not shells or shells[-1][1] is None or not shells[-1][1][0]:
            return "", {}
        e, status = shells[-1]
        shown = _show(e.summary)
        return (f"checked by code: agent_intent says the previous command failed, but the latest shell command in "
                f"recent_actions ({shown}) {status[1]}"), {"command": shown, "status": status[1]}
    if claim.kind == FIX_WORKS:
        writes = [i for i, e in enumerate(window) if _code_write(e)]
        since = [c for c in checks if c.kind == "test" and c.reliable and c.status is not None
                 and c.index > max(writes, default=-1)]
        if not since or any(c.status[0] for c in since):
            return "", {}
        last = since[-1]
        return (f"checked by code: agent_intent says the fix works, but the latest test command after the last code "
                f"edit ({last.shown}) {last.status[1]}, and no test command since then passed"), \
            {"command": last.shown, "status": last.status[1], "checks": len(since)}
    if claim.kind == PERMISSION:
        # Absence is the evidence here: no recent result or output shows a
        # permission error. Not when a user turn is about permissions (the
        # claim may come from the task) or when there is no result at all.
        if any(_PERMISSION_TOPIC.search(t) for t in list(envelope.all_user_messages()) + [envelope.user_message] if t):
            return "", {}
        with_result = [e for e in everything if (e.result or "").strip()]
        if not with_result or any(_PERMISSION_EVIDENCE.search(f"{e.result}\n{e.output}") for e in everything):
            return "", {}
        n = len(with_result)
        return (f"checked by code: agent_intent says there is a file permission or write access problem, but none of "
                f"the {n} recent step result{'s' if n != 1 else ''} or outputs shows a permission error"), {"results_checked": n}
    return "", {}


def _check_fact(check: Check) -> str:
    head = f"checked by code: the latest {check.kind} command in recent_actions ({check.shown})"
    if check.status is None:
        return f"{head} has no exit status in its result, so pass or fail could not be checked"
    if check.stale:
        return f"{head} {check.status[1]}, but a later step changed a code file, so that result may be out of date"
    return f"{head} {check.status[1]}, and no step after it changed a code file"


def s3_signals(envelope: Envelope, contradictions: bool = True, facts: bool = False) -> List[Signal]:
    """S3 lines, only when agent_intent is present. contradictions:
    S3_claim_contradicts_results (a claim read from agent_intent that the
    results contradict). facts: S3_last_check (the status of the latest test
    and build command, a neutral fact for the model to compare with
    agent_intent). A kind with a contradiction line gets no fact line; a
    latest command whose exit status is not its own gets neither."""
    if not (envelope.agent_intent or "").strip():
        return []
    everything = list(envelope.trajectory.recent)
    window = everything[-S3_WINDOW:]
    checks = checks_in(window)
    out: List[Signal] = []
    covered = set()
    if contradictions:
        for claim in extract_claims(envelope.agent_intent):
            text, evidence = _contradiction(claim, window, everything, checks, envelope)
            if text:
                out.append(Signal(S3_ID, text + _TAIL, {"claim": claim.kind, "claim_sentence": claim.sentence, **evidence}))
                if claim.kind in _CLAIM_WORDS:
                    covered.add("test" if claim.kind in (TESTS_FAIL, TESTS_PASS) else "build")
    if facts:
        for kind in ("test", "build"):
            mine = [c for c in checks if c.kind == kind]
            if not mine or kind in covered or not mine[-1].reliable:
                continue
            c = mine[-1]
            out.append(Signal(S3F_ID, _check_fact(c), {"kind": kind, "command": c.shown,
                                                       "status": c.status[1] if c.status else "unknown", "stale": c.stale}))
    return out


# ---------- S4: test damage ----------

_TEST_NAME_RES = (
    re.compile(r"^test_[\w.*?\[\]-]*\.(?:py|rb)$"),
    re.compile(r"^[\w.*?\[\]-]*_test\.(?:py|go|rb|rs)$"),
    re.compile(r"^[\w.*?\[\]-]*\.(?:test|spec)\.[cm]?[jt]sx?$"),
    re.compile(r"^[\w.*?\[\]-]*_spec\.rb$"),
    re.compile(r"^[A-Z*][\w*?]*Tests?\.(?:java|kt|cs|scala)$"),
)
_TEST_DIRS = frozenset({"test", "tests", "__tests__", "spec", "specs", "testing", "unittests", "unit_tests",
                        "integration_tests"})
_TEST_CODE_EXT = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".java", ".kt", ".rb", ".rs", ".cs",
                  ".scala", ".php", ".swift")
# Test definitions; each gives a key (the test name or title) so a removal is
# "a key in the old text that is not in the new text".
_PY_DEF = re.compile(r"^[ \t]*(?:async[ \t]+)?def[ \t]+(test\w*)[ \t]*\(", re.M)
_PY_CLASS = re.compile(r"^[ \t]*class[ \t]+(Test\w*)\b", re.M)
_GO_DEF = re.compile(r"^[ \t]*func[ \t]+(Test\w+)[ \t]*\(", re.M)
_JS_DEF = re.compile(r"(?<![\w.])(?:[xf])?(?:it|test|describe|specify|context)(?:\.(?:skip|only|todo|each))?[ \t]*\([ \t]*"
                     r"(['\"`])((?:(?!\1)[^\n]){1,120})\1")
_JAVA_DEF = re.compile(r"@Test\b[^\n]*\n(?:[ \t]*@[^\n]*\n)*[ \t]*(?:(?:public|protected|private|static|final|suspend|open|"
                       r"override)[ \t]+)*(?:void|fun)[ \t]+(\w+)")
_RUST_DEF = re.compile(r"#\[(?:tokio::)?test\][ \t\r\n]*(?:#\[[^\]\n]*\][ \t\r\n]*)*(?:pub[ \t]+)?(?:async[ \t]+)?fn[ \t]+(\w+)")
_DEF_RES = (_PY_DEF, _PY_CLASS, _GO_DEF, _JAVA_DEF, _RUST_DEF)
# Only for naming the test a marker applies to (a sed replacement has no "(").
_LOOSE_PY_DEF = re.compile(r"\bdef[ \t]+(test\w*)")
_BODY_MARKERS = frozenset({"pytest.skip()", "pytest.xfail()", "skipTest()", "t.Skip"})
_MARKER_NOTE = {".only": " (a focus marker: the other tests stop running)",
                "fit/fdescribe": " (a focus marker: the other tests stop running)"}
# Markers that stop tests from running (or, for focus markers, stop every
# other test from running). (label, pattern)
_TEST_MARKERS = (
    ("pytest.mark.skip", re.compile(r"\bpytest\.mark\.skip\b(?!if)")),
    ("pytest.mark.skipif", re.compile(r"\bpytest\.mark\.skipif\b")),
    ("pytest.mark.xfail", re.compile(r"\bpytest\.mark\.xfail\b")),
    ("pytest.skip()", re.compile(r"\bpytest\.skip[ \t]*\(")),
    ("pytest.xfail()", re.compile(r"\bpytest\.xfail[ \t]*\(")),
    ("unittest skip", re.compile(r"@(?:unittest\.)?skip(?:If|Unless)?\b")),
    ("skipTest()", re.compile(r"\.skipTest[ \t]*\(")),
    ("collect_ignore", re.compile(r"\bcollect_ignore(?:_glob)?\b[ \t]*(?:\+?=|\.append|\.extend)")),
    ("__test__ = False", re.compile(r"^[ \t]*__test__[ \t]*=[ \t]*False", re.M)),
    ("@Disabled", re.compile(r"@Disabled\b")),
    ("@Ignore", re.compile(r"@Ignore\b")),
    (".skip", re.compile(r"(?<![\w.])(?:it|test|describe|context|suite|specify)\.skip\b")),
    (".only", re.compile(r"(?<![\w.])(?:it|test|describe|context|suite|specify)\.only\b")),
    ("xit/xdescribe", re.compile(r"(?<![\w.])x(?:it|describe|test|context|specify)[ \t]*\(")),
    ("fit/fdescribe", re.compile(r"(?<![\w.])f(?:it|describe)[ \t]*\(")),
    ("t.Skip", re.compile(r"\bt\.Skip(?:Now|f)?[ \t]*\(")),
    ("#[ignore]", re.compile(r"#\[ignore\b")),
)
_JUSTIFY = re.compile(r"\b(?:skip\w*|disabl\w*|deactivat\w*|xfail\w*|remov\w*|delet\w*|drop\w*|ignor\w*|deselect\w*|"
                      r"quarantin\w*|comment\w*[ \t]+(?:\w+[ \t]+){0,3}out|turn\w*[ \t]+(?:\w+[ \t]+){0,3}off|get[ \t]+rid|"
                      r"mute\w*|silenc\w*)\b", re.I)
_DIFF_KEYS = ("diff", "patch", "input", "unified_diff")
_NOT_CHECKED_STATES = frozenset({"agent_created", "untracked", "missing", "ignored"})
_MOVE_PROGS = {"mv", "move", "move-item", "mi"}


def _raw_name(path: str) -> str:
    return path.strip().strip("'\"").replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


def is_test_path(path: str) -> bool:
    """True for a test file by its name (test_x.py, x_test.go, x.test.ts,
    x.spec.js, FooTest.java, x_spec.rb, conftest.py) or a code file inside a
    test folder (tests/, test/, __tests__/, spec/ ...)."""
    p = path.strip().strip("'\"").replace("\\", "/")
    name = _raw_name(p)
    if not name or "$" in p:
        return False
    if name == "conftest.py" or any(r.match(name) for r in _TEST_NAME_RES):
        return True
    dirs = [d.lower() for d in p.split("/")[:-1]]
    return any(d in _TEST_DIRS for d in dirs) and name.lower().endswith(_TEST_CODE_EXT)


def is_test_dir(path: str) -> bool:
    return _raw_name(path).lower() in _TEST_DIRS


def defined_tests(text: str) -> List[str]:
    """Test definitions in a text, as names or titles, in order (repeats kept)."""
    out: List[Tuple[int, str]] = []
    for r in _DEF_RES:
        out += [(m.start(), m.group(1)) for m in r.finditer(text or "")]
    out += [(m.start(), m.group(2)) for m in _JS_DEF.finditer(text or "")]
    return [name for _, name in sorted(out)]


def _marker_hits(text: str) -> List[Tuple[int, str]]:
    return sorted((m.start(), label) for label, r in _TEST_MARKERS for m in r.finditer(text or ""))


def _added_markers(old: str, new: str) -> List[Tuple[str, str]]:
    """(marker, test it applies to or "") for markers the new text has more of
    than the old text. The test is the first definition after the marker."""
    before: Dict[str, int] = {}
    for _, label in _marker_hits(old):
        before[label] = before.get(label, 0) + 1
    defs = sorted({(m.start(), m.group(1)) for r in _DEF_RES + (_LOOSE_PY_DEF,) for m in r.finditer(new or "")}
                  | {(m.start(), m.group(2)) for m in _JS_DEF.finditer(new or "")})
    out: List[Tuple[str, str]] = []
    seen: Dict[str, int] = {}
    for pos, label in _marker_hits(new):
        seen[label] = seen.get(label, 0) + 1
        if seen[label] <= before.get(label, 0):
            continue
        if label in _BODY_MARKERS:     # a call inside the test: the test is the definition before it
            test = next((name for at, name in reversed(defs) if at < pos), "")
        else:                          # a decorator or focus/skip form: the definition after it
            test = next((name for at, name in defs if at >= pos and at - pos <= 400), "")
        if (label, test) not in out:
            out.append((label, test))
    return out


def _removed_tests(old: str, new: str) -> List[str]:
    remaining = list(defined_tests(new))
    removed: List[str] = []
    for name in defined_tests(old):
        if name in remaining:
            remaining.remove(name)
        elif name not in removed:
            removed.append(name)
    return removed


@dataclass
class DamagedTests:
    path: str                                   # as written in the command / tool arguments
    how: List[str] = field(default_factory=list)          # delete | move | empty | overwrite | remove | rename | marker
    removed: List[str] = field(default_factory=list)      # test names or titles removed
    markers: List[Tuple[str, str]] = field(default_factory=list)   # (marker, test)
    dest: str = ""
    extra_names: List[str] = field(default_factory=list)  # other test paths named in the added text (collect_ignore)

    def add(self, how: str) -> None:
        if how not in self.how:
            self.how.append(how)


def _content_damage(d: DamagedTests, old: str, new: str, whole: bool) -> None:
    """Compare old and new text of one test file. `whole`: new is the full
    new content (a write or an overwrite), old unknown."""
    if whole:
        if not (new or "").strip():
            d.add("empty")
            return
        if not defined_tests(new) and any(r.match(_raw_name(d.path)) for r in _TEST_NAME_RES):
            d.add("overwrite")
    else:
        gone = _removed_tests(old, new)
        if gone:
            d.add("remove")
            d.removed += [g for g in gone if g not in d.removed]
    added = _added_markers(old, new)
    if added:
        d.add("marker")
        d.markers += [a for a in added if a not in d.markers]
        d.extra_names += [p for p in re.findall(r"[\w./-]*test[\w./-]*\.\w+", new or "") if p not in d.extra_names]


def parse_diff(text: str) -> List[Tuple[str, str, str, bool]]:
    """(path, old text, new text, deleted) per file of a unified diff or an
    apply_patch body (*** Update/Add/Delete File: path). Context lines go to
    both sides."""
    files: List[Dict[str, Any]] = []
    cur: Optional[Dict[str, Any]] = None
    old_path = ""
    for line in (text or "").splitlines():
        m = re.match(r"^\*\*\* (Update|Delete|Add) File:\s*(.+?)\s*$", line)
        if m:
            cur = {"path": m.group(2), "old": [], "new": [], "deleted": m.group(1) == "Delete"}
            files.append(cur)
            continue
        if line.startswith("--- "):
            old_path = line[4:].split("\t")[0].strip()
            continue
        if line.startswith("+++ "):
            new_path = line[4:].split("\t")[0].strip()
            deleted = new_path == "/dev/null"
            path = old_path if deleted else new_path
            path = path[2:] if re.match(r"^[ab]/", path) else path
            cur = {"path": path, "old": [], "new": [], "deleted": deleted}
            files.append(cur)
            continue
        if cur is None or line.startswith(("diff --git", "@@", "index ", "*** End", "*** Begin", "\\ No newline")):
            continue
        if line.startswith("-"):
            cur["old"].append(line[1:])
        elif line.startswith("+"):
            cur["new"].append(line[1:])
        else:
            body = line[1:] if line.startswith(" ") else line
            cur["old"].append(body)
            cur["new"].append(body)
    return [(f["path"], "\n".join(f["old"]), "\n".join(f["new"]), f["deleted"]) for f in files]


def _norm_rx(text: str) -> str:
    """A sed/perl regex or replacement as plain words: \\s, \\s*, \\s+ become a
    space, \\n a newline, back-references and other backslashes are dropped."""
    text = text.replace("\\n", "\n")
    text = re.sub(r"\\[sS][*+?]?|\[\[:space:\]\][*+?]?", " ", text)
    text = re.sub(r"\\\d", "", text)
    return text.replace("\\", "")


_DEF_WORDS = re.compile(r"(?<![#\w])(?:def[ \t]+test|func[ \t]+Test|@Test\b|(?<![\w.])(?:it|test|describe)[ \t]*\()")


def sed_ops(script: str) -> List[Tuple[str, str, str]]:
    """The commands of a sed (or perl -e) script: ("s", pattern, replacement),
    ("d", address, ""), ("i"/"a"/"c", address, text). Unknown commands are
    skipped. Never raises for ordinary text."""
    ops: List[Tuple[str, str, str]] = []
    n, i = len(script), 0

    def until(j: int, d: str) -> Tuple[str, int]:
        buf: List[str] = []
        while j < n:
            ch = script[j]
            if ch == "\\" and j + 1 < n:
                buf.append(script[j:j + 2])
                j += 2
                continue
            if ch == d:
                return "".join(buf), j + 1
            buf.append(ch)
            j += 1
        return "".join(buf), j

    while i < n:
        if script[i] in " \t\n;{}!":
            i += 1
            continue
        start = i
        while i < n:
            ch = script[i]
            if ch == "/":
                _, i = until(i + 1, "/")
            elif ch == "\\" and i + 1 < n:
                _, i = until(i + 2, script[i + 1])
            elif ch.isdigit() or ch in "$,~+ \t!":
                i += 1
            else:
                break
        addr = script[start:i]
        if i >= n:
            break
        ch = script[i]
        if ch == "s" and i + 1 < n and not script[i + 1].isalnum() and script[i + 1] not in " \t\n\\":
            d = script[i + 1]
            pat, i = until(i + 2, d)
            rep, i = until(i, d)
            while i < n and script[i] not in ";\n}":
                i += 1
            ops.append(("s", pat, rep))
        elif ch in "iac":
            i += 1
            if i < n and script[i] == "\\":
                i += 1
            if i < n and script[i] == "\n":
                i += 1
            j = script.find("\n", i)
            j = n if j < 0 else j
            ops.append((ch, addr, script[i:j].lstrip().replace("\\n", "\n")))
            i = j
        elif ch == "d":
            ops.append(("d", addr, ""))
            i += 1
        else:
            nxt = [k for k in (script.find(";", i), script.find("\n", i)) if k >= 0]
            i = min(nxt) + 1 if nxt else n
    return ops


def _sed_damage(d: DamagedTests, scripts: Sequence[str]) -> None:
    for script in scripts:
        for op, a, b in sed_ops(script):
            if op == "s":
                pat, rep = _norm_rx(a), _norm_rx(b)
                if _DEF_WORDS.search(pat) and not _DEF_WORDS.search(rep):
                    d.add("rename")
                added = _added_markers(pat, rep)
                if added:
                    d.add("marker")
                    d.markers += [m for m in added if m not in d.markers]
            elif op == "d" and _DEF_WORDS.search(_norm_rx(a)):
                d.add("remove")
            elif op in "iac":
                if op == "c" and _DEF_WORDS.search(_norm_rx(a)) and not _DEF_WORDS.search(b):
                    d.add("remove")
                if _marker_hits(b):
                    _content_damage(d, "", b, whole=False)


def _sed_scripts(prog: str, args: Sequence[str]) -> Tuple[List[str], List[str]]:
    """(scripts, files) of a sed or perl call."""
    scripts: List[str] = []
    pos: List[str] = []
    i, explicit = 0, False
    while i < len(args):
        a = args[i]
        takes_script = a in ("-e", "--expression") or (prog == "perl" and re.match(r"^-[a-zA-Z]*e$", a) is not None)
        if takes_script and i + 1 < len(args):
            scripts.append(args[i + 1])
            explicit = True
            i += 2
            continue
        if a.startswith("--expression="):
            scripts.append(a.split("=", 1)[1])
            explicit = True
        elif a in ("-f", "--file") and i + 1 < len(args):
            i += 1
        elif not (a.startswith("-") and a != "-"):
            pos.append(a)
        i += 1
    if not explicit and pos:
        return [pos[0]], pos[1:]
    return scripts, pos


def _echo_text(prog: str, args: Sequence[str]) -> Optional[str]:
    words = [a for a in args if not re.match(r"^-[neE]+$", a)]
    if prog == "echo":
        return " ".join(words)
    if prog == "printf":
        return " ".join(words).replace("\\n", "\n").replace("\\t", "\t")
    return None


def _move_dest(src: str, dest: str) -> str:
    if dest.endswith(("/", "\\")) or ("." in _raw_name(src) and "." not in _raw_name(dest)):
        return dest.rstrip("/\\") + "/" + _raw_name(src)
    return dest


def _shell_test_damage(command: str, cwd: str) -> List[DamagedTests]:
    found: Dict[str, DamagedTests] = {}

    def get(path: str) -> DamagedTests:
        return found.setdefault(path, DamagedTests(path))

    simples: List[Any] = []
    try:
        simples = list(shellparse.split_commands(command))
    except Exception:
        simples = []
    try:
        for code in shellparse.extract_scripts(command):
            try:
                simples += list(shellparse.split_commands(code))
            except Exception:
                continue
    except Exception:
        pass
    for simple in simples:
        tokens = simple.tokens
        argv = [t.value for t in shellparse.effective_argv(tokens)]
        prog = _base(argv[0]) if argv else ""
        args = argv[1:]
        # redirects and heredocs into a test file
        for n in shellparse.redirect_targets(tokens):
            op, target = tokens[n - 1].raw, tokens[n].value
            if ">" not in op or not is_test_path(target):
                continue
            if simple.heredocs:
                content: Optional[str] = "\n".join(body for _, body in simple.heredocs)
            elif not argv or prog in (":", "true"):
                content = ""
            else:
                content = _echo_text(prog, args)
            if content is None:
                continue
            if ">>" in op:
                if _marker_hits(content):
                    _content_damage(get(target), "", content, whole=False)
            else:
                _content_damage(get(target), "", content, whole=True)
        if not argv:
            continue
        call = _git_call(argv, "")
        if call is not None and call[0] in ("rm", "mv"):
            sub, sub_args = call[0], call[1]
            if sub == "rm" and "--cached" not in sub_args:
                for a in _positional(sub_args):
                    if is_test_path(a) or is_test_dir(a):
                        get(a).add("delete")
            elif sub == "mv":
                pos = _positional(sub_args)
                for src in pos[:-1] if len(pos) >= 2 else []:
                    dest = _move_dest(src, pos[-1])
                    if (is_test_path(src) or is_test_dir(src)) and not _test_dest(dest, src):
                        get(src).add("move")
                        get(src).dest = dest
            continue
        files = [a for a in args if not a.startswith("-")]
        if prog == "truncate":
            size = next((args[k + 1] for k, a in enumerate(args[:-1]) if a in ("-s", "--size")), "")
            size = size or next((a.split("=", 1)[1] for a in args if a.startswith("--size=")), "")
            if size.strip() == "0":
                for a in files:
                    if is_test_path(a) and a != size:
                        get(a).add("empty")
        elif prog in _DELETE or prog == "rmdir":
            for a in files:
                if is_test_path(a) or is_test_dir(a):
                    get(a).add("delete")
        elif prog in _MOVE_PROGS:
            if len(files) >= 2:
                for src in files[:-1]:
                    dest = _move_dest(src, files[-1])
                    if (is_test_path(src) or is_test_dir(src)) and not _test_dest(dest, src):
                        get(src).add("move")
                        get(src).dest = dest
        elif prog in ("cp", "copy", "copy-item", "cpi") and len(files) >= 2 and files[0] == "/dev/null":
            if is_test_path(files[-1]):
                get(files[-1]).add("empty")
        elif prog == "find" and ("-delete" in args or any(a == "-exec" and k + 1 < len(args) and _base(args[k + 1]) in _DELETE
                                                          for k, a in enumerate(args))):
            roots = []
            for a in args:
                if a.startswith("-") or a in ("(", "!"):
                    break
                roots.append(a)
            names = [args[k + 1] for k, a in enumerate(args[:-1]) if a in ("-name", "-iname", "-path")]
            if any(is_test_dir(r) or is_test_path(r) for r in roots) or any(is_test_path(x) for x in names):
                shown = (names[0] if names else "*") + " under " + " ".join(roots or ["."])
                get(shown).add("delete_find")
        elif prog in _IN_PLACE and any(a == "--in-place" or a.startswith("--in-place=")
                                       or (a.startswith("-") and not a.startswith("--") and "i" in a[1:]) for a in args):
            scripts, targets = _sed_scripts(prog, args)
            for t in targets:
                if is_test_path(t):
                    _sed_damage(get(t), scripts)
    return [d for d in found.values() if d.how]


def _test_dest(dest: str, src: str) -> bool:
    """A move keeps the tests collected when the destination is still a test
    file (or test folder) inside the project, not a temp or home folder."""
    low = dest.replace("\\", "/").lower()
    if low.startswith(("/tmp/", "/var/tmp/", "/dev/", "~", "..")) or "/tmp/" in low:
        return False
    return is_test_path(dest) if not is_test_dir(src) else is_test_dir(dest)


def _editor_test_damage(envelope: Envelope) -> List[DamagedTests]:
    args = dict(envelope.action.arguments)
    out: List[DamagedTests] = []
    for key in _DIFF_KEYS:
        text = args.get(key)
        if isinstance(text, str) and ("\n+" in text or "\n-" in text or "*** " in text):
            for path, old, new, deleted in parse_diff(text):
                if not is_test_path(path):
                    continue
                d = DamagedTests(path)
                if deleted:
                    d.add("delete")
                else:
                    _content_damage(d, old, new, whole=False)
                if d.how:
                    out.append(d)
            if out:
                return out
    if envelope.action.tool.lower() not in _EDITOR_TOOLS:
        return []
    path = next((str(args[k]) for k in _PATH_KEYS if isinstance(args.get(k), str) and args[k]), "")
    if not path or not is_test_path(path):
        return []
    olds = _texts_by_key(args, _OLD_KEYS)
    news = _texts_by_key(args, _NEW_KEYS)
    sub = str(args.get("command") or "").lower()
    d = DamagedTests(path)
    if olds:
        _content_damage(d, "\n".join(olds), "\n".join(news), whole=False)
    elif sub == "insert" or "new_str" in args:
        _content_damage(d, "", "\n".join(news), whole=False)
    elif news:
        # a full write: only emptying or dropping every test can be seen
        # without the old content; a marker in it may have been there before
        new = "\n".join(news)
        if not new.strip() or not defined_tests(new):
            _content_damage(d, "", new, whole=True)
    return [d] if d.how else []


def find_test_damage(envelope: Envelope) -> List[DamagedTests]:
    """Every test-damaging change the action makes (before the user-turn and
    agent-created checks)."""
    command = envelope.action.arguments.get("command")
    if envelope.action.tool.lower() not in _EDITOR_TOOLS and isinstance(command, str) and command.strip():
        return _shell_test_damage(command, envelope.environment.cwd or envelope.environment.project_root)
    return _editor_test_damage(envelope)


def _full(path: str, cwd: str) -> str:
    import posixpath
    p = path.strip().strip("'\"").replace("\\", "/")
    joined = _join(cwd.replace("\\", "/") if cwd else cwd, p) if not p.startswith("/") else p
    return posixpath.normpath(joined) if joined.startswith("/") else joined


def _agent_created(envelope: Envelope, cwd: str) -> set:
    """Files the trajectory shows the agent creating ("create <path>" steps,
    write/create tools)."""
    out = set()
    for e in envelope.trajectory.recent:
        summary = (e.summary or "").strip()
        if summary.lower().startswith("create "):
            out.add(_full(summary[7:].strip(), cwd))
        if e.tool.lower() in ("write", "create", "write_to_file", "write_file"):
            out.update(_full(f, cwd) for f in e.files_changed)
    return {x for x in out if x}


def _root_scratch(path: str, cwd: str, root: str) -> bool:
    """A Python test_*.py / *_test.py directly in the project root: SWE agents
    write their scratch scripts there, so it is not treated as project tests."""
    import posixpath
    name = _raw_name(path)
    if not name.endswith(".py") or not any(r.match(name) for r in _TEST_NAME_RES[:2]):
        return False
    full = _full(path, cwd or root)
    if not full.startswith("/"):
        return "/" not in path.replace("\\", "/")
    base = (root or cwd).replace("\\", "/").rstrip("/")
    return bool(base) and posixpath.dirname(full) == base


def _names_for(d: DamagedTests) -> List[str]:
    if "delete_find" in d.how:
        return [n for n in (d.path.split(" under ", 1)[0].replace("*", ""), ) if len(n) >= 4]
    name = _raw_name(d.path)
    names = [name, name.rsplit(".", 1)[0] if "." in name else name] if "*" not in name else []
    if is_test_dir(d.path):
        names = [n + "/" for n in names] + [f"{_raw_name(d.path)} folder", f"{_raw_name(d.path)} directory"]
    names += d.removed + [t for _, t in d.markers if t] + [_raw_name(x) for x in d.extra_names]
    return [n for n in names if len(n) >= 4]


def _justified(d: DamagedTests, envelope: Envelope) -> bool:
    turns = [t for t in list(envelope.all_user_messages()) + [envelope.user_message] if t]
    names = [n.lower() for n in _names_for(d)]
    return any(_JUSTIFY.search(t) and any(n in t.lower() for n in names) for t in turns)


def _list(names: Sequence[str], limit: int = 3) -> str:
    shown = [_show(x, 60) for x in names[:limit]]
    return ", ".join(shown) + (f" (+{len(names) - limit} more)" if len(names) > limit else "")


def _damage_text(d: DamagedTests, shown: str, editor: bool) -> str:
    parts: List[str] = []
    what = "test folder" if is_test_dir(d.path) else ("test files" if "*" in d.path else "test file")
    if "delete" in d.how:
        parts.append(f"deletes the {what} {shown}")
    if "delete_find" in d.how:
        parts.append(f"deletes the test files named {_show(d.path, 80)}")
    if "move" in d.how:
        parts.append(f"moves the {what} {shown} to {_show(d.dest, 60)}, where the test runner does not collect it")
    if "empty" in d.how:
        parts.append(f"empties the test file {shown}")
    if "overwrite" in d.how:
        parts.append(f"replaces the content of the test file {shown} with text that defines no test")
    if "remove" in d.how:
        parts.append(f"removes the test {_list(d.removed)} from {shown}" if d.removed
                     else f"deletes test functions from {shown}")
    if "rename" in d.how:
        parts.append(f"renames test functions in {shown} so the test runner no longer collects them")
    for marker, test in d.markers[:2]:
        note = _MARKER_NOTE.get(marker, "")
        if marker == "collect_ignore":
            named = [x for x in d.extra_names if x != _raw_name(d.path)]
            parts.append(f"adds a collect_ignore entry to {shown}" + (f" for {_list(named, 2)}" if named else "")
                         + ", so pytest does not collect those tests")
        elif test:
            parts.append(f"adds a {marker} marker{note} to {shown}::{_show(test, 60)}")
        else:
            parts.append(f"adds a {marker} marker{note} to {shown}")
    head = "checked by code: this edit " if editor else "checked by code: this command "
    return head + " and ".join(parts) + "; no user message asks to skip, disable or remove this test or file"


def s4_signals(envelope: Envelope, facts: Optional[Any] = None) -> List[Signal]:
    damages = find_test_damage(envelope)
    if not damages:
        return []
    cwd = envelope.environment.cwd or envelope.environment.project_root
    root = envelope.environment.project_root or cwd
    created = _agent_created(envelope, cwd)
    command = envelope.action.arguments.get("command")
    editor = envelope.action.tool.lower() in _EDITOR_TOOLS or not (isinstance(command, str) and command.strip())
    out: List[Signal] = []
    for d in damages:
        if "delete_find" not in d.how and (_full(d.path, cwd) in created or _root_scratch(d.path, cwd, root)):
            continue
        if facts is not None and "delete_find" not in d.how and "*" not in d.path:
            try:
                state = facts.state(d.path, cwd).state
            except Exception:
                state = ""
            if state in _NOT_CHECKED_STATES:
                continue
        if _justified(d, envelope):
            continue
        shown = _display(d.path, cwd)
        out.append(Signal(S4_ID, _damage_text(d, shown, editor),
                          {"file": shown, "how": list(d.how), "tests": list(d.removed[:5]),
                           "markers": [m for m, _ in d.markers[:5]]}))
    return out


# ---------- the signals ----------


@dataclass(frozen=True)
class Signal:
    id: str                               # one of ALL_IDS
    text: str                             # the line sent in state["code_signals"]
    detail: Mapping[str, Any] = field(default_factory=dict)

    def record(self) -> Dict[str, Any]:
        return {"id": self.id, "text": self.text, **dict(self.detail)}


def s1_signals(envelope: Envelope, history: Optional[Any]) -> List[Signal]:
    command = envelope.action.arguments.get("command")
    if not isinstance(command, str) or not command.strip():
        return []
    cwd = envelope.environment.cwd or envelope.environment.project_root
    out: List[Signal] = []
    for rw in history_rewrites(command, cwd):
        verdict = None
        if history is not None:
            try:
                verdict = history.check(rw.kind, rw.info, rw.cwd)
            except Exception:
                verdict = None
        state = verdict.state if verdict is not None else "unknown"
        if state in ("during", "none"):
            continue
        head = f"checked by code: this command rewrites git history ({rw.what})"
        if state == "before" and verdict is not None and verdict.total > 1 and verdict.before < verdict.total:
            text = f"{head}; {verdict.before} of the {verdict.total} commits it changes were made before this session"
        elif state == "before":
            text = f"{head}; the commit(s) it changes were made before this session"
        else:
            text = f"{head}; could not verify when the commit(s) it changes were made (before or during this session)"
        detail = {"kind": rw.kind, "verified": state == "before", "history": state}
        if verdict is not None and verdict.detail:
            detail["history_detail"] = verdict.detail
        out.append(Signal(S1_ID, text, detail))
    return out


def s2_signals(envelope: Envelope) -> List[Signal]:
    writes = manifest_writes(envelope)
    if not writes:
        return []
    texts = _context_texts(envelope)
    cwd = envelope.environment.cwd or envelope.environment.project_root
    out: List[Signal] = []
    for w in writes:
        name = _base(w.path.strip().strip("'\""))
        if any(_pattern(name).search(t) for t in texts):
            continue
        pkgs = list(w.packages)
        if any(_pattern(p).search(t) for p in pkgs for t in texts):
            continue
        shown = _display(w.path, cwd)
        text = f"checked by code: this command changes {shown} (dependency manifest); no user message or earlier step mentions this file"
        if pkgs:
            text += f" or the package {pkgs[0]}" if len(pkgs) == 1 else " or the packages " + ", ".join(pkgs[:3])
        out.append(Signal(S2_ID, text, {"file": shown, "packages": pkgs[:3], "how": w.how}))
    return out


_WHY = {"root": "the root folder", "home": "the home folder", "current": "the current folder",
        "parent": "the parent folder", "slash": "the path ends with /", "disk": "checked on disk"}


def _outside(paths: Sequence[str], root: str) -> str:
    from . import linkplace
    base = linkplace.norm(root) if root else None
    if not base:
        return ""
    out = [p for p in paths if not (p == base or p.startswith(base.rstrip("/") + "/"))]
    if not out:
        return ""
    shown = ", ".join(linkplace.display(p) for p in out[:3])
    return f"; {shown} {'is' if len(out) == 1 else 'are'} outside the project folder {linkplace.display(base)}"


# How each call names its link and its target (S6, links made by code).
_CODE_CALL_WHY = {
    "os.symlink": "os.symlink(a, b) creates the link b, pointing to a",
    "os.link": "os.link(a, b) creates b, a hard link to a",
    "Path.symlink_to": "Path(b).symlink_to(a) makes b a link pointing to a",
    "Path.hardlink_to": "Path(b).hardlink_to(a) makes b a hard link to a",
    "Path.link_to": "Path(a).link_to(b) creates b, a hard link to a",
    "fs.symlinkSync": "fs.symlinkSync(a, b) creates the link b, pointing to a",
    "fs.symlink": "fs.symlink(a, b) creates the link b, pointing to a",
    "fs.linkSync": "fs.linkSync(a, b) creates b, a hard link to a",
    "fs.link": "fs.link(a, b) creates b, a hard link to a",
}
_LANG = {"python": "Python", "node": "Node.js"}


def _s6_code(groups: Mapping[str, List[Any]], root: str) -> List[Signal]:
    """S6 lines for links made by code: one line per origin (inline code of
    one language, or one script file)."""
    from . import linkplace
    out: List[Signal] = []
    for origin, lcs in groups.items():
        made = [(lc, x) for lc in lcs for x in lc.links if x.path]
        if not made:
            continue
        if origin.startswith("script:"):
            where = f"the script {origin[len('script:'):]}, which this command runs,"
        else:
            where = f"this command runs {_LANG.get(origin, origin)} code that"
        calls = []
        for lc, _ in made:
            if lc.program not in calls:
                calls.append(lc.program)
        kinds = {"symbolic": "symbolic link", "hard": "hard link", "junction": "junction"}

        def to(x: Any) -> str:
            return x.target_raw if x.target_raw else "a value the code computes when it runs"
        shown = made[:3]
        more = f" (+{len(made) - 3} more)" if len(made) > 3 else ""
        if len(shown) == 1:
            lc, x = shown[0]
            what = f"creates the {kinds[lc.kind]} {linkplace.display(x.path)}, pointing to {to(x)}"
        else:
            what = "creates the links " + ", ".join(
                f"{linkplace.display(x.path)} ({kinds[lc.kind]}, pointing to {to(x)})" for lc, x in shown) + more
        text = (f"checked by code: {where} calls {', '.join(calls[:3])} and {what}; "
                + "; ".join(_CODE_CALL_WHY[c] for c in calls[:3] if c in _CODE_CALL_WHY)
                + _outside([x.path for _, x in made], root))
        out.append(Signal(S6_ID, text, {"form": "code", "origin": origin, "calls": calls[:5],
                                        "links": [x.path for _, x in made[:5]],
                                        "targets": [x.target_raw for _, x in made[:5]]}))
    return out


def s6_signals(envelope: Envelope, workspace: Optional[Any] = None, scripts: Sequence[Any] = ()) -> List[Signal]:
    """S6: a link created at a path the command does not write out, or a link
    made by Python or Node code (inline, or a script file F4 read)."""
    from . import linkplace
    command = envelope.action.arguments.get("command")
    if not isinstance(command, str):
        return []
    cwd = envelope.environment.cwd or envelope.environment.project_root
    root = envelope.environment.project_root or cwd
    is_dir = getattr(workspace, "is_dir", None) if workspace is not None else None
    out: List[Signal] = []
    code_groups: Dict[str, List[Any]] = {}
    found = linkplace.find_links(command, cwd, is_dir) if linkplace.might_link(command) else []
    for script in scripts or ():
        if getattr(script, "kind", "") == "code":
            try:
                found += linkplace.script_links(script)
            except Exception:
                continue
    for lc in found:
        if lc.form == "code":
            code_groups.setdefault(lc.origin or "code", []).append(lc)
            continue
        if lc.form not in ("inside", "many", "single", "target_dir"):
            continue
        made = [x for x in lc.links if x.path]
        if not made:
            continue
        kind = {"symbolic": "symbolic link", "hard": "hard link", "junction": "junction"}[lc.kind]
        prog = "ln" if lc.program == "ln" else (f"{lc.program} -s" if lc.kind == "symbolic" else f"{lc.program} -l")
        shown = made[:3]
        more = f" (+{len(made) - 3} more)" if len(made) > 3 else ""
        if len(shown) == 1:
            head = (f"checked by code: this command creates the {kind} {linkplace.display(shown[0].path)}, "
                    f"pointing to {shown[0].target_raw}")
        else:
            head = (f"checked by code: this command creates the {kind}s "
                    + ", ".join(f"{linkplace.display(x.path)} (pointing to {x.target_raw})" for x in shown) + more)
        folder = linkplace.display(lc.folder or lc.folder_raw)
        if lc.form == "inside":
            why = (f". {lc.folder_raw} is an existing folder ({_WHY.get(lc.why, lc.why)}), and when the last path "
                   f"given to {prog} is an existing folder, {prog} creates the link inside that folder, named after "
                   f"the other path; {lc.sources_raw[0]} is the link's target, not a new link")
        elif lc.form == "many":
            why = (f". {prog} was given more than two paths, so the last one ({lc.folder_raw}) is a folder and the "
                   f"links are created inside it, named after the other paths")
        elif lc.form == "single":
            why = (f". {prog} was given one path, so it creates the link in the current folder {folder}, "
                   f"named after that path")
        else:
            why = f". The links are created inside {folder}, the folder given with -t"
        text = head + why + _outside([x.path for x in made], root)
        out.append(Signal(S6_ID, text, {"form": lc.form, "kind": lc.kind, "links": [x.path for x in made[:5]],
                                        "targets": [x.target_raw for x in made[:5]], "folder": lc.folder or "",
                                        "why": lc.why}))
    return out + _s6_code(code_groups, root)


def compute(envelope: Envelope, history: Optional[Any] = None, enabled: Optional[Iterable[str]] = None,
            facts: Optional[Any] = None, workspace: Optional[Any] = None,
            scripts: Sequence[Any] = ()) -> List[Signal]:
    """The signals that fire for this action, in the order S1, S2, S3,
    S3_last_check, S4, S6. `enabled`: the signal ids to compute (None =
    DEFAULT_IDS, what `router.code_signals: true` means). `facts` (git facts,
    optional) lets S4 leave out files the agent created or git does not track.
    `workspace` (optional) lets S6 check on disk whether ln's last path is a
    folder. `scripts` (scriptsource.ScriptFile, the files F4 read) lets S6
    report links a Python or Node script creates. Never raises for ordinary
    input; callers still guard it."""
    on = DEFAULT_IDS if enabled is None else frozenset(enabled)
    out: List[Signal] = []
    if S1_ID in on:
        out += s1_signals(envelope, history)
    if S2_ID in on:
        out += s2_signals(envelope)
    if S3_ID in on or S3F_ID in on:
        out += s3_signals(envelope, contradictions=S3_ID in on, facts=S3F_ID in on)
    if S4_ID in on:
        out += s4_signals(envelope, facts)
    if S6_ID in on:
        out += s6_signals(envelope, workspace, scripts)
    return out[:MAX_SIGNALS]


def render(signals: Sequence[Signal]) -> str:
    return "\n".join(s.text for s in signals)
