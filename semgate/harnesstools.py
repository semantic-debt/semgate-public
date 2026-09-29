"""Harness tools: the tools a coding-agent host adds besides shell, files and
web (ask the user a question, load a skill, keep a to-do list).

Owner rule: the agent may use a tool of the harness unless that tool does
something dangerous. So each harness tool is judged by what it does:

  ask_user   OpenCode `question`, Claude Code `AskUserQuestion`, Codex
             `request_user_input`, `ask_user`. It shows a question to the
             person and returns the answer. No file, command or network
             effect. Allowed by code (ALLOW_DISPLAY), before the hard-deny
             patterns and the human gates: its arguments are text shown to
             the person ("May I run `git push`?"), not an action, so a
             pattern in them must not block the question.
  todo       OpenCode `todowrite` / `todoread`, Claude Code `TodoWrite`. It
             changes only the host's own to-do list of this session. Same
             rule as ask_user.
  skill      OpenCode `skill`, Claude Code `Skill`: loads a skill's text into
             the conversation. The text is scanned like any tool output when
             it comes back. Allowed by code only when loading it runs
             nothing (skill_check): OpenCode's skill tool returns the
             SKILL.md text and a file list (OpenCode 2.0.15 binary). Claude
             Code runs the !`command` lines of a skill or command file
             before the text is sent (code.claude.com/docs/en/skills,
             "Inject dynamic context"), so there the file is read first: no
             such line -> allowed; such lines -> each line goes through the
             hard-deny patterns and the gates, and the load is the human
             gate `skill_commands`; the file not found (a plugin skill, a
             namespaced name) -> no code decision, the model judges it. The
             hard rules and gates still run on the skill's arguments first.

Installing a skill, tool or MCP server is not one of these: a write into a
skill folder is the human gate instruction_file_edit, and a host CLI that
registers an MCP server, plugin or skill (`claude mcp add`, `opencode mcp
add`, `npx skills add` ...) is the human gate agent_config (rules.py).

Every other tool (OpenCode `execute`, `task`, unknown names) is judged by the
model like any action, and the host's enforcement keeps its local
auto_allow_tools list for model allows (fail closed for unknown tools).
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Optional, Tuple

from .envelope import Envelope

# Canonical names (adapters map the hosts' names to these).
ASK_USER = "ask_user"
TODO = "todo"
SKILL = "skill"
# No effect outside the host's own session: allowed by code before the
# pattern rules (their arguments are text for the person).
ALLOW_DISPLAY = frozenset({ASK_USER, TODO})
REASON_CODE = "harness_tool_allow"
GATE_CLASS = "skill_commands"

# Host tool names (lowercased) -> canonical. Only names whose meaning was
# checked (host docs, host binary) are listed; an unknown name stays itself.
HOST_NAMES = {
    "question": ASK_USER,            # OpenCode 2.0.15 (V2) and V1: ask the user, with options
    "askuserquestion": ASK_USER,     # Claude Code (code.claude.com/docs/en/agent-sdk/user-input)
    "request_user_input": ASK_USER,  # Codex (plan mode)
    "ask_user": ASK_USER,
    "todowrite": TODO,               # OpenCode V1, Claude Code TodoWrite
    "todoread": TODO,                # OpenCode V1
    "skill": SKILL,                  # OpenCode `skill` ({"name"} / {"id"}), Claude Code `Skill` ({"skill", "args"})
}

# Hosts whose skill tool only returns text (no command runs at load).
TEXT_ONLY_SKILL_HOSTS = frozenset({"opencode-plugin"})
# Claude Code dynamic context: !`command` (inline) and a ```! fenced block.
_BANG_INLINE = re.compile(r"(?<![\w`])!`([^`\n]+)`")
_BANG_FENCE = re.compile(r"^```!\s*\n(.*?)^```", re.MULTILINE | re.DOTALL)
_SKILL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_READ_CAP = 256 * 1024


def canonical(native: str) -> str:
    """The canonical name of a host tool name, or "" when it is not a harness tool here."""
    return HOST_NAMES.get(str(native or "").strip().lower(), "")


def display_allow(envelope: Envelope) -> bool:
    """True for ask_user and todo (ALLOW_DISPLAY)."""
    return envelope.action.tool in ALLOW_DISPLAY


def skill_name(envelope: Envelope) -> str:
    args = envelope.action.arguments
    for key in ("skill", "name", "id"):
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


@dataclass(frozen=True)
class SkillCheck:
    allow: bool = False                   # code allows the load (nothing runs)
    commands: Tuple[str, ...] = ()        # !`command` lines the load runs
    files: Tuple[str, ...] = ()           # the skill / command files read
    why: str = ""                         # one line for the decision's reasons
    unknown: bool = field(default=False)  # file not found: the model judges


def _skill_files(name: str, project_root: str) -> List[Path]:
    """Claude Code's personal and project skill and command files for `name`."""
    bases = []
    if project_root:
        bases.append(Path(project_root))
    bases.append(Path(os.path.expanduser("~")))
    found: List[Path] = []
    for base in bases:
        for rel in ((".claude", "skills", name, "SKILL.md"), (".claude", "commands", name + ".md")):
            path = base.joinpath(*rel)
            try:
                if path.is_file() and path not in found:
                    found.append(path)
            except OSError:
                continue
    return found


def dynamic_commands(text: str) -> List[str]:
    """The !`command` lines (and ```! blocks) of a Claude Code skill text."""
    out = [m.group(1).strip() for m in _BANG_INLINE.finditer(text)]
    for m in _BANG_FENCE.finditer(text):
        out.extend(line.strip() for line in m.group(1).splitlines() if line.strip())
    return [c for c in out if c]


def skill_check(envelope: Envelope) -> SkillCheck:
    """What loading this skill does. Only for tool `skill`."""
    if envelope.action.tool != SKILL:
        return SkillCheck()
    name = skill_name(envelope)
    if envelope.environment.harness in TEXT_ONLY_SKILL_HOSTS:
        return SkillCheck(allow=True, why=f"loads the text of skill {name!r} (this host's skill tool runs no command)")
    if not _SKILL_NAME.match(name) or ".." in name:
        return SkillCheck(unknown=True, why=f"skill {name!r}: not a plain skill name, its file was not looked up")
    files = _skill_files(name, envelope.environment.project_root)
    if not files:
        return SkillCheck(unknown=True, why=f"skill {name!r}: no skill or command file found in .claude/skills or .claude/commands")
    commands: List[str] = []
    for path in files:
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                text = handle.read(_READ_CAP + 1)
        except OSError:
            return SkillCheck(unknown=True, files=tuple(str(f) for f in files),
                              why=f"skill {name!r}: {path} could not be read")
        if len(text) > _READ_CAP:
            return SkillCheck(unknown=True, files=tuple(str(f) for f in files),
                              why=f"skill {name!r}: {path} is larger than {_READ_CAP} bytes; not checked")
        commands.extend(dynamic_commands(text))
    shown = tuple(str(f) for f in files)
    if commands:
        return SkillCheck(commands=tuple(dict.fromkeys(commands)), files=shown,
                          why=f"skill {name!r} runs shell commands when it loads")
    return SkillCheck(allow=True, files=shown, why=f"loads the text of skill {name!r} ({', '.join(shown)}); it runs no command")


# OpenCode code mode (`execute`): model-written JavaScript that calls the
# host's tools, e.g. `await tools.shell({ command: "git status", workdir })`.
# The hard-deny patterns are written for a shell line (`rm -rf /` must end
# the line), so a command inside a JS string needs to be taken out first.
CODE_TOOLS = frozenset({"execute"})
_CODE_COMMAND = re.compile(r"""\b(?:command|cmd)["']?\s*:\s*(["'`])((?:\\.|(?!\1)[^\\])*)\1""", re.DOTALL)
_JS_ESCAPES = {"n": "\n", "t": "\t", "r": "\r"}


def code_commands(code: str) -> List[str]:
    """The string literals given as `command:` (or `cmd:`) in the code, JS
    escapes undone. A command built at run time (a variable, a
    concatenation) is not found here: the model and the gates still read
    the whole code."""
    out: List[str] = []
    for m in _CODE_COMMAND.finditer(code or ""):
        text = re.sub(r"\\(.)", lambda e: _JS_ESCAPES.get(e.group(1), e.group(1)), m.group(2), flags=re.DOTALL)
        if text.strip():
            out.append(text.strip())
    return out


def inner_commands(envelope: Envelope, skill: "SkillCheck") -> List[Tuple[str, str]]:
    """(where, command) of the shell commands this action runs that are not
    its `command` argument: a skill's !`command` lines, the `command:`
    strings of OpenCode code-mode JavaScript."""
    if skill.commands:
        return [(skill.why, c) for c in skill.commands]
    if envelope.action.tool in CODE_TOOLS:
        code = envelope.action.arguments.get("code")
        if isinstance(code, str):
            return [("the command in the execute code", c) for c in code_commands(code)[:20]]
    return []


def command_envelope(envelope: Envelope, command: str) -> Envelope:
    """The envelope of one !`command` line run as a shell command: same grant,
    user and project, no trajectory."""
    import dataclasses
    from .envelope import ProposedAction, Trajectory
    return dataclasses.replace(envelope, action=ProposedAction(tool="bash", arguments={"command": command}),
                               trajectory=Trajectory())


def tools_text(tool: str) -> Optional[str]:
    """One line on why this canonical harness tool is allowed, or None."""
    if tool == ASK_USER:
        return "asks the user a question; no file, command or network effect"
    if tool == TODO:
        return "changes only the host's own to-do list of this session"
    return None
