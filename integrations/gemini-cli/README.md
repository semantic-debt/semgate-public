# Semgate → Gemini CLI (native policy, no fork, no launcher)

Semgate is the criterion; Gemini CLI enforces. `write_policy.py` judges each
command with the Semgate router (Jev) and writes an `allow` rule for every
command it confidently clears into Gemini CLI's own native policy file,
`~/.gemini/policies/semgate.toml`. Gemini reads that file at startup and
auto-runs matching commands with no prompt. Commands Semgate sends to ask or
deny are never written, so they keep prompting.

This is the "semantic layer" approach: Semgate does not wrap, launch, or patch
Gemini. It only decides which commands earn a standing native allow rule.

## Preview (writes nothing)

```bash
python integrations/gemini-cli/write_policy.py --dry-run "git status --short" "ls -la" "cat pyproject.toml"
```

Prints the decision per command and the TOML it would write.

## Write the rules

```bash
python integrations/gemini-cli/write_policy.py "git status --short" "ls -la" "grep -rn TODO ." "git log --oneline -5" "cat pyproject.toml"
```

Or from a JSONL file (one `{"command": "...", "user_message": "..."}` per line;
the user message lets Jev judge whether the command matches what was asked):

```bash
python integrations/gemini-cli/write_policy.py --commands-file mycommands.jsonl
```

Flags:
- `--exact` — command-exact rules (`commandRegex = "^git status --short$"`) instead of prefix.
- `--priority N` — rule priority (default 100; user-tier beats the built-in ask rule).
- `--out PATH` — where to write (default `~/.gemini/policies/semgate.toml`).

It never touches Gemini's own `auto-saved.toml`; it writes only `semgate.toml`.

## Verify it took effect

1. Check the file: `type %USERPROFILE%\.gemini\policies\semgate.toml` (Windows) —
   it should list your allow rules.
2. Launch Gemini CLI. If it shows a one-time "policies changed, accept?" prompt
   (its integrity check), accept it once.
3. Inside Gemini, run `/permissions` — your allow rules should be listed.
4. Ask Gemini to run one of the allowed commands (e.g. `git status`). It runs
   with no confirmation prompt. Ask it to run something NOT in the list — it
   still prompts.

## Limits (honest)

- Rules are read at **startup**; a change takes effect on the next launch, not
  mid-session.
- Granularity: prefix by default (`["git","status"]` allows any `git status …`),
  or command-exact with `--exact`.
- This gives **auto-allow** for cleared commands. It does not add live per-call
  denies — for that you also register a `BeforeTool` hook (a `deny`-only path in
  Gemini, same limit as Antigravity). Auto-allow is the piece that removes prompt
  fatigue; the hook is the safety net.
- Writing the file may trigger Gemini's one-time policy-accept prompt.
