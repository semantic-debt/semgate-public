# Hosts: adapters, capability manifests, safe config merge, doctor

Code: `semgate/hosts/` (interface and adapters), `semgate/data/hosts/*.json`
(manifests), `semgate/safemerge.py` (config edits), `semgate/doctor.py`.

## Host adapter

Each host (`semgate/hosts/builtin.py`) has:

| member | what it does |
|---|---|
| `name`, `display` | `claude`, `droid`, `antigravity`, `opencode`, `codex`, `pi`, `vscode`, `copilot` |
| `config_paths(env)` | user-level folders, project-level files (when the host has them), the file semgate edits |
| `detect(env)` | binary on PATH or config folder present; version from `<binary> --version` |
| `plan_install(req)` / `plan_uninstall(file)` | the new text of the host file; writes nothing; raises `MergeRefused` |
| `verify(env)` | semgate's hook present, interpreter and semgate.json exist, fail-closed settings |
| `mode_warnings(env)` | host settings that turn off the host's own prompts |
| `hook_configs(env)` | the `--config` path of each installed semgate hook (read only); `semgate feedback` uses it when no `--config`/`--store` is given (`semgate/hosts/installed.py`) |
| `manifest(version)` | the capability manifest |

`semgate init <host>` and `semgate uninstall <host>` use them. Installable:
antigravity, claude, codex, droid, copilot, opencode, pi. VS Code is
detect/doctor only. Codex uses `$CODEX_HOME/hooks.json` (or `~/.codex/hooks.json`)
with PreToolUse and PostToolUse entries. On Windows its hook commands use
PowerShell's call operator and return the Python process's exit status.
Codex must trust the hook configuration before it will run it.
Pi uses `$PI_CODING_AGENT_DIR/extensions/semgate.ts` (default
`~/.pi/agent/extensions/semgate.ts`). The extension blocks a call whenever
semgate answers ask or deny, and also blocks if its judge process fails.

## Capability manifest

One JSON file per host, schema `semgate-host-manifest/1`. For each capability
id of `docs/harness-hooks-survey.md` that semgate relies on (C1 deny, C2 ask,
C2b ask under bypass / YOLO mode (hookconf A2b; not a survey id), C3 allow, C6 headless, C8 full input, C10 ids, C11 transcript, C12 model id,
C14 output hook, C17 subagents, C19 fail-closed, C21 tamper, C26 schema
version, C33 post-tool context, C34 message at stop, C35 chat approval:
ordered user turns after a block, see `semgate/chatapproval.py`): `status`
yes / no / partial / unknown, `source` (hookconf result
file and requirement ids, a live-test note, or a doc URL), `verified`
(measured, not only read in docs), `note`.

Only `yes` counts as supported. A missing cell, an unknown status or a
manifest that does not load is `unknown`. When C2 is not `yes`,
`hosts.fit_decision()` turns semgate's ask into a deny and prefixes the reason:
`semgate: Codex CLI cannot show an ask prompt (manifest C2 = no, measured on
0.153.1), so this ask is a deny.` claude_hook applies it to every host that has
a manifest; vscode, copilot and devin have none and keep their old rendering.

`hosts.host_shows_ask(host)` is True only when every manifest of the host has
C2 = yes and C2b = yes with `verified` true (Claude Code today). `semgate init`
writes `enforcement.block_when_unsure = not host_shows_ask(host)`, and
`semgate doctor` warns about block_when_unsure off only where it is False.

Seeded: claude 2.1.280, codex 0.153.1, opencode-v1 1.18.31, opencode-v2
(V2 entry on 1.18.31), pi 0.86.0 (all from hookconf results, 2026-09-23);
antigravity 1.2.8 (live notes); droid (docs only, nothing measured).

## Safe config merge

For every host file semgate edits:

1. Invalid JSON, or a key semgate must touch with the wrong type (`hooks` is a
   list, `PreToolUse` is an object, a group without a `hooks` list, `semgate`
   is a string): refuse, exit 2, file untouched, nothing else written.
2. Text edit, not a rewrite: only semgate's entries are inserted, replaced or
   removed; every other byte stays. The result is parsed again and must equal
   the intended document. If not: a JSONC file is refused and the intended
   document is printed to paste by hand; a strict JSON file falls back to the
   old full rewrite.
3. Never looser: the document without semgate's entries must be the same
   before and after. semgate's entries contain no bypass or auto-approve.
4. Backup `<name>.semgate-bak-<timestamp>` next to the file, then temp file +
   `os.replace`. A re-run that changes nothing writes nothing.
5. `SEMGATE_WRITE_ROOT` (the test suite sets it to the pytest temp root):
   writes outside it are refused.

JSONC (comments, trailing commas) is supported by the editor; today no
installer target is JSONC (Claude, agy and Droid files are strict JSON,
OpenCode gets a plugin file).

## semgate doctor

Read only. `semgate doctor [--json] [--project DIR] [--no-exec]`. One line per
detected host (status OK / WARN / FAIL / UNGATED), then every WARN and FAIL,
then a summary with the TypeSafe key: found or not found, and where
(environment variable, `~/.semgate/.env`, the source checkout's `.env`). The
key and its length are never printed. Exit 1 when any host is FAIL.
