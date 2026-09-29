# Warp integration

Warp's agent has no hook an external gate can use (read from source,
`warpdotdev/warp@71088ba`, unchanged at `e865a74`): every agent command is
decided in `BlocklistAIPermissions::can_autoexecute_command` from org/user
regex lists, run-to-completion, and the model's own `is_read_only` /
`is_risky` flags.

## Status (2026-09-23)

Warp is already building hooks: draft PR
[#15832](https://github.com/warpdotdev/warp/pull/15832) "APP-4344: Add
first-party Oz lifecycle hooks" (bot-authored, draft since 2026-09-05, specs in
`specs/APP-4344/`). Its v1 decisions:

- 7 events (SessionStart, SessionEnd, UserPromptSubmit, PreToolUse, PostToolUse,
  PreCompact, Stop); config read once per session; schema versions; project
  hooks only after a hash trust prompt.
- PreToolUse can only **deny** ("hooks can reduce authority, not increase it");
  `allow`, `ask`, `updatedInput`, `additionalContext` are treated as failures.
- Failure default: run anyway (`on_failure: "continue"`); deny is opt-in.
- Tool input is heavily redacted: MCP calls send argument names only, file edits
  send paths only, 17 action types are fully redacted; no user prompt in
  PreToolUse.

So our own earlier spec draft for #7834 (not in this repository) would compete
with Warp's design and is **superseded**. The plan is a short review comment on #15832 (linking #7834)
that asks for a small delta on top of APP-4344. Measured evidence for the
comment comes from the hook conformance kit (`hookconf`, local): Warp today is
"no hook system" on every requirement.

That spec draft is not going to be posted.

Upstream proposal drafts are kept outside the repo.
