# The `semgate` agent skill: where each host reads it

`semgate init <host>` writes `semgate/assets/semgate_skill.md` as a user-level
skill named `semgate`. `semgate init <host> --no-skill` skips it.
`semgate uninstall <host>` removes it (see "Shared file" below). The skill
tells the agent what to do with an ask, a block, a hard deny, a block that
cannot be approved in chat, a question about an instruction file, and a
user's request to trust a command (`semgate trust`).

Every host reads a folder `<skills folder>/semgate/SKILL.md` whose YAML front
matter has `name` and `description`. `name` is `semgate`, the same as the
folder name, lower case (OpenCode and Pi require this). No host needs a
section in a global instructions file: every host below has user-level
skills.

| host (`semgate init`) | file semgate writes | source (checked 2026-09-24) |
|---|---|---|
| `claude` (Claude Code 2.1.281) | `~/.claude/skills/semgate/SKILL.md` | Installed binary: "**Personal** (`~/.claude/skills/<name>/SKILL.md`) — follows you across all repos". Docs: https://code.claude.com/docs/en/skills |
| `antigravity` (agy 1.2.10) | `~/.gemini/config/skills/semgate/SKILL.md` | Docs bundled in the agy binary: "Global Discovery: `~/.gemini/config/`" and "Location: `skills/<skill_name>/` (relative to the customization root)". Docs: https://antigravity.google/docs/skills ("`~/.gemini/config/skills/<skill-folder>/`"). The folder already holds 33 skills on the test machine. |
| `codex` (codex-cli 0.153.1) | `~/.agents/skills/semgate/SKILL.md` | Source at tag `rust-v0.153.1`, `codex-rs/ext/skills/src/host_roots.rs`: user scope `$HOME/.agents/skills`; `$CODEX_HOME/skills` (`~/.codex/skills`) is marked "Deprecated user skills location ... kept for backward compatibility". Docs: "USER \| `$HOME/.agents/skills`". |
| `opencode` (V1 docs; V2 preview binary installed) | `~/.agents/skills/semgate/SKILL.md` | https://opencode.ai/docs/skills: global `~/.config/opencode/skills/`, `~/.claude/skills/`, `~/.agents/skills/`. The opencode2 binary adds `~/.agents` and `~/.claude` as discovery roots. |
| `pi` (not installed on the test machine) | `~/.agents/skills/semgate/SKILL.md` | Pi `docs/skills.md`: "Pi also supports the Agent Skills locations `~/.agents/skills/` and `.agents/skills/`". Source `package-manager.ts`: `join(getHomeDir(), ".agents", "skills")`; its own folder is `~/.pi/agent/skills`. |
| `droid` (Factory 0.164.0, WSL) | `~/.agents/skills/semgate/SKILL.md` | https://docs.factory.ai/cli/configuration/skills: personal skills in `~/.factory/skills/`, "also reads from `~/.agents/skills/` and `~/.agent/skills/`". The binary's scan code adds `.agents/skills` under the home folder. |
| `copilot` (not installed on the test machine) | `~/.agents/skills/semgate/SKILL.md` | https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-skills: "create a `~/.copilot/skills` or `~/.agents/skills` directory". Docs only. |

Not read by Claude Code or agy: `~/.agents/skills` (Claude Code only imports
from it once, for Cursor users; the agy binary and docs do not name it).

## Shared file

`~/.agents/skills/semgate/SKILL.md` serves codex, opencode, pi, droid and
copilot. `semgate uninstall <one of them>` keeps it while another of the five
still has a semgate hook installed, and prints which ones; the last uninstall
removes it. OpenCode also reads `~/.claude/skills`, so with `claude` and
`opencode` both installed it finds the same skill twice (same name, same text).

## Safety of the write

- The file carries the line `<!-- written by \`semgate init\`; \`semgate uninstall\` removes it -->`.
  A `semgate/SKILL.md` without that line is the user's own: semgate never
  overwrites or removes it (`skill: refused: the file exists and was not
  written by semgate`).
- Writes go through `safemerge.safe_write`: a backup of an older semgate
  version first, an atomic replace, and `SEMGATE_WRITE_ROOT` in tests.
- `--dry-run` prints `skill: would write <path>` and writes nothing.

## Output of `semgate init claude`

```
skill: write                               C:\Users\you\.claude\skills\semgate\SKILL.md
```

A second run prints `skill: unchanged`.
