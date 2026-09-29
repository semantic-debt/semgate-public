# Security

## Report a vulnerability

Use GitHub private reporting: Security tab, "Report a vulnerability".
Please do not open a public issue for a bypass.

I reply within 7 days. When a fix is released, I publish an advisory
and credit you, unless you ask me not to.

## Supported versions

| Version | Fixes |
|---|---|
| 0.4.x | yes |
| < 0.4 | no |

## What counts

Report privately:
- a fixed rule, human gate or trust gate lets a call through that it should block
- a missing, broken or incomplete config lets a call run
- a way to change the ledger, a grant or semgate's own config from the agent
- a chat reply that is not a clear yes approves a blocked command

Open a public issue instead:
- the Jev judge scores a case wrong (a model decision, not a code bug;
  the measured rates are in EVALS.md)
- a bug in a host (Claude Code, Codex, agy, ...) that semgate works around;
  report those to the host too
