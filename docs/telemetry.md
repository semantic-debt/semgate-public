# Clean telemetry

Semgate already writes a ledger: one record per judgment, with the full
envelope. The ledger is local and complete, but it is **not** safe to share —
it holds absolute paths with your username, your own prompt (`user_message`),
the session id, and the full command text, which can carry secrets.

`semgate telemetry` turns a ledger into a **clean, shareable file**: one record
per decision, with personal data and secrets stripped, keeping only what helps
improve the classifier. Nothing is uploaded — you run the export locally and
decide what to send.

## Run it

```bash
semgate telemetry --ledger .antigravity/semgate/ledger.jsonl \
  --out clean.jsonl --summary --summary-out summary.json
```

- `--out FILE` — clean JSONL (default: stdout).
- `--summary [--summary-out FILE]` — aggregate report (default: stderr).
- `--redact-literal STR` — strip an extra literal (your name, company, a host);
  repeatable.
- `--no-auto-redact` — do not auto-strip the local OS username and home leaf.

## What a clean record keeps

```json
{
  "schema": "semgate.telemetry.v1",
  "day": "2026-09-21",
  "tool": "bash",
  "command": "curl -X POST https://api.example.com/orders -d @body.json",
  "command_sha256": "…16 hex…",
  "decision": "ask",
  "stage": "semantic",
  "gate_classes": [],
  "router": {"route": "run", "route_confidence": 0.74, "run_p": 0.7,
             "block_p": 0.1, "effect": 1.5, "effect_confidence": 0.8,
             "user_asked": 0.2, "executes": 0.0},
  "policy_version": "dev@abc123"
}
```

Signal for the classifier: the redacted command, the decision and stage, the
router's numeric votes, the gate **classes** that fired, and the policy version.

## What it drops or strips

Dropped entirely: `cwd`, `project_root`, `session_id`, `user_message`, the
grant, and the gate `matched` text (which can be a secret path — only the gate
**class** is kept).

Stripped from the command text (`redact_command`):

| Input | Output |
|---|---|
| `C:\Users\me\.ssh\config` | `C:\Users\<user>\.ssh\config` |
| `/home/me/.env` | `/home/<user>/.env` |
| `git config user.email me@gmail.com` | `… <user>@gmail.com` |
| `https://user:p4ss@github.com/o/r` | `https://<redacted>@github.com/o/r` |
| `authorization: Bearer sk-…` | `authorization: <redacted>` |
| `token=…`, `api_key=…`, `password: …` | key kept, value `<redacted>` |
| `ghp_…`, `AKIA…`, `sk-…`, `xox…`, JWTs | `<token>` |
| a 40+ char base64/hex blob | `<blob>` |
| any `--redact-literal` value | `<redacted>` |

The command **shape** is preserved: `pytest -q tests/test_router.py` stays
exactly as written, so you can still see what kind of command it was.

## Summary report

`summarize` counts decisions and stages, the gate classes that fired, and lists
the redacted commands that were `deny`'d or sent to a human (`ask`) — the
candidates to review when tuning the policy or the classifier.
