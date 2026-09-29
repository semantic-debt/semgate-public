# Phase 0 findings — v2 implementation slice

Status: **source investigation complete for the initial hook decision; native runtime gate OPEN**.
This file amends the implementation direction, not the original historical plan.

## Pinned sources

- Semgate base: `plan-review@9449f3596bf0bc940b99be0e2ce837f2a3030bfa`.
- Gemini source reference: `v0.60.0`, not a claim that a local Windows installation was inspected.
- [Hook decision plumbing](https://github.com/google-gemini/gemini-cli/blob/v0.60.0/packages/core/src/scheduler/hook-utils.ts).
- [Scheduler and confirmation routing](https://github.com/google-gemini/gemini-cli/blob/v0.60.0/packages/core/src/scheduler/scheduler.ts).
- [Shell parameters](https://github.com/google-gemini/gemini-cli/blob/v0.60.0/packages/core/src/tools/shell.ts): `command`, `description`, `dir_path`, background/delay and additional permissions require distinct treatment.
- [Existing documentation gap #28046](https://github.com/google-gemini/gemini-cli/issues/28046) independently describes implemented `ask` versus incomplete documentation.
- [Official hook reference](https://geminicli.com/docs/hooks/reference/): JSON stdin/stdout, exit 2 blocks, other failures may be warnings; timeout is configurable.
- [Official hook mechanics](https://geminicli.com/docs/hooks/): malformed stdout can cause non-blocking host behavior. A worker failing closed does not prove the whole harness fails closed.

## A1–A5 disposition

| Assumption | Disposition |
|---|---|
| A1: native confirmation exists | Source supports it; installed Windows behavior remains unverified. |
| A2: BeforeTool is deny-only | Not valid for the pinned scheduler. It consumes `ask` and invokes native confirmation. Do not add a duplicate primitive. |
| A3: native policy auto-allow is the fast path | Removed from this implementation slice. No standing allow rule, prefix permission or model-result cache is written. |
| A4: shell input is command plus cwd | Incomplete: `dir_path`, background execution and extra permissions also matter. This slice explicitly denies unverified variants. |
| A5: TypeScript patch point is needed | No patch is authorized by these findings. Verify the existing no-fork interaction first. |

## Implemented now

1. Lossless, versioned request identity across full arguments, grant, execution context and policy/provider. No legacy key migration and no permission implied by possessing a digest.
2. Strict input and external config validation, short-lived grants, fixed-argv isolated Python worker, bounded worker deadline and structured denial on handled failures.
3. One-shot confirmation probe, disabled by default. A model `allow` still becomes native `ask`; hard denial, expiry, provider failure and missing evidence become native `deny`.
4. No feedback/history passed to the judge. No reusable approval store, model cache or tool execution.
5. Offline tests plus a CI matrix for Linux/Windows and Python 3.9/3.12. See workflow runs for results, not this document for an assumed pass.

## Blocking runtime experiment

On a disposable **native Windows** workspace, pin and record the installed Gemini version. Enable only the supervised confirmation probe and verify:

- Hook `ask` shows the reason and proceeds only after the operator selects proceed-once.
- Operator rejection does not execute the pending action; a changed command prompts again.
- Host DENY plus hook ASK does not become approvable. The inspected source ordering makes this mandatory; it is not a demonstrated runtime bypass.
- Hard-deny output and gateway exit 2 prevent the exact pending action.
- Timeout, hook launch failure, disabled hook, killed parent and corrupt output cannot lead to unjudged execution in the chosen host mode.
- Additional hooks cannot rewrite an already-reviewed request into a different executed action.

Use harmless sentinel actions to prove whether execution happened; do not execute destructive examples. An API/model key is unnecessary for the first `ask` probe (`provider: none`). No blanket YOLO or broad static allow rules.

## Phase gates

- **0: partial GO** — source and portable preparation done; Windows interaction/precedence still open.
- **1: foundation only** — parser, identity and conservative gateway implemented; no production approval authority.
- **2: HOLD** — no duplicate confirmation patch. Isolate a real missing generic capability first.
- **3: HOLD** — consecutive-block UI deferred.
- **4: existing provider reused** — no new provider plugin loader or arbitrary class-path imports.
- **5: NO-GO for release** — CI and Windows host E2E are separate requirements; full native-Windows legacy-suite coverage is also outstanding.
- **6: HOLD** — no upstream feature PR or production demo yet.

## Verification limits

The working container could not resolve GitHub for a clone. Source reads and remote Git object operations use the connected API. Local testing covers the new standalone unit/contract suite, not a fabricated full checkout. The dedicated real-engine tests and complete Linux suite are included in CI against the actual repository. Native Gemini E2E, live Jev latency and same-user OS isolation are not validated here.
