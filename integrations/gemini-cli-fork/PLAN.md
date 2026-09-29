# Semgate → Gemini CLI fork: inline "approve and run" — implementation plan

Status: **SUPERSEDED — the fork is cancelled.** Phase 0 (`FINDINGS.md`) found that
assumption A2 is false: Gemini CLI's BeforeTool hook **already accepts an `ask`
decision and routes to native confirmation** (undocumented; upstream issue
#28046). A fork is therefore unnecessary — approve-and-run is achievable with the
existing **no-fork gateway** (`semgate/gemini_gate.py`). This document is kept for
history; the live plan is the no-fork gateway plus native-Windows runtime
verification. The fork/patch phases (2, 6) are dropped.

Original target (historical): latest upstream `google-gemini/gemini-cli`
(Apache 2.0), Windows-native.
Author date: 2026-09-21.

## 0. Governing principle — Jev judges live, not static rules

The operator's rule: **the model (Jev) makes the call on each command; accumulated
static allow rules do not.** Consequences for this design:

- The fork does **not** write or rely on Gemini's static native-policy prefix
  allow rules (`semgate.toml` / `auto-saved.toml`) to skip judging. A prefix rule
  like `["git"]` clears a whole command family without Jev; that is what we are
  removing, not adding.
- The only cached "yes" the fork honors is an **exact-command human approval**
  (`semgate feedback allow`, keyed on the exact `action_key`) — never a prefix,
  never a whole tool.
- Past accumulated auto-allows were cleared 2026-09-21 (Gemini `auto-saved.toml`
  incl. a `write_file` allow-all; Antigravity learned history, 487 entries;
  1 feedback allow), backed up as `*.semgate-bak-20260921-201241`.

## 1. Objective

**North star: demonstrate the experience so convincingly that it gets merged
upstream.** The fork is not the product — it is the prototype that (a) proves the
UX with a recorded demo and (b) produces the diff for an upstream PR. Success =
the capability lands in `google-gemini/gemini-cli`, after which Semgate needs no
fork at all.

The capability the no-fork integrations cannot provide: an **inline
"blocked → approve and run"** flow inside Gemini CLI, driven by the Semgate
judge. When Semgate blocks or is unsure, the user sees the reason in Gemini's own
confirmation prompt and can approve *that exact command*; the approval is
recorded (`semgate feedback allow`) and the command runs. Confident dangers are
still blocked outright and can never be approved.

Secondary: pluggable model (Jev **or** the user's own model), and a
"3 blocks in a row → show what's happening" display.

### Merge strategy — aim at the general primitive, not a Semgate bolt-on

Maintainers merge general capabilities, not "call this one security tool." So the
primary PR target is the reusable primitive:

- **Target A (preferred, most mergeable): let a BeforeTool hook return an
  `ask`/`confirm` decision**, routed into Gemini's existing confirmation UI —
  the same thing Claude Code's PreToolUse hook already does. This benefits every
  hook author. Semgate then delivers approve-and-run through a plain hook, **no
  fork**. The demo uses Semgate as the flagship example in the PR.
- **Target B (fallback): a Semgate-integrated confirmation feature** in the fork,
  if the maintainers reject a generic hook decision. Less likely to merge; used
  only to keep the demo alive.

The fork prototypes Target A first; if it works, the PR is small and generic and
the fork is discarded on merge.

## 2. Scope — what the fork adds vs. what already exists (reuse, don't rebuild)

| Piece | Source | In the fork? |
|---|---|---|
| Judge, router policy, gates, hard-deny | `semgate/` (Python) | Reused as-is, called as a subprocess |
| Exact-command approval store | `semgate.feedback` (`action_key`) | Reused as-is |
| Deny-only BeforeTool safety net | `integrations/gemini-cli/gemini_hook.py` | Reused unchanged |
| Native auto-allow rules for cleared commands | `integrations/gemini-cli/write_policy.py` → `~/.gemini/policies/semgate.toml` | **Dropped** — violates the Jev-live principle (§0); the fork judges live instead |
| **Inline approve-and-run UX** | — | **NEW (the whole point of the fork)** |
| **3-consecutive-blocks display** | — | **NEW** |
| Bring-your-own-model | `semgate/providers/base.py` interface | New: env selector + one example provider |

The marginal value of the fork is exactly the two **NEW** rows. Everything else
already works without a fork and is kept.

## 3. Non-goals

- Not re-implementing Semgate's decision logic in TypeScript. All policy stays
  in the Python package so it stays version-independent and testable.
- Not maintaining a full copy of Gemini CLI. See §7 (patch-set, not a fork copy).
- Not changing Semgate's safety model. Hard-deny stays unapprovable; the fork
  only surfaces the existing judge decisions in the UI.

## 4. Architecture

### Principle: thin patch, logic out of the fork

The fork adds **one integration module** plus a **minimal call-site edit** in
Gemini's tool-confirmation path. The module shells out to the Semgate judge
(same contract as `gemini_hook.py` today) and returns a decision object. No Jev
SDK, no policy, no gate regex lives in the fork. This keeps the patch small
(easy to rebase on new upstream releases) and keeps one source of truth for
safety.

```
Gemini CLI (patched)
  └─ tool call proposed (run_shell_command)
       └─ [PATCH] semgateGate.evaluate(command, cwd, sessionId)
             └─ subprocess: py -m semgate.gemini_gate  (reuses judge + feedback)
                   → { decision, stage, reason, approvable }
       ├─ allow            → run (or already covered by native policy auto-allow)
       ├─ deny+approvable  → Gemini's AwaitingApproval prompt, enriched with reason
       │                        └─ user approves → semgate feedback allow → run
       │                        └─ user rejects  → block
       └─ deny+hard        → block, no approve option
```

### Decision mapping (mirrors `judge.py` `human_override` rules)

| Judge result | `approvable` | Fork behavior |
|---|---|---|
| `hard_rules/deny` (rm -rf /, gate-config tamper, cloud metadata) | no | Block. No approve option shown. |
| `human_gate` ask (creds, money, exfil, destructive, privesc) | yes | Confirmation prompt with gate reason; approve → feedback allow + run |
| `semantic`/router `deny` | yes | Confirmation prompt with reason; approve overrides semantic → feedback allow + run |
| `semantic`/router `ask` (uncertain) | yes | Confirmation prompt; approve → run |
| `allow` (confident, live Jev clear) | — | Run, no prompt. Decided live per command; no static prefix rule is written. |
| exact-command human approval (`feedback allow`) | — | Run, no prompt. Exact `action_key` only. |
| `grant_validity` (expired) | no (renew) | Prompt to renew grant; never a silent run |

This is consistent with the judge: a human can override a semantic or human-gate
decision, never a hard-deny or an expired grant.

### Bring-your-own-model

`semgate/providers/base.py` already defines the whole contract:
`JudgeProvider.evaluate(state, questions) -> {predicate_id: PredicateAnswer}`.
The gate subprocess selects the provider from `SEMGATE_PROVIDER`
(`typesafe` = Jev default, `fake` = tests, or a user class path). Deliverable: a
worked example `providers/gemini_provider.py` that calls the user's own Gemini
API key, so "use their own model" is real, not theoretical. No fork-side change
needed to swap models.

### 3-consecutive-blocks display

The gate module keeps a tiny per-session counter (same JSONL pattern as the
ledger). On the 3rd consecutive non-allow, the fork renders an expanded panel:
what the three commands had in common (e.g. "all wrote outside the project
folder"), and the options (approve one, widen the grant purpose, switch
profile). Pure presentation on top of decisions the judge already made.

## 5. Patch points — ASSUMPTIONS to confirm in Phase 0

These are from the existing v0.60.0 work and MUST be re-verified against latest
upstream, because we chose latest:

- **A1** Gemini CLI has an interactive confirmation flow: `Notification:ToolPermission`
  then `AwaitingApproval`. → the patch point for the enriched prompt.
- **A2** BeforeTool hooks are **deny-only** (allow ignored). → we cannot get
  approve-and-run from a hook; the fork must patch the confirmation module.
- **A3** Native policy file `~/.gemini/policies/semgate.toml` (prefix/commandRegex,
  priority) is read at startup and auto-runs matches. → auto-allow path.
- **A4** Shell tool name is `run_shell_command`; event carries `tool_input.command`, `cwd`.
- **A5** Build is a TypeScript npm-workspaces monorepo; tool confirmation lives in
  a locatable module (name TBD on latest).

If any of A1–A5 differ on latest, the affected phase is revised before coding.

## 6. Phases (each ends at a gate before the next starts)

**Phase 0 — Clone latest + verify assumptions + survey merge landscape.**
Clone upstream at the latest tag. Confirm A1–A5 by reading the tool-confirmation
and hooks code and by running the existing `gemini_deny_probe.py`. **Also survey
prior art:** search upstream issues/PRs for any existing request to add an
`ask`/confirm hook decision, and read `CONTRIBUTING` + the hooks design docs so
the Target-A PR fits their norms. Deliverable: `FINDINGS.md` with exact file
paths, event shapes, deltas from v0.60.0, and the merge landscape.
GATE: assumptions hold or this plan is amended.

**Phase 6 — Demo + PR.** Record a short screen capture of the full experience
(dangerous command blocked with reason → inline approve → runs; a variation
still blocked; `rm -rf /` shows no approve option; benign runs). Open the
upstream PR for Target A with the Semgate example and the recording. This is the
deliverable that actually achieves the north star.

**Phase 1 — `semgate.gemini_gate` (Python).**
A thin entrypoint the fork calls: reads command+cwd+session, runs the judge,
consults the feedback store, returns `{decision, stage, reason, approvable}`.
Reuses `gemini_hook.py` logic; adds the `approvable` flag and the feedback
write on approve. Unit-tested with FakeProvider (no network).

**Phase 2 — Gate module + confirmation patch (TypeScript).**
`semgateGate.ts` (subprocess call + mapping) and the minimal call-site edit in
the confirmation path (A1). Deny+approvable → enriched AwaitingApproval; approve
→ record feedback + run; hard-deny → block. Behind a config flag so upstream
default behavior is unchanged when Semgate is off.

**Phase 3 — 3-consecutive-blocks display.** Session counter + expanded panel.

**Phase 4 — Pluggable provider.** `SEMGATE_PROVIDER` wiring + example
`gemini_provider.py`. Mostly Semgate-side; documented.

**Phase 5 — Packaging, tests, docs.** Patch-set + install script (§7), TS tests
for the gate, Python tests for `gemini_gate`, an end-to-end approve-and-run test
(blocked → approve → runs; variation → still blocked; `rm -rf /` → never
approvable), and a README.

## 7. Maintenance model — patch-set, not a fork copy

Do **not** vendor a full copy of Gemini CLI. Instead:

- Keep our changes as a small **git patch series** under
  `integrations/gemini-cli-fork/patches/`.
- Ship `install.py` that: clones upstream at a pinned tag, applies the patches,
  `npm install` + build, and links the binary. Re-pinning to a newer upstream =
  re-apply patches, fix any rejects, re-run tests.
- Track which upstream tag each patch set was verified against.

This bounds maintenance to "keep a handful of small patches applying," not
"track an entire fork." If the patches grow large or reject often, that is the
signal to instead pursue the upstream PR (add an `ask` decision to hook
outputs), which removes the fork entirely.

## 8. Testing

- **Python:** `gemini_gate` decision + feedback round-trip (FakeProvider, offline).
  Reuse the exact-command / variation / hard-deny cases we added for the
  Antigravity hook.
- **TypeScript:** `semgateGate.ts` mapping + confirmation routing, using Gemini's
  own test harness.
- **End-to-end (in the built fork):** blocked command → approve → runs; a
  variation stays blocked; `rm -rf /` shows no approve option; confident-benign
  auto-runs via native policy.
- **Latency:** confirm a synchronous Jev call fits the confirmation budget
  (v0.60.0 hook budget was ~7s; Jev op timeout 4s). Per §0 we do **not** use
  static prefix auto-allow as the latency escape. If it is tight, the only
  allowed cache is an exact-command result (Jev's own recent clear or a human
  `feedback allow`), never a prefix/family rule. Otherwise Jev is called live.

## 9. Risks and open questions

- **R1 Upstream drift (latest).** Latest may have changed the confirmation flow
  or hooks API since v0.60.0; Phase 0 exists to catch this. Latest also moves,
  so we pin a tag.
- **R2 OS — DECIDED: Windows-native.** The prior prototype was POSIX-only, so
  this is real added work: path handling, shell quoting (PowerShell/cmd), the
  subprocess call to Python, and hook plumbing all need Windows testing. The
  existing hard-deny rules already include Windows/PowerShell catastrophic
  patterns, but the confirmation-flow patch and the gate subprocess must be
  verified on native Windows in Phase 0.
- **R3 Hooks-only might suffice.** If latest upstream has since added a richer
  hook decision (ask/confirm), the fork may be unnecessary — a hook could do
  approve-and-run. Phase 0 checks this; if true, we drop the fork.
- **R4 Latency on the interactive path.** Synchronous model calls in the
  confirmation flow can feel slow. Mitigation: native-policy auto-allow for
  repeats; call the model only on first sight.
- **R5 Fork/patch upkeep.** Every upstream bump needs patch re-application. §7
  keeps this small; the upstream PR is the exit.

## 10. Decisions needed from you before Phase 0

1. ~~OS target~~ — **DECIDED: Windows-native.**
2. ~~Fork exit strategy~~ — **DECIDED: the fork is a prototype to prove the UX and
   produce the upstream PR (Target A). It is discarded on merge.**
3. **Forward auto-allow policy:** past auto-allows are cleared. Do you also want
   Antigravity's `propagate_learned_allow` / `auto_allow_learned` turned **off**
   in `.antigravity/semgate.json`, so the learned history does not rebuild and
   bypass Jev again? (Consistent with §0; trade-off is more prompts.)
4. **Approve of this plan** to proceed to Phase 0 (clone latest + verify A1–A5).
