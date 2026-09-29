# Plan review — instructions for the reviewer

You are reviewing a plan, not code that ships today. Read these two documents and
answer the questions below with specific, actionable findings. Be adversarial:
the goal is to catch flawed assumptions before we spend effort.

## What to read

1. `integrations/gemini-cli-fork/PLAN.md` — plan to fork Gemini CLI as a
   prototype whose real output is (a) a demo and (b) an upstream PR that adds a
   general `ask`/confirm decision to BeforeTool hooks. The fork is discarded on
   merge.
2. The multi-host strategy draft (Semgate as a host-agnostic gate adopted by
   many agent CLIs via thin adapters + one generic upstream contribution per
   host). It is not in this repository; upstream proposal drafts are kept
   outside the repo.

Supporting context (for grounding, not review targets):
- `semgate/judge.py`, `semgate/rules.py` — the host-agnostic decision engine.
- `semgate/antigravity_hook.py` — the reference host integration; note the
  recently added `human_approved` allow path (approve-and-run, exact-command
  scoped).
- `semgate/adapters/antigravity.py`, `semgate/adapters/opencode.py` — the adapter
  pattern (two functions per host).

## Questions to answer

1. **Merge realism.** Will Gemini CLI maintainers plausibly accept a generic
   "hook can return `ask`/confirm" decision? Is Target A framed generically
   enough, or does it still read as a Semgate-specific feature? Cite their
   contribution norms if you can.
2. **Phase 0 assumptions (A1–A5).** Are any likely wrong on *latest* Gemini CLI
   (not v0.60.0)? Specifically: is the BeforeTool hook still deny-only, does the
   confirmation flow (`Notification:ToolPermission` → `AwaitingApproval`) still
   exist, and where is the tool-confirmation code?
3. **Jev-live principle.** The plan forbids static prefix auto-allow; every novel
   command is judged live by Jev. Is that viable within the interactive
   confirmation latency budget (~7s hook, 4s Jev op)? If not, what is the minimal
   acceptable cache (exact-command only)?
4. **Windows-native risk.** The prior prototype was POSIX-only. What breaks on
   native Windows (shell quoting, subprocess to Python, hook plumbing) that the
   plan underestimates?
5. **Security of the approve path.** The `human_approved` allow now bypasses
   `auto_allow_tools`. Verify it is scoped to the exact `action_key`, never
   overrides a hard-deny or expired grant, and cannot be triggered by the agent
   (only the operator's own terminal). Any hole?
6. **Multi-host correctness.** Is OpenHands' security-analyzer the right
   integration point (no fork)? Is the Warp assessment (closed-source, not a PR)
   correct? Any host mischaracterized?
7. **Better alternative.** Is there a lower-effort path that reaches the same
   north star (e.g., skip the fork, ship the demo differently, or a different
   upstream primitive)?

## How to verify claims

- Run the test suite: `py -m pytest tests/ --ignore=tests/tests -q` (should pass).
- Inspect the approve-and-run tests in `tests/test_antigravity_hook.py`
  (`test_feedback_approved_exact_command_runs_variation_stays_blocked`,
  `test_feedback_allow_never_overrides_hard_deny`).

## Deliverable

A written review with a **go / no-go per phase** and the highest-risk assumption
to verify first in Phase 0. Flag anything that would waste effort if wrong.
