# Properties (written before the specs)

Scope: shared state that several semgate processes (or several `semgate serve`
requests) read and write. Written for commit 7f4f160 (branch product-foundation);
updated for branch concurrency-fixes (see "Changes after the fixes" below).

Kinds: `[]P` invariant; `P ~> Q` leads-to; `<>[]P` eventually-always;
`[]<>P` always-eventually. "Implies" names the weaker property that follows
from this one; a property is only kept if at least one mutant violates it
(see the report, mutation table).

Fairness used for liveness, and why:
- `WF(Step(p))` for every hook process p: an OS process that is runnable is
  eventually scheduled. No fairness on `Crash(p)` (a crash may or may not
  happen) and none on operator actions (the human may never approve).
- Serve module: `WF(Serve)` (the serve loop runs when it has a request),
  `WF(Tick)` (time passes), `WF(Timeout(i))` (the plugin's `setTimeout`
  fires once due). No fairness on `Send` (the agent may stop).

## Semgate.tla: hook processes, JSONL stores (ledger, tool history, feedback)

| id | kind | property (plain English) | implies | expected shortest counterexample for a plausible bug |
|---|---|---|---|---|
| L1 `LedgerOneLine` | `[]` | For every hook call that returned decision d to the host, the ledger has exactly one complete `host_response` line for that step, and its decision is d. It stays so after later writes. | at least one line; no duplicate line; no line with another decision | 5 steps: p1 seek, p2 seek, p1 write, p1 return, p2 write (p2 overwrites p1's returned record) |
| R1 `NoMisread` | `[]` | Every record the code's history reader returns equals, field by field, a record that some process wrote. A torn line is never read as a record. | the reader never invents a count or a pending decision | 5 steps with a "tolerant" reader: short record overwrites the head of a long one; the tail is read with fields from two records |
| H1 `LearnedSound` | `[]` | A learned allow for command c is only produced when humans really approved c after an ask at least `MinCount` times (ground truth at decision time). | a denied or rejected command is never promoted | ~14 steps with a mutant that counts rejected (error) runs, or a duplicated post event |
| H2 `CountNoOver` | `[]` | The count that the code reads for c is never larger than the number of real human approvals of c after an ask. | H1 for the counting part | ~10 steps: one approval, post event delivered twice |
| H3 `CountExactAtEnd` | `[]` (state predicate guarded by "all calls finished, no crash") | When every call has finished, the count equals the number of real approvals (nothing lost). | learning is not slower than designed | ~12 steps: two post-hook appends race; one executed record is overwritten |
| F1 `ApprovalScoped` | `[]` | Every human-approved allow is covered by the operator's approval: same command, same session, same project, before its expiry. (Replaces the first F1 `ApprovalOnce` "at most one use": owner decision (b) makes an approval reusable inside its scope until it expires. `ApprovalOnce` is kept as a canary: reuse inside the scope must be reachable.) | F2, F3, F4 | 3 steps with any key mutant |
| F2 `ApprovalExact` | `[]` | A human-approved allow is only for the exact command that was approved. | no approval widens to another command | 2 steps with a key mutant (tool only) |
| F3 `ApprovalSessionScoped` | `[]` | A human-approved allow only happens in the session AND the project to which the operator's approval was bound. | no cross-session or cross-project reuse; a legacy (unscoped) record never approves | grant for (s1, j1), p in s2 or j2 decides allow |
| F4 `ApprovalUnexpired` | `[]` | No human-approved allow after the approval expired. | approvals are short-lived | grant, expire, decide allow |
| FC `FailClosed` | `[]` | A hook call whose lock wait timed out before it returned never returned allow. | lock timeouts cannot open anything | pending append times out, host gets allow |
| `NoTornLine`, `NoLostRecord` | `[]` | No torn line in any store; every finished call has its host_response (ledger or spill). With locks these are properties; for "old" they are canaries K4, K5. | L1 | two unlocked appends at the same offset |
| T1 `Termination` | `<>[]` | Eventually every hook call has returned (or crashed) and stays so. | every call returns; no deadlock on a cross-process lock | lasso: p1 takes a lock file, crashes; p2 waits forever (lock-file mutant) |
| T2 `HistoryRecovers` | `[]<>` | The tool-history file is readable by the code's reader again and again (a bad moment does not last forever). The system here terminates, so over a finished run this means: the final history file is readable. | learning is not switched off for good by one bad write | ~9 steps: a torn line appears in tool_history.jsonl and stays |

## SemgateF6.tla: agent-created files (F6 eligibility, snapshots)

| id | kind | property | implies | expected shortest counterexample |
|---|---|---|---|---|
| E1 `EligibleSound` | `[]` | When eligibility is checked and says "restorable" for path x in session s: a `created` record of session s exists for x, x's current content equals the recorded hash, and a complete snapshot of that content exists in s's snapshot dir. | eligible => restorable at decision time | 4 steps with a mutant that skips the re-hash (trust the record), after a user edit |
| E2 `RmRestorable` | `[]` | When an `rm x` that was allowed because x was eligible actually runs, x's content at that moment has a complete snapshot. | no data loss through F6 | 6 steps: create, post, decide(eligible), user edit, rm runs (documented TOCTOU) |
| E3 `AgentContentOnly` | `[]` | If x is eligible, its current content is content an agent step wrote (not a user edit). | the model is never told "created by the agent" for user content | 5 steps: agent writes x, user edits x before the post hook runs, post hook records the user's content |
| E4 `EditedStaysIneligible` | `<>[]` (as `Edited ~> []~Eligible`) | Once the user changed x to content that no agent step wrote, x becomes and stays not eligible. | a user edit is never later treated as restorable | lasso: user edit, then a racing post hook records the edited content |
| E5 `SnapshotRaceNoLoss` | `[]` (at end) | When all post hooks have finished, every agent-created, unchanged file has a created record (nothing skipped by a snapshot race). | fewer extra asks | 6 steps: two post hooks, same content, same `<sha>.tmp` |

## SemgateServe.tla: `semgate serve --stdio` and the OpenCode plugin

| id | kind | property | implies | expected shortest counterexample |
|---|---|---|---|---|
| S1 `AnswerForRightId` | `[]` | The decision the plugin uses for request i is serve's answer for i, or "ask" (timeout), never the answer of another request. | an allow is never delivered to a different call | 6 steps with a FIFO-matching mutant: timeout on 1, then 1's late answer is taken by 2 |
| S2 `NoLateAllow` | `[]` | After the plugin resolved i with "ask" (timeout), i is never later resolved with allow. | a timed-out call cannot run | 4 steps with a mutant that keeps the waiter after timeout |
| S3 `EveryRequestResolved` | `~>` | Every sent request is eventually resolved (answer or timeout). | the agent loop never hangs on semgate | lasso with a mutant that has no timeout and a hung judge |
| S4 `ServeReturnsIdle` | `[]<>` | The serve loop returns to idle (no request in progress, queue empty) again and again. Arrivals come in bursts: the agent waits for all tool results of a turn before it sends the next burst. | a hung judgment is not permanent | lasso with a judge that can hang (no provider timeout) |
| S5 `NoTimeoutWithinBudget` | `[]` | No request is resolved by the plugin's timeout when every single judgment takes less than the timeout. | the timeout only fires for a slow judgment | burst of 3 with judgment 2 ticks, timeout 5 ticks: 3rd request waits 6 |

## Changes after the fixes (branch concurrency-fixes)

- L1 counts a host_response kept in a spill file (lock timeout) as recorded.
- H3 is guarded by "no lock wait timed out" (a timed-out record is kept out of
  the store on purpose, so the count may be lower; never higher: H2).
- Serve: `S4 ServeReturnsIdle` now needs serve's restart (an abandoned judgment
  keeps its worker thread; serve exits and the plugin starts a new one when only
  abandoned judgments remain). Fairness adds `WF(RestartServe)`.
- Weak vs strong: F1 is the conjunction of F2, F3, F4. Each approval mutant
  breaks F1 and exactly the weaker property it targets. Liveness is checked
  under weak fairness only (the weaker assumption); `SpecNoFair` shows it fails
  without fairness (the properties are not true by stuttering).

## Canaries (each must be VIOLATED by TLC; if one holds, the model is vacuous there)

| id | module | canary claim |
|---|---|---|
| K1 | Semgate | no approval is ever used (no `human` stage) |
| K2 | Semgate | no learned allow ever happens |
| K3 | Semgate | no hook call ever returns |
| K4 | Semgate | no torn line ever appears in any file (crt mode) |
| K5 | Semgate | no written record is ever lost (crt mode) |
| K6 | SemgateF6 | no path is ever eligible |
| K7 | SemgateF6 | no `rm` ever runs |
| K8 | SemgateServe | no request is ever answered by serve |
| K9 | SemgateServe | no request ever times out |
| K10 | Semgate | no lock wait ever times out (LockTimeouts on) |
| K11 | Semgate | no allow is ever turned into an ask by a lock timeout |
| K12 | SemgateServe | no judgment is ever abandoned |
| `ApprovalOnce` | Semgate | an approval is never used twice (reuse inside its scope is allowed by design) |
