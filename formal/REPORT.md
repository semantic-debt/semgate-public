# Concurrency analysis of semgate shared state (TLA+ + multi-process stress)

Date: 2026-09-23. Code at 5805459. No semgate code changed. Findings and repros only.

## Tools
| tool | version | sha256 |
|---|---|---|
| Temurin JDK win-x64 zip | 21.0.12.1+1 (2026-08-21) | f9d6e191ab098c0d416e7d588a24420a8621cd2f4720dab2459b8b7b2d2d8b4e (matches Adoptium API) |
| tla2tools.jar | TLC 2.19, v1.7.4 (2024-08-08) | 936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88 (size matches; no published digest) |

Both live in the session scratchpad `tla/` only.

## Inventory (threading.Lock orders threads inside one process only; each hook call is a separate process)
| # | state | write / read | interleaving |
|---|---|---|---|
| I1 | ledger.jsonl | `_append` ledger.py:41; readers `records` :171 (raises on bad line), `session_first_seen` :103, `session_on_task` :134 (skip bad lines) | parallel PreToolUse hooks, subagents, sessions, serve processes |
| I2 | tool_history.jsonl | history.py:51; `record_pending`, `record_executed` :88 (read then append); `records` :56 raises | pre/post hooks of parallel steps |
| I3 | feedback.jsonl | `record` feedback.py:53 (CLI); `latest` :69 skips bad lines, last wins | CLI write vs every hook read |
| I4 | agent_files/<session>.jsonl | agentfiles.py:106; `records` :113; `eligible` :222 | parallel post hooks; user edits |
| I5 | snapshots, `<sha>.tmp` | agentfiles.py:199-213 | same content from two processes -> same temp name |
| I6 | deny_streak.json | antigravity_hook.py:165-179 read-modify-write, no lock; parse error -> zeros, not rewritten | every enforce-mode hook |
| I7 | profiles state_file | profiles.py:113 | cache, safe |
| I8 | serve stdio | serve.py:48 one request at a time; plugin 20 s timer per request from send time | parallel calls queue |

## Properties (TLC; "code" = current code, "fixed" = candidate design used as mutation baseline)
Model: 3 processes, 2 sessions, 2 commands for invariants; liveness with 2 processes. Trace = states in shortest counterexample.

| id | kind | code | fixed | mutants caught (trace) |
|---|---|---|---|---|
| L1 LedgerOneLine | [] | violated (11) | holds | nolock, raise_nolock, tolerant (11) |
| R1 NoMisread | [] | holds* | holds | tolerant (15) |
| H1 LearnedSound | [] | holds | holds | count_error (29), post_twice (20) |
| H2 CountNoOver | [] | holds | holds | count_error (14), post_twice (19), tolerant (15) |
| H3 CountExactAtEnd | [] | violated (21) | holds | 5 mutants (21-58) |
| F1 ApprovalOnce | [] | violated (5) | holds | reuse (5), consume_race (5), key_tool (4) |
| F2 ApprovalExact | [] | holds | holds | key_tool (4) |
| F3 ApprovalSessionScoped | [] | violated (4) | holds | key_nosession (6), key_tool (4) |
| T1 Termination | <>[] | holds (2p) | holds, with crashes | lockfile_crash lasso (8) |
| T2 HistoryRecovers | []<> | violated (lasso 17) | holds | raise_nolock (17) |
| E1 EligibleSound | [] | holds | holds | trust (10), nosnap (8), shared (8) |
| E2 RmRestorable | [] | violated (11) | violated (10): inherent TOCTOU | all |
| E3 AgentContentOnly | [] | violated (12) | holds | postcode (10), trust (8) |
| E4 EditedStaysIneligible | <>[] | violated (lasso 20) | holds | postcode (16), trust (15) |
| E5 SnapshotRaceNoLoss | [] | violated (16) | holds | tmp_collide (16) |
| S1 AnswerForRightId | [] | holds | holds | fifo (9) |
| S2 NoLateAllow | [] | holds | holds | keepwaiter (14) |
| S3 EveryRequestResolved | ~> | holds | holds | notimeout_hang (6) |
| S4 ServeReturnsIdle | []<> | violated (lasso 40) | holds | fifo, nocancel_hang, notimeout_hang, keepwaiter |
| S5 NoTimeoutWithinBudget | [] | violated (12) | holds | one_worker, nocancel, keepwaiter, fifo |

\* R1 relies on abstraction A4 (a torn line never parses as JSON); stress data: 0 phantom records in 176,000.
Canaries K1-K9 all violated as required (reachability shown).

## Stress tests (real processes, temp HOME/USERPROFILE)
| test | result |
|---|---|
| real claude_hook, 8 at once x 40 rounds | 10.9 % of returned decisions have no host_response line; 14 judgment + 17 pending lines lost; 12 torn lines; deny-streak updates lost 44 % |
| same, 3 at once | 5.8 % no host_response; 20.8 % pending lost; deny-streak lost 73.8 % |
| store APIs, 3 / 8 processes | ledger 12.5/16.5 %, history 12.7/18.2 %, feedback 13.7/17.7 %, agentfiles 5.5/12.0 % lost; 0 phantom |
| control, 8 processes | open("a") 13.9 % lost; msvcrt.locking 0 %; FILE_APPEND_DATA handle 0 % |
| learned allow pre+post | 95-97 % of post joins raise; history unreadable 10/10 rounds |
| deny_streak | unparseable at end of 20/20 rounds, never repaired |
| F6 snapshots, same content | 13.3 % skipped (temp collision); 46.7 % unchanged agent files not eligible; unsafe 0/570 |
| session drift, 8 writers | 64.5 % judgment lines lost; drift ask missed (allow) in 28 % of rounds |

## Findings (unsafe first)
- **U1 (unsafe, deterministic): approvals are never consumed and have no scope.** `semgate feedback allow "rm -rf dist"` allows that exact text forever, in any session/project. Repro `repro/feedback_reuse.py` (verified by the orchestrator 2026-09-23: allow, allow, allow incl. sess-B/projB). Fix: one-shot grant keyed by tool+command+session+cwd with expiry, consumed atomically (lock, or one file per grant removed by the winner).
- **U2 (unsafe): user content recorded as "created by the agent".** `record_post` (agentfiles.py:196) hashes at post-hook time, not the content the tool wrote; an edit before the post hook is trusted. Repro `repro/f6_post_window.py`. Fix: pre hook records expected hash from the tool input; post hook records only on match.
- **U3 (unsafe for experimental session-drift policies): lost ledger lines can remove the drift ask.** Repro `repro/stress_drift.py` (28 % allow instead of ask). Fix: locked appends; incomplete input -> ask.
- **U4 (known): E2 TOCTOU** between check and rm; inherent to a pre-hook.
- **S1 (safe): Windows append race loses records in all JSONL stores** (seek-to-end then write). Fix: cross-process lock per append (msvcrt.locking / LockFileEx, fcntl.flock); no lock file without stale-lock recovery.
- **S2 (safe, permanent): one torn line in tool_history.jsonl disables learned allow and executed recording for good.** Fix: skip bad lines, lock appends, warn. Not a "tolerant" partial-line reader (overcounts, unsafe).
- **S3 (safe, permanent): deny_streak.json** loses updates; once corrupt, escalation stays off. Fix: lock + temp file + os.replace; rewrite on parse error.
- **S4 (safe): F6 snapshot temp-name collision** -> extra asks. Fix: per-process temp name; existing snapshot with right hash = success.
- **S5 (safe, availability): serve is one-at-a-time.** Calls 4-5 of a burst time out to ask; a hung model call blocks serve forever; serve writes no host_response. Fix: concurrent judging with cancel on timeout; restart after repeated timeouts; write host_response.

Checked and holding: learned allow never promotes denied/rejected commands (H1/H2); torn lines never misread (R1); answers go to the right id (S1); a timeout never becomes allow (S2).

## Limits
Records 1-2 units; one write call atomic; reader reads whole file in one step; torn-line parse backed by stress data; decision reduced to base -> learned -> human; gates and model call not modelled; symmetry only for invariants; liveness with 2 processes; POSIX append atomicity not measured (losses expected Windows-specific); host re-delivery of PostToolUse not verified; the "fixed" design is a candidate, not implemented.

## Files
PROPERTIES.md, Semgate.tla, MC_Semgate.tla, SemgateF6.tla, MC_SemgateF6.tla, SemgateServe.tla, run_tlc*.py, run_all_tlc.sh, trace_summary.py, cfg/, results/tlc/*.out, results/tlc/summary.json (after the fixes; before: summary_5805459.json), repro/*.py, results/*.txt (before), results/after/*.txt (after).

## After the fixes (branch concurrency-fixes, 2026-09-23)

The tables above describe code at 5805459. This section is the new code.

### What changed in the code
| finding | fix | where |
|---|---|---|
| S1, U3 | every JSONL append takes an OS lock on `<store>.lock` (msvcrt.locking / flock; released at process exit), then one `O_APPEND` write; wait bounded to 5 s (`SEMGATE_LOCK_TIMEOUT_S`); on timeout the record goes to a per-process spill file `<store>.lock-timeout.<pid>.<rand>.jsonl` and the decision fails closed (allow -> ask) | `semgate/filelock.py`; callers: ledger.py, history.py, feedback.py, agentfiles.py, antigravity_hook.py (`_store_failed`, `record_host_response`), judge.py (`fail_closed`) |
| U1 | approvals bound to exact command + session + project + expiry (default 4 h, `feedback.approval_ttl_hours`, also a cap on the hook side); legacy allows ignored; CLI binds to the most recent asked/blocked session of the project; feedback read under the lock, unreadable -> allow becomes ask | `semgate/feedback.py`, `semgate/cli.py` `_cmd_feedback`, judge.py `human_override` |
| U2 | pre hook records the expected sha256 from the tool input (Write content, the text and its CRLF form); post hook records `created` only on a match, else `not_recorded`; shell writes never recorded | agentfiles.py `record_pre`, `record_post`, `expected_hashes`; antigravity_hook.py `action_expected_hashes` |
| S2 | readers skip malformed lines (one `store_warning` record per line); no tolerant parsing | filelock.py `read_jsonl`, `warn_malformed`; `records()` of ledger, history, agentfiles |
| S3 | deny_streak.json: lock + unique temp file + os.replace; unparseable file restarts from zero | antigravity_hook.py `_deny_streak_update` |
| S4 | snapshot temp name unique per process; an existing snapshot with the right hash is success | agentfiles.py `_snapshot` |
| S5 | serve: worker pool (default 4), per-request deadline (timeout_ms - 1.5 s) answered ask, a queued request past its deadline is never judged, a running one is abandoned, restart when only abandoned judgments remain; host_response per request; the plugin restarts serve after 3 timeouts in a row | `semgate/serve.py`, `semgate/assets/opencode_semgate.js` |
| U3 | session-drift window read under the lock; lock timeout, malformed line since the session's first line, or a spill file naming the session -> allow becomes ask | ledger.py `session_on_task`, judge.py |

Also found and fixed: `semgate feedback allow` of a command the model had
allowed but the host blocked (bash outside `auto_allow_tools`) had no effect;
judge.py now marks it `human_approved` (inside the approval's scope).

### TLC after the fixes ("code" = new code, "old" = 5805459)
Model changes: Semgate.tla adds projects, the expiry clock, legacy records,
lock timeouts with spill files (`AcqTimeout`) and the feedback read under the
lock. SemgateF6 "code" = expected-hash post hook + unique temp names.
SemgateServe adds abandoned judgments (`aband`) and `RestartServe`.

| id | code | old | mutants caught (shortest trace) |
|---|---|---|---|
| L1 LedgerOneLine | holds (also crashes; lock timeouts; timeouts+crashes 2p) | violated (11) | nolock (11), timeout_drop (6) |
| R1 NoMisread | holds (also timeouts) | - | tolerant (15) |
| H1 LearnedSound | holds | - | count_error (30), post_twice (21) |
| H2 CountNoOver | holds | - | count_error (15), post_twice (19), tolerant (15) |
| H3 CountExactAtEnd | holds | violated (21) | nolock (25), raise_nolock (21), count_error (43), post_twice (58) |
| NoTornLine / NoLostRecord | hold | violated (12 / 14) | nolock (12 / 14) |
| FC FailClosed (new) | holds (timeouts; timeouts+crashes 2p) | - | timeout_open (8) |
| F1 ApprovalScoped (new, strong) | holds (2p) | violated (4) | every key mutant (8-10) |
| F2 ApprovalExact | holds | violated (4) | key_tool (8), legacy_ok (8) |
| F3 ApprovalSessionScoped | holds | violated (4) | key_tool, key_nosession, key_noproject, legacy_ok (8-9) |
| F4 ApprovalUnexpired (new) | holds | violated (5) | noexpiry (9), key_tool (9) |
| T1 Termination (2p, WF) | holds (also crash, timeouts, timeouts+crash) | holds | lockfile_crash (deadlock, 6) |
| T2 HistoryRecovers | holds (2p lasso; 3p end state) | violated (17 / 21) | raise_nolock (17 / 21) |
| E1 EligibleSound | holds | holds | trust (8), nosnap (8), shared (7) |
| E2 RmRestorable | violated (10): inherent TOCTOU (U4) | violated | all |
| E3 AgentContentOnly | holds | violated (10) | postcode (9), trust (8) |
| E4 EditedStaysIneligible | holds | violated (lasso 20) | postcode (16), trust (16) |
| E5 SnapshotRaceNoLoss | holds | violated (16) | tmp_collide (16) |
| S1 AnswerForRightId | holds (also hangs) | - | fifo (10) |
| S2 NoLateAllow | holds (also hangs) | - | keepwaiter (26) |
| S3 EveryRequestResolved | holds (also hangs) | - | notimeout_hang (6) |
| S4 ServeReturnsIdle | holds (also hangs) | violated (41) | fifo, nocancel_hang, norestart_hang, notimeout_hang, one_worker |
| S5 NoTimeoutWithinBudget | holds (no hang; a hang must time out) | violated (12) | one_worker (12), fifo, keepwaiter, nocancel_hang, norestart_hang |

Canaries all violated: K1 (8), K2 (30), K3 (10), K4/K5 on "old" (12/14), K6
(8), K7 (8), K8 (9), K9 (11), K10 (4), K11 (23), K12 (11). The old F1
`ApprovalOnce` is violated (4): reuse inside the scope is reachable, as owner
decision (b) wants.

Checks on the checks. Weak vs strong: F1 is the conjunction of F2-F4; each
approval mutant breaks F1 plus exactly the weaker properties it targets
(noexpiry: F4; nosession / noproject: F3; key_tool: F2, F3, F4; legacy_ok:
F2, F3). Fairness: liveness is checked under weak fairness only; without
fairness (`SpecNoFair`) Termination and EveryRequestResolved fail, so they
are not true by stuttering. Depth of the complete search: 45 (stores, 3
processes), 32 (approvals, 2 processes), 31 (liveness), 15 (F6), 30-50
(serve).

Size limits: approval properties run with 2 processes (3 processes with 2
sessions x 2 projects x 2 commands did not finish in 1 h); lock timeouts with
crashes run with 2 processes; mutants and "old" run only the properties they
target (a "holds" run on an unlocked configuration is 20M+ states and proves
nothing new). 180 jobs.

### Stress tests after the fixes (Windows 11, real processes, temp HOME)
| test | before | after |
|---|---|---|
| real claude_hook, 8 at once x 40 rounds | 10.9 % no host_response; 14 judgment + 17 pending lost; 12 torn; deny streak 44 % lost | 0/320 no host_response; 320/320 judgments; 0 pending lost; 0 torn; deny streak 160/160 |
| same, 3 at once | 5.8 %; 20.8 % pending lost; streak 73.8 % lost | 0/120; 120/120; 0; 80/80 |
| store APIs, 3 / 8 processes (ledger, history, feedback, agentfiles) | 5.5-18.2 % lost | 0 lost of 12,000 / 32,000 per store; 0 torn; 0 duplicates; 0 phantom; reader raised 0/20 |
| deny_streak, 8 / 3 processes | 100 % lost; corrupt 20/20 | 0/16,000 and 0/1,200 lost; 0 corrupt |
| learned allow pre+post, 8 / 3 | 95-97 % of joins raise; history unreadable 10/10 | 0 raises; undercount 0/3,840 and 0/1,440; overcount 0; denied counted 0 |
| F6 snapshots, same content, 8 / 3 | 13.3 % skipped; 46.7 % not eligible | 0/240 and 0/90 skipped; 0 not eligible; unsafe 0; leftover .tmp 0 |
| F6 post window (user edit before the post hook) | C = allow | C = ask (same as B) |
| session drift, 8 writers x 200 rounds | 64.5 % lines lost; drift ask missed 28 % | 0/800 lost; ask 200/200 |
| approvals, feedback_reuse (10 steps) | allowed in another session and project, forever | in scope 2/2; out of scope 0 (other session, other project, variation, expired, legacy) |
| approvals under load (new: 8 x 40 decisions + 200 concurrent approval writes) | - | in scope 40/40; elsewhere 0/280; 203/203 feedback records; 320/320 host_response |
| serve burst, 6 s per model call, 5 / 8 requests | calls 4-5 past 20 s | 0/5 and 0/8 past 20 s (6 s, then 12 s) |
| serve, 2 hung model calls in a burst of 6 | serve blocked for good | hung ones ask at 18.5 s (timeout=true); others allow at 1-2 s; serve restarts (exit 75) |
| cost | - | ledger append 8 processes x 200 x 20 rounds: 27.7 s (unlocked old code: 11.8 s); claude_hook 8x40: 14.6 s (old: 18 s); one deny-streak update about 16 ms |

A first version locked a byte of the store file itself. Opening a
just-written file with read access costs about 9 ms on this machine (most
likely a virus scan), and appends were about 60x slower (ledger 8x: 732 s).
The lock now lives on the never-modified `.lock` sidecar.

### Behaviour changes the owner must know
- Approvals recorded before this branch (no session, no project) are no longer
  honoured. Re-approve with `semgate feedback allow "<cmd>"` from the project
  directory (`--config` for non-default store paths).
- An approval expires after 4 h and applies to one session and one project; it
  can be reused inside that scope.
- `semgate feedback allow` refuses (exit 2) when the ledger shows no
  asked/blocked step with exactly that command text in the project.
- F6: only a file written by a file tool that carries the content counts as
  agent-created; `rm` of a file the agent made with a shell command asks.
- New files next to each store: `<store>.lock` (empty) and, only after a lock
  timeout, `<store>.lock-timeout.*.jsonl`.
- serve answers out of order (matched by id) and may exit with code 75 to
  restart.

### Still open
- U4 / E2: TOCTOU between the check and the `rm` (inherent to a pre-hook).
- The hot stores do not repair a line torn by a writer that died in the middle
  of one write (the feedback store does); the record glued onto it is skipped
  by every reader (safe side; session drift asks).
- Host re-delivery of PostToolUse is still assumed not to happen (mutant
  post_twice shows it would overcount).
- POSIX locking (flock) is covered by the unit tests in CI (ubuntu), not by the
  stress runs (Windows only).
