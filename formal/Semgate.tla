------------------------------- MODULE Semgate -------------------------------
(***************************************************************************)
(* Hook processes that share semgate's JSONL stores.                       *)
(*                                                                         *)
(* One process p = one PreToolUse hook call (python -m semgate.claude_hook *)
(* or semgate.antigravity_hook), then the host acting on the answer, then  *)
(* one PostToolUse hook call for the same step (antigravity_post_hook).    *)
(*                                                                         *)
(* Code mapped (branch concurrency-fixes; "old" = commit 5805459):         *)
(*   Decide    judge.py learned(), human_override().                       *)
(*             history read = ToolHistory.count_executed_after_ask; the    *)
(*             reader skips malformed lines (filelock.read_jsonl), old:    *)
(*             raised on any bad line.                                     *)
(*             feedback read = FeedbackStore.latest, read UNDER THE LOCK   *)
(*             (filelock.read_jsonl_locked); a lock timeout -> the store   *)
(*             is "unreadable" -> an allow becomes an ask (judge.py        *)
(*             fail_closed). An approval applies only to the exact         *)
(*             command, the same session, the same project, before its     *)
(*             expiry; legacy (unscoped) records are ignored.              *)
(*   appends   pending  antigravity_hook.run_core record_pending           *)
(*             hr       record_host_response -> Ledger._append             *)
(*             executed antigravity_post_hook record_executed              *)
(*   append    filelock.append_record: take the OS lock on <store>.lock    *)
(*             (msvcrt.locking / flock; released by the OS when the        *)
(*             process ends), then one O_APPEND write (seek to the end,    *)
(*             write), unlock. On a lock timeout the record                *)
(*             goes to a spill file only this process writes, and a        *)
(*             record written before the hook returned turns an allow      *)
(*             into an ask (run_core _store_failed, record_host_response). *)
(*                                                                         *)
(* Abstractions (see the report, "model limits"):                          *)
(*  A1 A record is 1 or 2 "units" (slices of bytes); the last unit ends    *)
(*     with the newline. Lengths differ by kind so that a shorter record   *)
(*     can overwrite the head of a longer one and leave a torn tail.       *)
(*  A2 One WriteFile call is atomic. A real WriteFile of a large buffer    *)
(*     may be split; that only adds interleavings.                         *)
(*  A3 A reader reads a whole file in one step.                            *)
(*  A4 A torn line never parses as JSON in the real code: json.dumps       *)
(*     output cut anywhere, or a tail of it, or a prefix followed by       *)
(*     another record, is not one JSON object (the stress tests found 0    *)
(*     phantom records). The "tolerant" reader exists only as a mutant.    *)
(*  A5 The operator's `semgate feedback allow` append is one atomic step.  *)
(*  A6 One global lock stands for "a cross-process lock around each        *)
(*     append"; per-file locks give the same results in this model.        *)
(*  A7 Decisions are reduced to Base[c] (what rules + the model say),      *)
(*     then learned allow, then the human override. Gates, grants, the     *)
(*     model call and the enforcement mapping are outside this model.      *)
(*  A8 The judgment record (judge.py finish) is not modelled; host_response*)
(*     lengths differ by decision instead (a deny/ask reason is longer).   *)
(*  A9 Steps that touch no shared state are merged into the next step that *)
(*     does (choosing the event, preparing a record). Reordering such      *)
(*     local steps cannot change what other processes observe.             *)
(*  A10 Record ids are <<process, n>> (n = which append of that process),  *)
(*     so an id does not depend on the order in which appends start.       *)
(*  A11 The host acts and the post hook reads history in one step.         *)
(*  A12 Time: one approval clock. `Expire` = the approval's expiry passed  *)
(*     (the CLI's expires_at, or the hook's approval_ttl_hours cap).      *)
(*  A13 A lock timeout is a nondeterministic choice, enabled only while    *)
(*     another process holds the lock.                                     *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Procs,          \* hook processes (model values)
    Sessions,       \* host session ids
    Projects,       \* project roots
    Commands,       \* exact commands
    Base,           \* [Commands -> {"ask","deny"}]: decision before learning / feedback
    MinCount,       \* auto_allow_learned.min_count (code: max(2, ...))
    GrantCmds,      \* commands the operator approves (once each)
    GrantSess,      \* session the CLI binds the approval to
    GrantProj,      \* project the CLI binds the approval to
    AppendMode,     \* "crt" (seek to end, then write) | "atomic" (append that is atomic)
    LockMode,       \* "none" (old) | "oslock" (code: released at exit) | "lockfile" (O_EXCL, stays after a crash)
    LockTimeouts,   \* TRUE: a lock wait may time out (code: bounded wait)
    TimeoutAction,  \* "closed" (code: spill the record, allow -> ask) | "open" (mutant: decision unchanged)
                    \*   | "drop" (mutant: allow -> ask, the record is dropped)
    HistReader,     \* "skip" (code) | "raise" (old) | "tolerant" (mutant: reads torn lines)
    CountMode,      \* "code" | "ignore_error" (mutant)
    PostDelivery,   \* "once" (assumed) | "twice" (mutant: host delivers PostToolUse twice)
    KeyMode,        \* approval match: "scoped" (code: cmd+session+project, no legacy) | "exact" (old: cmd only)
                    \*   mutants: "tool_only" | "nosession" | "noproject" | "legacy_ok"
    ExpiryMode,     \* "check" (code) | "ignore" (mutant)
    Legacy,         \* TRUE: the feedback file may hold a legacy (unscoped) approval
    Crashes         \* TRUE: a process may die at any step

Files == {"ledger", "history", "feedback"}
Decs  == {"allow", "ask", "deny"}
\* append numbers per process
K_PENDING == 2
K_HR == 3
K_EXEC == 4
K_EXEC2 == 5
OpKey == <<"op", 1>>
OpLegKey == <<"op", 2>>
Keys == (Procs \X (2..5)) \cup {OpKey, OpLegKey}

VARIABLES
    files,      \* [Files -> Seq(unit)], unit = [id |-> key, part |-> n, last |-> BOOLEAN]
    recs,       \* [Keys -> record content]
    pc,         \* "idle" | "app" | "returned" | "post2" | "done" | "crashed"
    sub,        \* inside an append: "acq" | "seek" | "write" | "rel" | "none"
    queue,      \* appends still to do: Seq(<<file, key>>)
    after,      \* pc when the queue is empty
    wpos,       \* end offset read by the seek
    sess, proj, cmd, dec, stage, learnOk,
    ran,        \* "none" | "yes" | "no"
    approved,   \* [Commands -> Nat]: ground truth, human approved after an ask and it ran
    granted,    \* [Commands -> Nat]: operator approvals given (scoped)
    lock,       \* "free" or the holder
    expired,    \* the approval clock passed the expiry
    expAt,      \* [Procs -> BOOLEAN]: expired when p decided
    tout,       \* [Procs -> 0..2]: 0 no lock wait of p timed out; 1 one timed out before p
                \* returned (the decision could still change); 2 only after it returned
    spill       \* Seq of records kept in per-process spill files

vars == <<files, recs, pc, sub, queue, after, wpos, sess, proj, cmd, dec, stage, learnOk, ran, approved, granted,
          lock, expired, expAt, tout, spill>>

NoRec == [kind |-> "none", step |-> "none", sess |-> "none", proj |-> "none", cmd |-> "none", dec |-> "none",
          err |-> FALSE, legacy |-> FALSE]

RLen(r) == CASE r.kind = "hr"       -> (IF r.dec = "allow" THEN 1 ELSE 2)
          []   r.kind = "executed" -> 2
          []   OTHER               -> 1

Units(k) == [n \in 1..RLen(recs[k]) |-> [id |-> k, part |-> n - 1, last |-> n = RLen(recs[k])]]

Max(a, b) == IF a > b THEN a ELSE b

Overwrite(f, pos, us) ==
    [i \in 1..Max(Len(f), pos + Len(us)) |->
        IF i > pos /\ i <= pos + Len(us) THEN us[i - pos] ELSE f[i]]

\* ---------- reading a JSONL file ----------
RECURSIVE LinesFrom(_, _, _)
LinesFrom(f, i, acc) ==
    IF i > Len(f) THEN (IF acc = <<>> THEN <<>> ELSE <<acc>>)
    ELSE LET acc2 == Append(acc, f[i]) IN
         IF f[i].last THEN <<acc2>> \o LinesFrom(f, i + 1, <<>>)
         ELSE LinesFrom(f, i + 1, acc2)
Lines(f) == LinesFrom(f, 1, <<>>)

IsComplete(line) ==
    LET id == line[1].id IN
        /\ Len(line) = RLen(recs[id])
        /\ \A n \in 1..Len(line) : line[n].id = id /\ line[n].part = n - 1 /\ line[n].last = (n = Len(line))

\* Mutant reader: a torn line is read with its head fields from the first
\* unit and decision / error from the last unit.
Merged(line) == [recs[line[1].id] EXCEPT !.dec = recs[line[Len(line)].id].dec,
                                         !.err = recs[line[Len(line)].id].err]

\* Each parsed record carries the key of its first unit, so that a reader
\* result can be compared with what was written under that key.
RECURSIVE Parse(_, _, _)
Parse(ls, i, mode) ==
    IF i > Len(ls) THEN <<>>
    ELSE (IF IsComplete(ls[i]) THEN <<recs[ls[i][1].id] @@ [key |-> ls[i][1].id]>>
          ELSE IF mode = "tolerant" THEN <<Merged(ls[i]) @@ [key |-> ls[i][1].id]>> ELSE <<>>)
         \o Parse(ls, i + 1, mode)

HasTorn(f) == \E i \in 1..Len(Lines(files[f])) : ~IsComplete(Lines(files[f])[i])

\* mode "raise" (old code) gives ok = FALSE when any line is bad; "skip" (code) drops bad lines.
Read(f, mode) == IF mode = "raise" /\ HasTorn(f) THEN [ok |-> FALSE, rs |-> <<>>]
                 ELSE [ok |-> TRUE, rs |-> Parse(Lines(files[f]), 1, mode)]

Range(s) == {s[i] : i \in 1..Len(s)}

\* ---------- decisions ----------
Count(c) ==
    LET rd == Read("history", HistReader)
        rs == rd.rs IN
    IF ~rd.ok THEN 0
    ELSE Cardinality({i \in 1..Len(rs) :
            /\ rs[i].kind = "executed" /\ rs[i].cmd = c /\ rs[i].dec = "ask"
            /\ (CountMode = "ignore_error" \/ ~rs[i].err)})

Unexpired == ExpiryMode = "ignore" \/ ~expired

\* FeedbackStore._applies for an allow record r, for command c in session s, project j.
KeyMatch(r, c, s, j) ==
    CASE KeyMode = "tool_only" -> TRUE
    []   KeyMode = "exact"     -> r.cmd = c
    []   KeyMode = "scoped"    -> ~r.legacy /\ r.cmd = c /\ r.sess = s /\ r.proj = j /\ Unexpired
    []   KeyMode = "nosession" -> ~r.legacy /\ r.cmd = c /\ r.proj = j /\ Unexpired
    []   KeyMode = "noproject" -> ~r.legacy /\ r.cmd = c /\ r.sess = s /\ Unexpired
    []   KeyMode = "legacy_ok" -> r.cmd = c /\ (r.legacy \/ (r.sess = s /\ r.proj = j)) /\ Unexpired

\* FeedbackStore.latest: the newest applicable record wins.
Latest(c, s, j) ==
    LET rs == Read("feedback", "skip").rs
        fb == {i \in 1..Len(rs) : rs[i].kind = "fb" /\ KeyMatch(rs[i], c, s, j)}
    IN IF fb = {} THEN "none"
       ELSE rs[CHOOSE i \in fb : \A k \in fb : k <= i].dec

LastPending(p) ==
    LET rd == Read("history", HistReader)
        rs == rd.rs IN
    IF ~rd.ok THEN [st |-> "ERR", r |-> NoRec]
    ELSE LET ps == {i \in 1..Len(rs) : rs[i].kind = "pending" /\ rs[i].step = p} IN
         IF ps = {} THEN [st |-> "none", r |-> NoRec]
         ELSE [st |-> "found", r |-> rs[CHOOSE i \in ps : \A k \in ps : k <= i]]

FirstSub == IF LockMode = "none" THEN "seek" ELSE "acq"

\* ---------- appends ----------
\* Finish the head append of p: start the next one, or leave the "app" state.
Advance(p) ==
    /\ queue' = [queue EXCEPT ![p] = Tail(@)]
    /\ IF Len(queue[p]) = 1
       THEN pc' = [pc EXCEPT ![p] = after[p]] /\ sub' = [sub EXCEPT ![p] = "none"]
       ELSE pc' = pc /\ sub' = [sub EXCEPT ![p] = FirstSub]

LocalVars == <<sess, proj, cmd, stage, learnOk, ran, approved, granted, expired, expAt>>

Acquire(p) ==
    /\ pc[p] = "app" /\ sub[p] = "acq" /\ lock = "free"
    /\ lock' = p /\ sub' = [sub EXCEPT ![p] = "seek"]
    /\ UNCHANGED <<files, recs, pc, queue, after, wpos, dec, tout, spill>> /\ UNCHANGED LocalVars

\* filelock.append_record on LockTimeout: the record goes to this process's
\* spill file; before the hook returned, an allow becomes an ask, and the
\* host_response still to be written carries the final decision.
AcqTimeout(p) ==
    /\ LockTimeouts
    /\ pc[p] = "app" /\ sub[p] = "acq" /\ lock # "free" /\ lock # p
    /\ LET k == Head(queue[p])[2]
           pre == after[p] = "returned"
           nd == IF TimeoutAction # "open" /\ pre /\ dec[p] = "allow" THEN "ask" ELSE dec[p]
           recs1 == IF pre THEN [recs EXCEPT ![<<p, K_HR>>] = [@ EXCEPT !.dec = nd]] ELSE recs
       IN /\ dec' = [dec EXCEPT ![p] = nd]
          /\ recs' = recs1
          /\ spill' = IF TimeoutAction = "drop" THEN spill ELSE Append(spill, recs1[k] @@ [key |-> k])
    /\ tout' = [tout EXCEPT ![p] = IF after[p] = "returned" \/ @ = 1 THEN 1 ELSE 2]
    /\ Advance(p)
    /\ UNCHANGED <<files, after, wpos, lock>> /\ UNCHANGED LocalVars

Seek(p) ==
    /\ pc[p] = "app" /\ sub[p] = "seek"
    /\ LET f == Head(queue[p])[1]
           k == Head(queue[p])[2] IN
       IF AppendMode = "atomic"
       THEN /\ files' = [files EXCEPT ![f] = @ \o Units(k)]
            /\ IF LockMode = "none" THEN Advance(p)
               ELSE sub' = [sub EXCEPT ![p] = "rel"] /\ UNCHANGED <<pc, queue>>
            /\ UNCHANGED wpos
       ELSE /\ wpos' = [wpos EXCEPT ![p] = Len(files[f])]
            /\ sub' = [sub EXCEPT ![p] = "write"]
            /\ UNCHANGED <<files, pc, queue>>
    /\ UNCHANGED <<recs, after, dec, lock, tout, spill>> /\ UNCHANGED LocalVars

Write(p) ==
    /\ pc[p] = "app" /\ sub[p] = "write"
    /\ LET f == Head(queue[p])[1]
           k == Head(queue[p])[2] IN
         files' = [files EXCEPT ![f] = Overwrite(@, wpos[p], Units(k))]
    /\ wpos' = [wpos EXCEPT ![p] = 0]
    /\ IF LockMode = "none" THEN Advance(p)
       ELSE sub' = [sub EXCEPT ![p] = "rel"] /\ UNCHANGED <<pc, queue>>
    /\ UNCHANGED <<recs, after, dec, lock, tout, spill>> /\ UNCHANGED LocalVars

Release(p) ==
    /\ pc[p] = "app" /\ sub[p] = "rel"
    /\ lock' = "free"
    /\ Advance(p)
    /\ UNCHANGED <<files, recs, after, wpos, dec, tout, spill>> /\ UNCHANGED LocalVars

\* ---------- hook call ----------
\* The feedback store is read under the lock (code). Without a lock the read
\* waits; with LockTimeouts it may time out, and the store is "unreadable".
CanRead == LockMode = "none" \/ lock = "free"

\* PreToolUse: choose the event, decide, then append pending (history) and
\* host_response (ledger).
Decide(p) ==
    /\ pc[p] = "idle"
    /\ CanRead \/ LockTimeouts
    /\ \E s \in Sessions, j \in Projects, c \in Commands :
       LET rto == ~CanRead
           learned == Base[c] = "ask" /\ Count(c) >= MinCount
           d1 == IF learned THEN "allow" ELSE Base[c]
           \* mutant "open": an unreadable store counts as "no human decision" (old judge.py)
           h == IF rto THEN (IF TimeoutAction = "open" THEN "none" ELSE "unreadable") ELSE Latest(c, s, j)
           d == CASE h = "unreadable" -> (IF d1 = "allow" THEN "ask" ELSE d1)
                []   h = "deny" /\ d1 # "deny" -> "deny"
                []   h = "allow" /\ ~learned -> "allow"
                []   OTHER -> d1
           st == CASE h = "unreadable" /\ d1 = "allow" -> "failclosed"
                 []   h = "deny" /\ d1 # "deny" -> "hblock"
                 []   h = "allow" /\ ~learned -> "human"
                 []   learned -> "learned"
                 []   OTHER -> "base"
       IN /\ sess' = [sess EXCEPT ![p] = s] /\ proj' = [proj EXCEPT ![p] = j] /\ cmd' = [cmd EXCEPT ![p] = c]
          /\ dec' = [dec EXCEPT ![p] = d]
          /\ stage' = [stage EXCEPT ![p] = st]
          /\ learnOk' = [learnOk EXCEPT ![p] = learned /\ approved[c] >= MinCount]
          /\ tout' = [tout EXCEPT ![p] = IF rto THEN 1 ELSE 0]
          /\ recs' = [recs EXCEPT ![<<p, K_PENDING>>] = [NoRec EXCEPT !.kind = "pending", !.step = p, !.sess = s, !.proj = j, !.cmd = c, !.dec = d],
                                  ![<<p, K_HR>>] = [NoRec EXCEPT !.kind = "hr", !.step = p, !.sess = s, !.proj = j, !.cmd = c, !.dec = d]]
          /\ queue' = [queue EXCEPT ![p] = <<<<"history", <<p, K_PENDING>>>>, <<"ledger", <<p, K_HR>>>>>>]
    /\ expAt' = [expAt EXCEPT ![p] = expired]
    /\ pc' = [pc EXCEPT ![p] = "app"] /\ sub' = [sub EXCEPT ![p] = FirstSub]
    /\ after' = [after EXCEPT ![p] = "returned"]
    /\ UNCHANGED <<files, wpos, ran, approved, granted, lock, expired, spill>>

\* The PostToolUse hook reads the history and joins on the step
\* (record_executed). ran' is the value set by the same step.
PostCall(p, key, again) ==
    LET pend == LastPending(p) IN
    IF pend.st = "ERR"
    THEN /\ pc' = [pc EXCEPT ![p] = again]                 \* exception swallowed (old reader only)
         /\ UNCHANGED <<recs, queue, sub, after>>
    ELSE /\ recs' = [recs EXCEPT ![<<p, key>>] =
                       IF pend.st = "none"
                       THEN [NoRec EXCEPT !.kind = "unmatched", !.step = p, !.sess = sess[p]]
                       ELSE [NoRec EXCEPT !.kind = "executed", !.step = p, !.sess = pend.r.sess,
                                          !.cmd = pend.r.cmd, !.dec = pend.r.dec, !.err = (ran'[p] = "no")]]
         /\ queue' = [queue EXCEPT ![p] = <<<<"history", <<p, key>>>>>>]
         /\ pc' = [pc EXCEPT ![p] = "app"] /\ sub' = [sub EXCEPT ![p] = FirstSub]
         /\ after' = [after EXCEPT ![p] = again]

\* The decision reached the host: it runs (allow), a human approves or
\* rejects (ask), or it is blocked (deny). Then the post hook.
HostAndPost(p) ==
    /\ pc[p] = "returned"
    /\ \/ /\ dec[p] = "allow" /\ ran' = [ran EXCEPT ![p] = "yes"] /\ UNCHANGED approved
       \/ /\ dec[p] = "ask" /\ ran' = [ran EXCEPT ![p] = "yes"]
          /\ approved' = [approved EXCEPT ![cmd[p]] = @ + 1]
       \/ /\ dec[p] \in {"ask", "deny"} /\ ran' = [ran EXCEPT ![p] = "no"] /\ UNCHANGED approved
    /\ PostCall(p, K_EXEC, IF PostDelivery = "twice" THEN "post2" ELSE "done")
    /\ UNCHANGED <<files, wpos, sess, proj, cmd, dec, stage, learnOk, granted, lock, expired, expAt, tout, spill>>

\* Mutant only: the host delivers the same PostToolUse event a second time.
Post2(p) ==
    /\ pc[p] = "post2"
    /\ UNCHANGED <<files, wpos, sess, proj, cmd, dec, stage, learnOk, ran, approved, granted, lock, expired, expAt, tout, spill>>
    /\ PostCall(p, K_EXEC2, "done")

Crash(p) ==
    /\ Crashes
    /\ pc[p] \notin {"idle", "done", "crashed"}
    /\ pc' = [pc EXCEPT ![p] = "crashed"]
    \* an OS lock is released when the process ends; a lock file stays
    /\ lock' = IF LockMode = "oslock" /\ lock = p THEN "free" ELSE lock
    /\ UNCHANGED <<files, recs, sub, queue, after, wpos, dec, tout, spill>> /\ UNCHANGED LocalVars

\* ---------- operator and clock ----------
\* `semgate feedback allow`: one scoped record (session and project from the ledger, expiry).
OpGrant(c) ==
    /\ c \in GrantCmds /\ granted[c] = 0
    /\ recs' = [recs EXCEPT ![OpKey] = [NoRec EXCEPT !.kind = "fb", !.sess = GrantSess, !.proj = GrantProj, !.cmd = c, !.dec = "allow"]]
    /\ files' = [files EXCEPT !["feedback"] = @ \o <<[id |-> OpKey, part |-> 0, last |-> TRUE]>>]
    /\ granted' = [granted EXCEPT ![c] = 1]
    /\ UNCHANGED <<pc, sub, queue, after, wpos, sess, proj, cmd, dec, stage, learnOk, ran, approved, lock, expired, expAt, tout, spill>>

\* A legacy record (written before schema 2): no session, no project, no expiry.
OpLegacy(c) ==
    /\ Legacy /\ c \in GrantCmds /\ recs[OpLegKey].kind = "none"
    /\ recs' = [recs EXCEPT ![OpLegKey] = [NoRec EXCEPT !.kind = "fb", !.cmd = c, !.dec = "allow", !.legacy = TRUE]]
    /\ files' = [files EXCEPT !["feedback"] = <<[id |-> OpLegKey, part |-> 0, last |-> TRUE]>> \o @]
    /\ UNCHANGED <<pc, sub, queue, after, wpos, sess, proj, cmd, dec, stage, learnOk, ran, approved, granted, lock, expired, expAt, tout, spill>>

Expire ==
    /\ ~expired /\ \E c \in Commands : granted[c] > 0
    /\ expired' = TRUE
    /\ UNCHANGED <<files, recs, pc, sub, queue, after, wpos, sess, proj, cmd, dec, stage, learnOk, ran, approved, granted, lock, expAt, tout, spill>>

Step(p) == Decide(p) \/ HostAndPost(p) \/ Post2(p) \/ Acquire(p) \/ AcqTimeout(p) \/ Seek(p) \/ Write(p) \/ Release(p)

AllDone == \A p \in Procs : pc[p] \in {"done", "crashed"}

Init ==
    /\ files = [f \in Files |-> <<>>]
    /\ recs = [k \in Keys |-> NoRec]
    /\ pc = [p \in Procs |-> "idle"]
    /\ sub = [p \in Procs |-> "none"]
    /\ queue = [p \in Procs |-> <<>>]
    /\ after = [p \in Procs |-> "done"]
    /\ wpos = [p \in Procs |-> 0]
    /\ sess = [p \in Procs |-> "none"] /\ proj = [p \in Procs |-> "none"] /\ cmd = [p \in Procs |-> "none"]
    /\ dec = [p \in Procs |-> "none"] /\ stage = [p \in Procs |-> "none"]
    /\ learnOk = [p \in Procs |-> FALSE]
    /\ ran = [p \in Procs |-> "none"]
    /\ approved = [c \in Commands |-> 0]
    /\ granted = [c \in Commands |-> 0]
    /\ lock = "free"
    /\ expired = FALSE
    /\ expAt = [p \in Procs |-> FALSE]
    /\ tout = [p \in Procs |-> 0]
    /\ spill = <<>>

Next == \/ \E p \in Procs : Step(p) \/ Crash(p)
        \/ \E c \in Commands : OpGrant(c) \/ OpLegacy(c)
        \/ Expire
        \/ (AllDone /\ UNCHANGED vars)          \* a finished run stutters (not a deadlock)

Spec == Init /\ [][Next]_vars /\ \A p \in Procs : WF_vars(Step(p))
\* Without fairness: used only to show that the liveness properties need it.
SpecNoFair == Init /\ [][Next]_vars

\* ======================= properties =======================
TypeOK ==
    /\ \A p \in Procs : dec[p] \in Decs \cup {"none"}
    /\ lock \in Procs \cup {"free"}

ExactRecords(f) == Parse(Lines(files[f]), 1, "skip")

Returned(p) == pc[p] = "returned" \/ ran[p] # "none"

\* L1: a returned decision has exactly one complete host_response record with
\* that decision: in the ledger, or (after a lock timeout) in a spill file.
LedgerOneLine ==
    \A p \in Procs : Returned(p) =>
        LET rs == ExactRecords("ledger") \o spill
            hr == {i \in 1..Len(rs) : rs[i].kind = "hr" /\ rs[i].step = p}
        IN Cardinality(hr) = 1 /\ \A i \in hr : rs[i].dec = dec[p]

\* R1: the code's history reader returns only records that were written, as written.
NoMisread ==
    LET rd == Read("history", HistReader) IN
    rd.ok => \A r \in Range(rd.rs) : r = recs[r.key] @@ [key |-> r.key]

\* H1
LearnedSound == \A p \in Procs : stage[p] = "learned" => learnOk[p]

\* H2
CountNoOver == \A c \in Commands : Count(c) <= approved[c]

\* H3 (a lock timeout keeps a record out of the store on purpose: guarded)
CountExactAtEnd == (AllDone /\ \A p \in Procs : pc[p] # "crashed" /\ tout[p] = 0) => \A c \in Commands : Count(c) = approved[c]

\* F1 (strong): every human-approved allow is covered by the operator's
\* approval: same command, same session, same project, before the expiry.
ApprovalScoped == \A p \in Procs : stage[p] = "human" =>
                    granted[cmd[p]] > 0 /\ sess[p] = GrantSess /\ proj[p] = GrantProj /\ ~expAt[p]
\* F2 (weaker): only the approved command
ApprovalExact == \A p \in Procs : stage[p] = "human" => granted[cmd[p]] > 0
\* F3 (weaker): only in the approved session and project
ApprovalSessionScoped == \A p \in Procs : stage[p] = "human" => sess[p] = GrantSess /\ proj[p] = GrantProj
\* F4 (weaker): never after the expiry
ApprovalUnexpired == \A p \in Procs : stage[p] = "human" => ~expAt[p]
\* Old F1 (one use per approval). Not required any more (owner decision (b):
\* reusable inside its scope until it expires); kept as a check that reuse
\* inside the scope is reachable.
ApprovalOnce == \A c \in Commands : Cardinality({p \in Procs : stage[p] = "human" /\ cmd[p] = c}) <= granted[c]

\* FC: a hook call whose lock wait timed out before it returned never returned allow.
FailClosed == \A p \in Procs : Returned(p) /\ tout[p] = 1 => dec[p] # "allow"

\* T1
Termination == <>[]AllDone

\* T2
HistoryReadable == Read("history", HistReader).ok
HistoryRecovers == []<>HistoryReadable
\* The same claim for a run that terminates and then stutters: []<>P holds
\* exactly when P holds in the final state. Checkable as an invariant (with
\* symmetry) on the large configurations.
HistoryRecoversFinal == AllDone => HistoryReadable

\* No torn line and no lost record (for the locked code these are
\* properties; for the unlocked "old" configuration they are canaries that
\* show the model can produce both).
NoTornLine     == \A f \in Files : ~HasTorn(f)
NoLostRecord   == \A p \in Procs : pc[p] = "done" =>
                        \E i \in 1..Len(ExactRecords("ledger") \o spill) : (ExactRecords("ledger") \o spill)[i].step = p

\* ======================= canaries (must be violated) =======================
K1_NoApprovalUsed == \A p \in Procs : stage[p] # "human"
K2_NoLearnedAllow == \A p \in Procs : stage[p] # "learned"
K3_NoReturn       == \A p \in Procs : ~Returned(p)
K4_NoTornLine     == NoTornLine
K5_NoLostRecord   == NoLostRecord
K10_NoLockTimeout == \A p \in Procs : tout[p] # 1
K11_NoFailClosed  == \A p \in Procs : stage[p] # "failclosed"
=============================================================================
