---------------------------- MODULE SemgateServe ----------------------------
(***************************************************************************)
(* `semgate serve --stdio` and the OpenCode plugin.                        *)
(*                                                                         *)
(* Code mapped (branch concurrency-fixes; "old" = commit 7f4f160):        *)
(*   serve.py Server: a pool of `Workers` threads judges requests from a   *)
(*                 queue; each judge request has a deadline (the plugin's  *)
(*                 timeout minus a margin). At the deadline serve answers  *)
(*                 "ask": a queued request is dropped (never judged); a    *)
(*                 running one is abandoned (it keeps its thread; its late *)
(*                 result is discarded). serve exits (the plugin starts a  *)
(*                 new one) when every worker holds an abandoned judgment, *)
(*                 or when it is idle except for abandoned judgments.      *)
(*                 old: one request at a time, in order, no deadline.      *)
(*   opencode_semgate.js judge(): id = nextId++, a 20 s timer per request  *)
(*                 started when it is SENT; on timeout the waiter is       *)
(*                 deleted and the call gets "ask" (refused). Answers are  *)
(*                 matched by id; an answer with no waiter is dropped. On  *)
(*                 serve exit every open call gets "ask".                  *)
(*   The serve-side deadline and the plugin timer are one action here     *)
(*   (Timeout): both give "ask"; serve's comes first by the margin.        *)
(*                                                                         *)
(* Abstractions:                                                           *)
(*  C1 Time is discrete ticks. A judgment takes D ticks; the plugin        *)
(*     timeout is T ticks. Timers and finished judgments are urgent: time  *)
(*     does not pass while one of them is due, nor while serve has a free  *)
(*     worker and a waiting line.                                          *)
(*  C2 The agent sends requests in bursts of N (one turn's tool calls).    *)
(*     It sends the next burst only after every request of the current    *)
(*     burst was resolved (answer or timeout): the next model turn needs   *)
(*     all tool results.                                                   *)
(*  C3 Request ids are <<burst parity, k>>. A new burst may start only     *)
(*     when serve holds no request of the same parity, so an id is never   *)
(*     reused while serve still has it (the real ids never repeat).        *)
(*  C4 Answers: odd k -> "allow", even k -> "deny" (so that a mixed-up     *)
(*     answer is visible).                                                 *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    N,              \* requests per burst
    D,              \* ticks per judgment
    T,              \* plugin timeout, ticks
    Workers,        \* judgments in progress at once (old: 1; code: pool)
    Match,          \* "id" (code) | "fifo" (mutant: oldest waiter gets the answer)
    KeepWaiter,     \* FALSE (code) | TRUE (mutant: a late answer still resolves the call)
    HasTimeout,     \* TRUE (code) | FALSE (mutant)
    CancelMode,     \* "none" (old) | "abandon" (code) | "drop" (frees the worker; not possible in Python)
    Restart,        \* TRUE (code): serve exits when stuck, the plugin starts a new one
    JudgeCanHang    \* FALSE | TRUE (a model call that never returns; no provider timeout)

Ids == {0, 1} \X (1..N)
Ans(i) == IF i[2] % 2 = 1 THEN "allow" ELSE "deny"

VARIABLES
    queue,      \* Seq(Ids): lines waiting on serve's stdin
    work,       \* [Ids -> -1..D]: -1 = not being judged
    hung,       \* [Ids -> BOOLEAN]
    pend,       \* [Ids -> "unsent" | "waiting" | "resolved"]
    rem,        \* [Ids -> 0..T]: ticks left on the plugin timer
    used,       \* [Ids -> "none" | "allow" | "deny" | "ask"]: what the plugin used
    timedOut,   \* [Ids -> BOOLEAN]
    b,          \* current burst parity
    sent,       \* requests sent in the current burst
    aband       \* ids whose judgment passed its deadline and still holds a worker

vars == <<queue, work, hung, pend, rem, used, timedOut, b, sent, aband>>

InServe(i) == work[i] >= 0 \/ \E j \in 1..Len(queue) : queue[j] = i
Busy == {i \in Ids : work[i] >= 0}
ServeIdle == Busy = {} /\ queue = <<>>

Send ==
    /\ sent < N
    /\ LET i == <<b, sent + 1>> IN
       /\ pend' = [pend EXCEPT ![i] = "waiting"]
       /\ rem' = [rem EXCEPT ![i] = T]
       /\ queue' = Append(queue, i)
    /\ sent' = sent + 1
    /\ UNCHANGED <<work, hung, used, timedOut, b, aband>>

NewBurst ==
    /\ sent = N
    /\ \A k \in 1..N : pend[<<b, k>>] = "resolved"
    /\ \A k \in 1..N : ~InServe(<<1 - b, k>>)
    /\ b' = 1 - b /\ sent' = 0
    /\ pend' = [i \in Ids |-> IF i[1] = 1 - b THEN "unsent" ELSE pend[i]]
    /\ used' = [i \in Ids |-> IF i[1] = 1 - b THEN "none" ELSE used[i]]
    /\ timedOut' = [i \in Ids |-> IF i[1] = 1 - b THEN FALSE ELSE timedOut[i]]
    /\ UNCHANGED <<queue, work, hung, rem, aband>>

ServeStart ==
    /\ queue # <<>> /\ Cardinality(Busy) < Workers
    /\ LET i == Head(queue) IN
       /\ work' = [work EXCEPT ![i] = D]
       /\ \E h \in (IF JudgeCanHang THEN BOOLEAN ELSE {FALSE}) : hung' = [hung EXCEPT ![i] = h]
    /\ queue' = Tail(queue)
    /\ UNCHANGED <<pend, rem, used, timedOut, b, sent, aband>>

\* serve writes the answer line; the plugin's readline handler runs.
ServeAnswer(i) ==
    /\ work[i] = 0 /\ ~hung[i]
    /\ work' = [work EXCEPT ![i] = -1]
    /\ aband' = aband \ {i}
    /\ IF Match = "id"
       THEN IF pend[i] = "waiting"
            THEN /\ pend' = [pend EXCEPT ![i] = "resolved"] /\ used' = [used EXCEPT ![i] = Ans(i)]
                 /\ rem' = [rem EXCEPT ![i] = 0]
            ELSE /\ UNCHANGED rem
                 /\ IF KeepWaiter /\ timedOut[i]
                    THEN used' = [used EXCEPT ![i] = Ans(i)] /\ UNCHANGED pend
                    ELSE UNCHANGED <<pend, used>>
       ELSE LET ws == {j \in Ids : pend[j] = "waiting"} IN
            IF ws = {} THEN UNCHANGED <<pend, used, rem>>
            ELSE LET w == CHOOSE j \in ws : \A j2 \in ws : j[2] <= j2[2] IN
                 /\ pend' = [pend EXCEPT ![w] = "resolved"] /\ used' = [used EXCEPT ![w] = Ans(i)]
                 /\ rem' = [rem EXCEPT ![w] = 0]
    /\ UNCHANGED <<queue, hung, timedOut, b, sent>>

Timeout(i) ==
    /\ HasTimeout /\ pend[i] = "waiting" /\ rem[i] = 0
    /\ pend' = [pend EXCEPT ![i] = "resolved"]
    /\ used' = [used EXCEPT ![i] = "ask"]
    /\ timedOut' = [timedOut EXCEPT ![i] = TRUE]
    /\ CASE CancelMode = "drop" ->
              /\ queue' = SelectSeq(queue, LAMBDA j : j # i)
              /\ work' = [work EXCEPT ![i] = -1]
              /\ hung' = [hung EXCEPT ![i] = FALSE]
              /\ UNCHANGED aband
         []  CancelMode = "abandon" ->
              /\ queue' = SelectSeq(queue, LAMBDA j : j # i)       \* queued: dropped, never judged
              /\ aband' = IF work[i] >= 0 THEN aband \cup {i} ELSE aband
              /\ UNCHANGED <<work, hung>>
         []  OTHER -> UNCHANGED <<queue, work, hung, aband>>
    /\ UNCHANGED <<rem, b, sent>>

\* serve reads the next stdin line as soon as a worker is free
Urgent == \/ \E i \in Ids : HasTimeout /\ pend[i] = "waiting" /\ rem[i] = 0
          \/ \E i \in Ids : work[i] = 0 /\ ~hung[i]
          \/ queue # <<>> /\ Cardinality(Busy) < Workers

Tick ==
    /\ ~Urgent
    /\ (\E i \in Ids : pend[i] = "waiting" /\ HasTimeout) \/ (\E i \in Busy : ~hung[i])   \* something is timed
    /\ rem' = [i \in Ids |-> IF pend[i] = "waiting" /\ HasTimeout /\ rem[i] > 0 THEN rem[i] - 1 ELSE rem[i]]
    /\ work' = [i \in Ids |-> IF work[i] > 0 /\ ~hung[i] THEN work[i] - 1 ELSE work[i]]
    /\ UNCHANGED <<queue, hung, pend, used, timedOut, b, sent, aband>>

\* serve exits (code 75) and the plugin starts a new one: every open call of
\* the old process gets "ask"; abandoned judgments are gone with the process.
RestartServe ==
    /\ Restart /\ aband # {}
    /\ \/ (Busy \ aband = {} /\ queue = <<>>)
       \/ Cardinality(aband) >= Workers
    /\ work' = [i \in Ids |-> -1] /\ hung' = [i \in Ids |-> FALSE] /\ aband' = {} /\ queue' = <<>>
    /\ pend' = [i \in Ids |-> IF pend[i] = "waiting" THEN "resolved" ELSE pend[i]]
    /\ used' = [i \in Ids |-> IF pend[i] = "waiting" THEN "ask" ELSE used[i]]
    /\ rem' = [i \in Ids |-> IF pend[i] = "waiting" THEN 0 ELSE rem[i]]
    /\ UNCHANGED <<timedOut, b, sent>>

Init ==
    /\ queue = <<>>
    /\ work = [i \in Ids |-> -1] /\ hung = [i \in Ids |-> FALSE]
    /\ pend = [i \in Ids |-> "unsent"] /\ rem = [i \in Ids |-> 0]
    /\ used = [i \in Ids |-> "none"] /\ timedOut = [i \in Ids |-> FALSE]
    /\ b = 0 /\ sent = 0
    /\ aband = {}

ServeStep == ServeStart \/ \E i \in Ids : ServeAnswer(i)

Next == Send \/ NewBurst \/ ServeStep \/ Tick \/ RestartServe \/ \E i \in Ids : Timeout(i)

Spec == Init /\ [][Next]_vars
        /\ WF_vars(ServeStep) /\ WF_vars(Tick) /\ WF_vars(RestartServe) /\ \A i \in Ids : WF_vars(Timeout(i))
\* Without fairness: used only to show that the liveness properties need it.
SpecNoFair == Init /\ [][Next]_vars

\* ======================= properties =======================
\* S1
AnswerForRightId == \A i \in Ids : used[i] \in {"none", "ask", Ans(i)}
\* S2
NoLateAllow == \A i \in Ids : timedOut[i] => used[i] = "ask"
\* S3
EveryRequestResolved == \A i \in Ids : (pend[i] = "waiting") ~> (pend[i] = "resolved")
\* S4
ServeReturnsIdle == []<>ServeIdle
\* S5
NoTimeoutWithinBudget == \A i \in Ids : ~timedOut[i]

\* canaries (must be violated)
K8_NoAnswer == \A i \in Ids : used[i] \notin {"allow", "deny"}
K9_NoTimeout == \A i \in Ids : ~timedOut[i]
K12_NoAbandon == aband = {}
=============================================================================
