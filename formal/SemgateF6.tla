------------------------------ MODULE SemgateF6 ------------------------------
(***************************************************************************)
(* F6: files the agent created in this session (semgate/agentfiles.py).    *)
(*                                                                         *)
(* Agent steps a (each: PreToolUse record_pre, the tool run, PostToolUse   *)
(* record_post) create a file with content "h1". A `rm x` decision (one    *)
(* hook call) asks AgentFiles.eligible and, when eligible, the host runs   *)
(* the rm later. The user may edit x (content "h2") at any time, and may   *)
(* delete ~/.semgate/snapshots/ (the docs say to do this to free space).   *)
(*                                                                         *)
(* Code mapped (branch concurrency-fixes; "old" = commit 7f4f160):        *)
(*   Pre        agentfiles.record_pre: existed = os.path.lexists; the      *)
(*              expected sha256 from the tool input (Write content).       *)
(*   Post       agentfiles.record_post: sha of the current file; recorded  *)
(*              only if it is an expected sha (PostMode "expect"; old:     *)
(*              "code" = whatever is there). Snapshot: an existing one     *)
(*              with the right hash is success; else copy to a temp name   *)
(*              unique per process, hash it, os.replace (Replace "unique"; *)
(*              old: shared <sha>.tmp, "windows"/"posix").                 *)
(*   Eligible   agentfiles.py:222: latest created record for the path in   *)
(*              this session's file, current sha == recorded sha, snapshot *)
(*              <session>/<sha> re-hashed == sha                           *)
(*                                                                         *)
(* Abstractions:                                                           *)
(*  B1 Content is a hash value: "none" (no file), "h1" (agent), "h2"       *)
(*     (user). Two agent files with the same content share one sha, one   *)
(*     snapshot path and one temp name <sha>.tmp (agentfiles.py:205).      *)
(*  B2 The created-record append is atomic here. Its cross-process race    *)
(*     (lost records) is modelled in Semgate.tla; here a lost record only  *)
(*     means "not eligible", which the other checks already cover.         *)
(*  B3 Copying to <sha>.tmp is: open (truncate) then close. Two writers of *)
(*     the same content leave a complete file when the last one closes.   *)
(*  B4 Windows: os.replace fails while another process holds the temp file *)
(*     open (no FILE_SHARE_DELETE) or when the temp file is gone. POSIX:   *)
(*     the rename succeeds; open writers keep writing into the inode that  *)
(*     is now the snapshot.                                                *)
(*  B5 Hashing a file and reading the records are one step each.           *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Agents,         \* agent create steps (model values)
    AgentPath,      \* [Agents -> Paths]
    Paths,          \* {"x", "y"}
    Sessions,       \* {"s1", "s2"}; every agent step runs in s1
    Rehash,         \* "code" | "trust" (mutant: eligible without re-hashing the file)
    SnapCheck,      \* "code" | "none" (mutant: eligible without checking the snapshot)
    SessionMode,    \* "code" (per-session records) | "shared" (mutant: records of every session)
    Replace,        \* "windows" | "posix" | "unique" (temp name unique per process: no collision)
    PostMode,       \* "code" (hash whatever is there) | "expect" (record only the content the tool wrote)
    UserEdits,      \* TRUE: the user may edit x once
    UserCleans      \* TRUE: the user may delete the snapshots directory once

AgentSess == "s1"
Hashes == {"h1", "h2"}
SH == Sessions \X Hashes

VARIABLES
    content,     \* [Paths -> {"none","h1","h2"}]
    agentWrote,  \* set of <<path, hash>> an agent step wrote
    created,     \* Seq of [sess, path, sha] created records (append order)
    snap,        \* [SH -> {"absent","complete","partial"}]
    tmp,         \* [SH -> {"absent","writing","complete"}]
    tmpOpen,     \* [SH -> SUBSET Agents] writers holding <sha>.tmp open
    snapW,       \* [SH -> SUBSET Agents] (POSIX) writers still writing into the renamed inode
    apc, existed, hsh,
    userEdited, cleaned,
    dpc, dsess, delig, eOk, agentOk, rmRan, rmOk

vars == <<content, agentWrote, created, snap, tmp, tmpOpen, snapW, apc, existed, hsh,
          userEdited, cleaned, dpc, dsess, delig, eOk, agentOk, rmRan, rmOk>>

\* ---------- eligibility as the code computes it ----------
Matching(s, x) == {i \in 1..Len(created) : created[i].path = x /\ (SessionMode = "shared" \/ created[i].sess = s)}

EligibleCode(s, x) ==
    LET m == Matching(s, x) IN
    IF m = {} THEN FALSE
    ELSE LET r == created[CHOOSE i \in m : \A j \in m : j <= i]
             snapSess == IF SessionMode = "shared" THEN r.sess ELSE s
         IN /\ (Rehash = "trust" \/ content[x] = r.sha)
            /\ (SnapCheck = "none" \/ snap[<<snapSess, r.sha>>] = "complete")

\* ground truth used by E1: a record of THIS session, current content, complete snapshot of THIS session
TrulyRestorable(s, x) ==
    /\ content[x] # "none"
    /\ \E i \in 1..Len(created) : created[i].sess = s /\ created[i].path = x /\ created[i].sha = content[x]
    /\ snap[<<s, content[x]>>] = "complete"

\* ---------- agent create step ----------
AgentStep(a) ==
    LET x == AgentPath[a]
        k == <<AgentSess, hsh[a]>>
    IN
    \/ /\ apc[a] = "pre"
       /\ existed' = [existed EXCEPT ![a] = content[x] # "none"]
       /\ apc' = [apc EXCEPT ![a] = "run"]
       /\ UNCHANGED <<content, agentWrote, created, snap, tmp, tmpOpen, snapW, hsh>>
    \/ /\ apc[a] = "run"
       /\ content' = [content EXCEPT ![x] = "h1"]
       /\ agentWrote' = agentWrote \cup {<<x, "h1">>}
       /\ apc' = [apc EXCEPT ![a] = "post"]
       /\ UNCHANGED <<created, snap, tmp, tmpOpen, snapW, existed, hsh>>
    \/ /\ apc[a] = "post"
       /\ LET h == content[x] IN
          IF existed[a] \/ h = "none" \/ (PostMode = "expect" /\ h # "h1")
          THEN apc' = [apc EXCEPT ![a] = "done"] /\ UNCHANGED hsh
          ELSE /\ hsh' = [hsh EXCEPT ![a] = h]
               /\ apc' = [apc EXCEPT ![a] = IF snap[<<AgentSess, h>>] # "absent" THEN "verify"
                                            ELSE IF Replace = "unique" THEN "ucopy" ELSE "open"]
       /\ UNCHANGED <<content, agentWrote, created, snap, tmp, tmpOpen, snapW, existed>>
    \* unique temp name: copy + replace cannot collide (fixed design)
    \/ /\ apc[a] = "ucopy"
       /\ snap' = [snap EXCEPT ![k] = "complete"]
       /\ apc' = [apc EXCEPT ![a] = "verify"]
       /\ UNCHANGED <<content, agentWrote, created, tmp, tmpOpen, snapW, existed, hsh>>
    \/ /\ apc[a] = "open"                           \* copyfile opens <sha>.tmp for writing (truncate)
       /\ tmp' = [tmp EXCEPT ![k] = "writing"]
       /\ tmpOpen' = [tmpOpen EXCEPT ![k] = @ \cup {a}]
       /\ apc' = [apc EXCEPT ![a] = "close"]
       /\ UNCHANGED <<content, agentWrote, created, snap, snapW, existed, hsh>>
    \/ /\ apc[a] = "close"                          \* copyfile finishes and closes
       /\ IF a \in snapW[k]
          THEN /\ snapW' = [snapW EXCEPT ![k] = @ \ {a}]
               /\ snap' = [snap EXCEPT ![k] = IF snapW'[k] = {} /\ @ = "partial" THEN "complete" ELSE @]
               /\ UNCHANGED <<tmp, tmpOpen>>
          ELSE /\ tmpOpen' = [tmpOpen EXCEPT ![k] = @ \ {a}]
               /\ tmp' = [tmp EXCEPT ![k] = IF tmpOpen'[k] = {} /\ @ = "writing" THEN "complete" ELSE @]
               /\ UNCHANGED <<snap, snapW>>
       /\ apc' = [apc EXCEPT ![a] = "replace"]
       /\ UNCHANGED <<content, agentWrote, created, existed, hsh>>
    \/ /\ apc[a] = "replace"                        \* os.replace(tmp, snap)
       /\ IF tmp[k] = "absent" \/ (Replace = "windows" /\ tmpOpen[k] # {})
          THEN apc' = [apc EXCEPT ![a] = "done"] /\ UNCHANGED <<snap, tmp, tmpOpen, snapW>>   \* OSError: skip
          ELSE /\ snap' = [snap EXCEPT ![k] = IF tmpOpen[k] = {} THEN "complete" ELSE "partial"]
               /\ snapW' = [snapW EXCEPT ![k] = tmpOpen[k]]
               /\ tmpOpen' = [tmpOpen EXCEPT ![k] = {}]
               /\ tmp' = [tmp EXCEPT ![k] = "absent"]
               /\ apc' = [apc EXCEPT ![a] = "verify"]
       /\ UNCHANGED <<content, agentWrote, created, existed, hsh>>
    \/ /\ apc[a] = "verify"                         \* re-hash the snapshot; unlink on mismatch
       /\ IF snap[k] = "complete"
          THEN /\ created' = Append(created, [sess |-> AgentSess, path |-> x, sha |-> hsh[a]])
               /\ UNCHANGED snap
          ELSE /\ snap' = [snap EXCEPT ![k] = "absent"] /\ UNCHANGED created
       /\ apc' = [apc EXCEPT ![a] = "done"]
       /\ UNCHANGED <<content, agentWrote, tmp, tmpOpen, snapW, existed, hsh>>

\* ---------- the rm decision and its run ----------
Decide ==
    /\ dpc = "idle"
    /\ \E s \in Sessions :
         /\ dsess' = s
         /\ delig' = EligibleCode(s, "x")
         /\ eOk' = TrulyRestorable(s, "x")
         /\ agentOk' = (content["x"] # "none" /\ <<"x", content["x"]>> \in agentWrote)
    /\ dpc' = "decided"
    /\ UNCHANGED <<content, agentWrote, created, snap, tmp, tmpOpen, snapW, apc, existed, hsh, userEdited, cleaned, rmRan, rmOk>>

RunRm ==
    /\ dpc = "decided"
    /\ IF delig
       THEN /\ rmRan' = TRUE
            /\ rmOk' = (content["x"] = "none" \/ snap[<<dsess, content["x"]>>] = "complete")
            /\ content' = [content EXCEPT !["x"] = "none"]
       ELSE UNCHANGED <<rmRan, rmOk, content>>        \* not eligible: the human is asked (not modelled)
    /\ dpc' = "done"
    /\ UNCHANGED <<agentWrote, created, snap, tmp, tmpOpen, snapW, apc, existed, hsh, userEdited, cleaned, dsess, delig, eOk, agentOk>>

\* ---------- the user ----------
UserEdit ==
    /\ UserEdits /\ ~userEdited
    /\ content' = [content EXCEPT !["x"] = "h2"]
    /\ userEdited' = TRUE
    /\ UNCHANGED <<agentWrote, created, snap, tmp, tmpOpen, snapW, apc, existed, hsh, cleaned, dpc, dsess, delig, eOk, agentOk, rmRan, rmOk>>

UserClean ==
    /\ UserCleans /\ ~cleaned
    /\ snap' = [k \in SH |-> "absent"]
    /\ cleaned' = TRUE
    /\ UNCHANGED <<content, agentWrote, created, tmp, tmpOpen, snapW, apc, existed, hsh, userEdited, dpc, dsess, delig, eOk, agentOk, rmRan, rmOk>>

AgentAct(a) == AgentStep(a) /\ UNCHANGED <<userEdited, cleaned, dpc, dsess, delig, eOk, agentOk, rmRan, rmOk>>

AllDone == (\A a \in Agents : apc[a] = "done") /\ dpc = "done"

Init ==
    /\ content = [p \in Paths |-> "none"]
    /\ agentWrote = {}
    /\ created = <<>>
    /\ snap = [k \in SH |-> "absent"] /\ tmp = [k \in SH |-> "absent"]
    /\ tmpOpen = [k \in SH |-> {}] /\ snapW = [k \in SH |-> {}]
    /\ apc = [a \in Agents |-> "pre"] /\ existed = [a \in Agents |-> FALSE] /\ hsh = [a \in Agents |-> "h1"]
    /\ userEdited = FALSE /\ cleaned = FALSE
    /\ dpc = "idle" /\ dsess = "none" /\ delig = FALSE /\ eOk = FALSE /\ agentOk = FALSE
    /\ rmRan = FALSE /\ rmOk = TRUE

Next == \/ \E a \in Agents : AgentAct(a)
        \/ Decide \/ RunRm \/ UserEdit \/ UserClean
        \/ (AllDone /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars /\ (\A a \in Agents : WF_vars(AgentAct(a))) /\ WF_vars(Decide) /\ WF_vars(RunRm)

\* ======================= properties =======================
\* E1
EligibleSound == dpc # "idle" /\ delig => eOk
\* E2
RmRestorable == rmRan => rmOk
\* E3
AgentContentOnly == dpc # "idle" /\ delig => agentOk
\* E4: the code's eligibility for x in s1, evaluated on the current state
EligibleNow == EligibleCode("s1", "x")
EditedStaysIneligible == <>[](userEdited /\ content["x"] = "h2" => ~EligibleNow)
\* E5: at the end, every unchanged agent-created file has a created record
SnapshotRaceNoLoss ==
    AllDone /\ ~cleaned =>
      \A a \in Agents : (~existed[a] /\ content[AgentPath[a]] = "h1") =>
          \E i \in 1..Len(created) : created[i].path = AgentPath[a]

\* canaries (must be violated)
K6_NoEligible == ~(dpc # "idle" /\ delig)
K7_NoRmRuns   == ~rmRan
=============================================================================
