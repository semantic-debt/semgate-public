---------------------------- MODULE MC_Semgate ----------------------------
(* Model constants for Semgate.tla that a .cfg file cannot write directly. *)
EXTENDS Semgate
\* c1: a command the judge asks about (semantic ask);
\* c2: a command the judge denies (semantic deny).
MCBase == [c \in Commands |-> IF c = "c1" THEN "ask" ELSE "deny"]
\* Processes are identical up to their id: symmetry is sound for invariants
\* (not used for liveness checks).
Perms == Permutations(Procs)
=============================================================================
