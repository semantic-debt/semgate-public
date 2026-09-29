--------------------------- MODULE MC_SemgateF6 ---------------------------
EXTENDS SemgateF6
\* a1 creates x, a2 creates y; both write the same content h1 (same sha).
MCPath == [a \in Agents |-> IF a = "a1" THEN "x" ELSE "y"]
=============================================================================
