"""TLC jobs for SemgateF6.tla and SemgateServe.tla (imported by run_tlc.py)."""
from __future__ import annotations

# "code" = branch concurrency-fixes: expected-hash post hook, unique temp names.
F6_OLD = {"Agents": '{"a1", "a2"}', "AgentPath": "<- MCPath", "Paths": '{"x", "y"}', "Sessions": '{"s1", "s2"}',
          "Rehash": '"code"', "SnapCheck": '"code"', "SessionMode": '"code"', "Replace": '"windows"',
          "PostMode": '"code"', "UserEdits": "TRUE", "UserCleans": "TRUE"}
F6_CODE = dict(F6_OLD, Replace='"unique"', PostMode='"expect"')
F6_VARIANTS = {
    "code": F6_CODE,
    "old": F6_OLD,
    "old_posix": dict(F6_OLD, Replace='"posix"'),
    "M_trust": dict(F6_CODE, Rehash='"trust"'),
    "M_nosnap": dict(F6_CODE, SnapCheck='"none"'),
    "M_shared": dict(F6_CODE, SessionMode='"shared"'),
    "M_tmp_collide": dict(F6_CODE, Replace='"windows"'),
    "M_postcode": dict(F6_CODE, PostMode='"code"'),
}
F6_INV = ["EligibleSound", "RmRestorable", "AgentContentOnly", "SnapshotRaceNoLoss"]
F6_TEMP = ["EditedStaysIneligible"]
F6_CANARY = ["K6_NoEligible", "K7_NoRmRuns"]

# "code" = branch concurrency-fixes: worker pool, deadline per request,
# abandon + restart. "old" = one request at a time, no deadline in serve.
SV_OLD = {"N": "2", "D": "3", "T": "5", "Workers": "1", "Match": '"id"', "KeepWaiter": "FALSE",
          "HasTimeout": "TRUE", "CancelMode": '"none"', "Restart": "FALSE", "JudgeCanHang": "FALSE"}
SV_CODE = dict(SV_OLD, Workers="2", CancelMode='"abandon"', Restart="TRUE")
SV_VARIANTS = {
    "code": SV_CODE,
    "code_hang": dict(SV_CODE, JudgeCanHang="TRUE"),
    "old": SV_OLD,
    "old_hang": dict(SV_OLD, JudgeCanHang="TRUE"),
    "M_fifo": dict(SV_CODE, JudgeCanHang="TRUE", Match='"fifo"'),
    "M_keepwaiter": dict(SV_CODE, JudgeCanHang="TRUE", KeepWaiter="TRUE"),
    "M_notimeout_hang": dict(SV_CODE, JudgeCanHang="TRUE", HasTimeout="FALSE"),
    "M_one_worker": dict(SV_CODE, Workers="1"),
    "M_nocancel_hang": dict(SV_CODE, JudgeCanHang="TRUE", CancelMode='"none"'),
    "M_norestart_hang": dict(SV_CODE, JudgeCanHang="TRUE", Restart="FALSE"),
}
SV_INV = ["AnswerForRightId", "NoLateAllow", "NoTimeoutWithinBudget"]
SV_TEMP = ["EveryRequestResolved", "ServeReturnsIdle"]


def more_jobs():
    out = []
    for v, c in F6_VARIANTS.items():
        for p in F6_INV:
            out.append(("MC_SemgateF6", v, c, "inv", p, "Spec"))
    for p in F6_CANARY:
        out.append(("MC_SemgateF6", "code", F6_CODE, "inv", p, "Spec"))
    for v, c in F6_VARIANTS.items():
        for p in F6_TEMP:
            out.append(("MC_SemgateF6", v, c, "prop", p, "Spec"))
    for v, c in SV_VARIANTS.items():
        for p in SV_INV:
            out.append(("SemgateServe", v, c, "inv", p, "Spec"))
    out.append(("SemgateServe", "code", SV_CODE, "inv", "K8_NoAnswer", "Spec"))
    out.append(("SemgateServe", "code_hang", SV_VARIANTS["code_hang"], "inv", "K9_NoTimeout", "Spec"))
    out.append(("SemgateServe", "code_hang", SV_VARIANTS["code_hang"], "inv", "K12_NoAbandon", "Spec"))
    for v, c in SV_VARIANTS.items():
        for p in SV_TEMP:
            out.append(("SemgateServe", v, c, "prop", p, "Spec"))
    # fairness check: without WF the liveness properties must fail
    out.append(("SemgateServe", "code_hang_nofair", SV_VARIANTS["code_hang"], "prop", "EveryRequestResolved", "SpecNoFair"))
    return out
