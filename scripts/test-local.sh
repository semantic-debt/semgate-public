#!/usr/bin/env bash
# Run the full test suite locally before a merge: here, and on Linux through
# WSL when it is available (Windows machines). CI on a pull request runs only
# one Linux job; the full matrix runs on main (.github/workflows/ci.yml).
#
#   scripts/test-local.sh              # this machine + WSL (if present)
#   scripts/test-local.sh --no-wsl     # this machine only
#   scripts/test-local.sh --live opencode   # live check against OpenCode 2 only
#   scripts/test-local.sh --live pi         # live check against Pi only
#   PYTHON=/path/to/python scripts/test-local.sh
#   SKIP_LOCAL=1 scripts/test-local.sh     # WSL only
#
# The run checks itself (each check exists because of a real incident):
#   - tree marker: a marker (git HEAD, sha256 over the tracked files' content,
#     random nonce) goes to both runs; tests/test_localci_marker.py must pass
#     and write the nonce back. It fails when pytest ran another tree or
#     imported semgate from elsewhere (2026-09-25: WSL tested another copy
#     and the script printed "all passed").
#   - must-fail canary: before the real run, a generated failing test must
#     make the same pytest exit 1, here and in WSL; if it does not, stop.
#   - test count floor: tests/.min_counts; fewer tests ran = FAIL.
#   - skip reasons: every skip must match tests/.allowed_skips.
#   - exit code: non-zero when any phase failed; the last line is always
#     "RESULT: PASS|FAIL (...)", so a caller that pipes through tail still
#     sees it (2026-09-25: a run with 15 failures showed "exit code 0"
#     because the command was piped through grep | tail).
#   Exit codes: 0 pass, 1 a test phase or check failed, 2 setup problem
#   (untracked files, WSL copy), 3 the live check was skipped.
#
# To see that a check fires, LOCALCI_BREAK breaks the guarded thing on
# purpose and the run must end with RESULT: FAIL and a non-zero exit:
#   mustfail  the canary test passes instead of failing (stops at once)
#   mustfail-wsl  the same, only in WSL (with SKIP_LOCAL=1 for a quick proof)
#   marker    the marker holds a wrong tree hash (both sides fail)
#   wslcopy   a file in the WSL copy is changed after the marker was written
#   count     most test files are left out (--ignore-glob), below the floor
#   skip      an extra test skips for a reason nobody listed
#   fail      an extra test fails
#
# WSL half: scripts/localci-wsl.sh (the copy, the shared venv, the runs).
set -u -o pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2

PYTHON="${PYTHON:-}"
if [ -z "$PYTHON" ]; then
  for c in .venv/Scripts/python.exe .venv/bin/python python3 python; do
    if [ -x "$c" ] || command -v "$c" >/dev/null 2>&1; then PYTHON="$c"; break; fi
  done
fi
use_wsl=1
live=""
while [ $# -gt 0 ]; do
  case "$1" in
    --no-wsl) use_wsl=0 ;;
    --live) live="${2:-}"; shift ;;
    *) echo "unknown argument: $1"; exit 2 ;;
  esac
  shift
done
brk="${LOCALCI_BREAK:-}"

winpath() { cygpath -m "$1" 2>/dev/null || echo "$1"; }

if [ -n "$live" ]; then
  case "$live" in
    opencode) "$PYTHON" scripts/live_opencode.py ;;
    pi) "$PYTHON" scripts/live_pi.py ;;
    *) echo "--live: 'opencode' or 'pi'"; exit 2 ;;
  esac
  exit $?
fi

# The WSL copy takes only files git tracks (git ls-files). An untracked .py
# file under semgate/ or tests/ would be tested here but be missing there, so
# the two halves would test different code (found 2026-09-25: a new
# semgate/proc.py made every WSL test fail at import). Stop instead.
untracked="$(git ls-files --others --exclude-standard -- semgate tests integrations scripts | grep -E '\.(py|js|ts|json|sh)$|/\.(min_counts|allowed_skips)$' || true)"
if [ -n "$untracked" ]; then
  echo "== untracked files would be missing from the WSL copy; git add them (or delete them) first:"
  echo "$untracked" | sed 's/^/   /'
  exit 2
fi

case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) side=windows ;; *) side=posix ;; esac
work="$(mktemp -d -t semgate-localci-XXXXXX)" || exit 2
trap 'rm -rf "$work"' EXIT
wwork="$(winpath "$work")"
status=0
canaries=ok
local_sum="skipped"
wsl_sum="not run"
fail() { status=1; echo "== FAIL: $*"; }

# ---------------------------------------------------------------- tree marker
if ! "$PYTHON" scripts/localci.py marker --out "$wwork/marker.json" $([ "$brk" = marker ] && echo --tamper); then
  echo "== cannot write the tree marker"; exit 2
fi

# ---------------------------------------------------------------- must-fail canary (here)
mkdir -p "$work/canary"
if [ "$brk" = mustfail ]; then body='assert 1 == 1'; else body='assert 1 == 2, "localci must-fail canary"'; fi
printf 'def test_localci_must_fail():\n    %s\n' "$body" > "$work/canary/test_localci_must_fail.py"
"$PYTHON" -m pytest -q -p no:cacheprovider "$wwork/canary" > "$work/canary.out" 2>&1
crc=$?
if [ "$crc" != 1 ]; then
  echo "== canary: a test that must fail gave pytest exit $crc (expected 1); failures would not be seen. Stopping."
  sed 's/^/   /' "$work/canary.out" | tail -5
  echo "RESULT: FAIL (windows=not run, wsl=not run, canaries=must-fail canary passed on $side)"
  exit 1
fi
echo "== canary: a failing test gives pytest exit 1 ($side)"

# The pytest targets; the LOCALCI_BREAK proofs change them (same as
# localci-wsl.sh). An extra test file goes into tests/ (outside tests/ pytest
# would walk up to the drive root); it is not tracked, so the marker hash does
# not change, and it is removed when the script ends (if the script is killed,
# the untracked-file guard above reports it on the next run).
targets=(tests)
brkfile=tests/test_localci_brk_tmp.py
case "$brk" in
  count) targets=(tests/test_[l-z]*.py) ;;   # tests/test_[a-k]*.py left out: below the floor
  skip)  printf 'import pytest
def test_localci_unlisted_skip():
    pytest.skip("localci break: a skip reason nobody listed")
' > "$brkfile" ;;
  fail)  printf 'def test_localci_injected_failure():
    assert False, "localci break: injected failure"
' > "$brkfile" ;;
esac
trap 'rm -rf "$work"; [ -n "$brk" ] && rm -f "$brkfile"' EXIT

# check <side> <suite> <junit> [marker ack]: prints the summary line.
check() {
  local out
  if [ $# -gt 3 ]; then
    out="$("$PYTHON" scripts/localci.py check --side "$1" --suite "$2" --junit "$3" --marker "$4" --ack "$5")"
  else
    out="$("$PYTHON" scripts/localci.py check --side "$1" --suite "$2" --junit "$3")"
  fi
  local rc=$?
  echo "== $out"
  return $rc
}

# ---------------------------------------------------------------- this machine
if [ "${SKIP_LOCAL:-0}" != 1 ]; then
  echo "== local: $("$PYTHON" -c 'import platform,sys; print(platform.system(), sys.version.split()[0])')"
  SEMGATE_TREE_MARKER="$wwork/marker.json" SEMGATE_TREE_ACK="$wwork/ack-local.json" SEMGATE_TREE_ROOT="$(winpath "$PWD")" \
    "$PYTHON" -m pytest -q -p no:cacheprovider -rs "${targets[@]}" --junitxml="$wwork/junit-local-tests.xml"
  rc1=$?
  "$PYTHON" -m pytest -q -p no:cacheprovider -rs integrations/gemini-cli-shadow/tests --junitxml="$wwork/junit-local-integration.xml"
  rc2=$?
  [ "$rc1" = 0 ] || fail "$side pytest tests exit $rc1"
  [ "$rc2" = 0 ] || fail "$side pytest integration exit $rc2"
  l1="$(check "$side" tests "$wwork/junit-local-tests.xml" "$wwork/marker.json" "$wwork/ack-local.json")" || status=1
  case "$l1" in *"tree marker"*) canaries=FAIL ;; esac
  echo "$l1"
  l2="$(check "$side" integration "$wwork/junit-local-integration.xml")" || status=1
  echo "$l2"
  local_sum="$(echo "$l1" | sed -n 's/.*: \(PASS\|FAIL\) ran=\([0-9]*\).*/\1 ran=\2/p') +integration $(echo "$l2" | sed -n 's/.*: \(PASS\|FAIL\) ran=\([0-9]*\).*/\1 ran=\2/p')"
fi

# ---------------------------------------------------------------- WSL
if [ "$use_wsl" = 1 ] && command -v wsl.exe >/dev/null 2>&1; then
  git ls-files -z | tar --null -T - -cf "$work/tree.tar" || { echo "== WSL: tar of the tracked files failed"; exit 2; }
  # Forward slashes: Git Bash strips backslashes from arguments to wsl.exe.
  wslwork="$(wsl.exe wslpath -a "$wwork" | tr -d '\r')"
  wslscript="$(wsl.exe wslpath -a "$(winpath "$PWD")/scripts/localci-wsl.sh" | tr -d '\r')"
  if [ -z "$wslwork" ] || [ -z "$wslscript" ]; then echo "== WSL: cannot map $wwork into WSL"; exit 2; fi
  # A short hash of this checkout's path: the WSL folder name says which
  # checkout it belongs to.
  key="$(pwd | cksum | cut -d' ' -f1)"
  echo "== WSL"
  # The script's carriage returns are removed first: this repository stores
  # many files with CRLF endings, and bash in WSL fails on a CRLF script
  # (found 2026-09-26: "set: pipefail: invalid option name").
  MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" wsl.exe -e bash -c 'exec bash -c "$(tr -d "\r" < "$1")" localci-wsl.sh "${@:2}"' \
    _ "$wslscript" "$wslwork" "$key" "$brk"
  wrc=$?
  if [ "$wrc" = 90 ]; then
    echo "RESULT: FAIL (windows=$local_sum, wsl=not run, canaries=must-fail canary passed in WSL)"
    exit 1
  fi
  if [ "$(cat "$work/wsl-canary.rc" 2>/dev/null)" != 1 ]; then
    fail "WSL must-fail canary did not report exit 1 (got '$(cat "$work/wsl-canary.rc" 2>/dev/null)')"; canaries=FAIL
  else
    echo "== canary: a failing test gives pytest exit 1 (wsl)"
  fi
  [ "$wrc" = 0 ] || fail "WSL exit $wrc"
  w1="$(check wsl tests "$wwork/junit-wsl-tests.xml" "$wwork/marker.json" "$wwork/ack-wsl.json")" || status=1
  case "$w1" in *"tree marker"*) canaries=FAIL ;; esac
  echo "$w1"
  w2="$(check wsl integration "$wwork/junit-wsl-integration.xml")" || status=1
  echo "$w2"
  wsl_sum="$(echo "$w1" | sed -n 's/.*: \(PASS\|FAIL\) ran=\([0-9]*\).*/\1 ran=\2/p') +integration $(echo "$w2" | sed -n 's/.*: \(PASS\|FAIL\) ran=\([0-9]*\).*/\1 ran=\2/p')"
fi

if [ "$status" = 0 ]; then
  echo "RESULT: PASS (windows=$local_sum, wsl=$wsl_sum, canaries=$canaries)"
else
  echo "RESULT: FAIL (windows=$local_sum, wsl=$wsl_sum, canaries=$canaries)"
fi
exit $status
