#!/usr/bin/env bash
# The WSL half of scripts/test-local.sh. Runs inside WSL (Linux); the Windows
# side runs it (carriage returns removed) with: <work> <key> <break>
#
#   <work>   WSL path of the Windows run folder: tree.tar (the tracked files),
#            marker.json (scripts/localci.py marker). This script writes its
#            results there: wsl-canary.rc, junit-wsl-*.xml, ack-wsl.json.
#   <key>    short hash of the Windows checkout path (names the copy folder)
#   <break>  "" normally; a LOCALCI_BREAK value to prove a canary fires
#
# The copy: a new folder ~/semgate-localci-<key>-XXXXXX in the WSL home (not
# /tmp: it can be mounted noexec), removed when this script ends. The shared
# venv ~/semgate-localci-venv holds only the pinned dependencies from
# pyproject.toml (".[dev]", semgate itself uninstalled); it is created and
# updated under a lock (flock ~/semgate-localci-venv.lock), and only when
# pyproject.toml changed. Tests import semgate from the copy (PYTHONPATH) and
# run with HOME, USERPROFILE and TMPDIR pointing at fresh temp folders.
#
# Exit: 0 all pytest runs passed; 1 a pytest run failed; 2 setup failed;
# 90 the must-fail canary passed (failures would not be seen).
set -u -o pipefail
work="$1"; key="$2"; brk="${3:-}"
venv="$HOME/semgate-localci-venv"
src="$(mktemp -d "$HOME/semgate-localci-$key-XXXXXX")" || exit 2
h="$(mktemp -d -p "$HOME")"; t="$(mktemp -d -p "$HOME")"
trap 'rm -rf "$src" "$h" "$t"' EXIT
tar -xf "$work/tree.tar" -C "$src" || { echo "== WSL: copy into WSL failed ($work/tree.tar)"; exit 2; }
cd "$src" || exit 2
if [ "$brk" = wslcopy ]; then
  # Proof for the tree marker: the copy differs from what the marker hashed
  # (the 2026-09-25 incident: WSL tested another copy).
  printf '\n# localci break: changed in the WSL copy only\n' >> "$src/semgate/__init__.py"
fi

# One run at a time creates or updates the shared venv. semgate is not
# installed in it: an install would point at the folder of one run.
command -v flock >/dev/null || { echo "== WSL: flock not found (util-linux)"; exit 2; }
exec 9>"$venv.lock"
flock 9
stamp="$(sha256sum pyproject.toml | cut -d" " -f1)"
if [ ! -x "$venv/bin/python" ]; then rm -rf "$venv"; python3 -m venv "$venv" || exit 2; fi
if [ "$(cat "$venv/.semgate-deps" 2>/dev/null)" != "$stamp" ]; then
  "$venv/bin/python" -m pip install -q ".[dev]" || exit 2
  echo "$stamp" > "$venv/.semgate-deps"
fi
# Remove every installed semgate (also an old editable install). Run from /
# so pip does not see the semgate.egg-info the build left in $src.
for _ in 1 2 3; do
  (cd / && "$venv/bin/python" -m pip show -q semgate >/dev/null 2>&1) || break
  (cd / && "$venv/bin/python" -m pip uninstall -q -y semgate)
done
flock -u 9; exec 9>&-
py="$venv/bin/python"

# Must-fail canary: the same python and pytest must report a failing test.
mkdir -p "$t/canary"
if [ "$brk" = mustfail ] || [ "$brk" = mustfail-wsl ]; then body='assert 1 == 1'; else body='assert 1 == 2, "localci must-fail canary"'; fi
printf 'def test_localci_must_fail():\n    %s\n' "$body" > "$t/canary/test_localci_must_fail.py"
HOME="$h" USERPROFILE="$h" TMPDIR="$t" "$py" -m pytest -q -p no:cacheprovider "$t/canary" > "$t/canary.out" 2>&1
crc=$?
echo "$crc" > "$work/wsl-canary.rc"
if [ "$crc" != 1 ]; then
  echo "== WSL canary: a test that must fail gave pytest exit $crc (expected 1); failures would not be seen. Stopping."
  exit 90
fi

# The pytest targets; the LOCALCI_BREAK proofs change them (same as
# test-local.sh; the extra file goes into the copy's tests/).
targets=(tests)
case "$brk" in
  count) targets=(tests/test_[l-z]*.py) ;;
  skip)  printf 'import pytest
def test_localci_unlisted_skip():
    pytest.skip("localci break: a skip reason nobody listed")
' > tests/test_localci_brk_tmp.py ;;
  fail)  printf 'def test_localci_injected_failure():
    assert False, "localci break: injected failure"
' > tests/test_localci_brk_tmp.py ;;
esac

export PYTHONPATH="$src"
rc=0
HOME="$h" USERPROFILE="$h" TMPDIR="$t" SEMGATE_TREE_MARKER="$work/marker.json" SEMGATE_TREE_ACK="$work/ack-wsl.json" \
  SEMGATE_TREE_ROOT="$src" "$py" -m pytest -q -p no:cacheprovider -rs tests "${extra[@]}" \
  --junitxml="$work/junit-wsl-tests.xml" || rc=1
HOME="$h" USERPROFILE="$h" TMPDIR="$t" "$py" -m pytest -q -p no:cacheprovider -rs integrations/gemini-cli-shadow/tests \
  --junitxml="$work/junit-wsl-integration.xml" || rc=1
exit $rc
