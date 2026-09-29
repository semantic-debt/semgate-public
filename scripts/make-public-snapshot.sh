#!/usr/bin/env bash
# Make a public snapshot of a repo: one commit, new history, local folder only.
#
#   scripts/make-public-snapshot.sh --repo PATH --name NAME --out DIR [options]
#
# What it does:
#   1. `git archive` of one commit of --repo (default HEAD), minus the paths in
#      that commit's `.publish/exclude.txt` and any --exclude.
#   2. Extracts it into DIR/NAME-YYYYMMDD (a NEW folder; refuses an existing
#      one unless it was made by this script and --replace is given).
#   3. `git init`, ONE commit authored and committed by --author (default
#      "Manuel Parra <th3nolo@gmail.com>"). Executable bits are copied from the
#      source commit. No remote is added. Nothing is pushed.
#   4. Runs scripts/publish_scan.py on the snapshot and prints a PASS/FAIL
#      table. Exit code 1 when a check fails. The JSON report is written next
#      to the snapshot folder (DIR/NAME-YYYYMMDD.scan.json), not inside it.
#      With "wheel_test" in .publish/scan.json the scan also builds the wheel
#      from a clone of the snapshot and runs the wheel install test on it; it
#      needs pip, pytest and the network (the pinned build backend).
#
# Options:
#   --ref REF          commit to export (default HEAD)
#   --author "N <e>"   author and committer of the one commit
#   --message MSG      commit message (default "Initial public release")
#   --exclude GLOB     extra path to leave out (repeatable; `dir/` = whole folder)
#   --env-file FILE    .env with real keys for the hash-only key check
#                      (repeatable; default: the .env of this script's main
#                      checkout and ~/.semgate/.env when they exist)
#   --private-dir DIR  held-out cases to look for (default: evals/private of
#                      this script's main checkout)
#   --agpl-data DIR    local L1B3RT4S / AgentTrust data (default: evals/data of
#                      this script's main checkout)
#   --date YYYYMMDD    folder date (default: today, local time)
#   --replace          delete and rebuild DIR/NAME-DATE if this script made it
#   --no-scan          only build the snapshot
#
# Python: $PYTHON, else the .venv of this script's main checkout (it has
# pytest), else python3 / python / py.
#
# The name is a parameter so the product name can change without editing
# this script. The script never reads .env itself; publish_scan.py reads the
# key values inside its own process and prints only "found" / "not found".
set -euo pipefail

usage() { sed -n '2,38p' "$0"; exit 2; }

REPO="" NAME="" OUT="" REF="HEAD" AUTHOR="Manuel Parra <th3nolo@gmail.com>"
MESSAGE="Initial public release" DATE="$(date +%Y%m%d)" REPLACE=0 SCAN=1
EXCLUDES=() ENV_FILES=() PRIVATE_DIR="" AGPL_DATA=""
while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="$2"; shift 2 ;;
    --name) NAME="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --ref) REF="$2"; shift 2 ;;
    --author) AUTHOR="$2"; shift 2 ;;
    --message) MESSAGE="$2"; shift 2 ;;
    --exclude) EXCLUDES+=("$2"); shift 2 ;;
    --env-file) ENV_FILES+=("$2"); shift 2 ;;
    --private-dir) PRIVATE_DIR="$2"; shift 2 ;;
    --agpl-data) AGPL_DATA="$2"; shift 2 ;;
    --date) DATE="$2"; shift 2 ;;
    --replace) REPLACE=1; shift ;;
    --no-scan) SCAN=0; shift ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done
[ -n "$REPO" ] && [ -n "$NAME" ] && [ -n "$OUT" ] || usage
case "$NAME" in *[!A-Za-z0-9._-]*|"") echo "name must be [A-Za-z0-9._-]: $NAME" >&2; exit 2 ;; esac
case "$AUTHOR" in *" <"*@*">") ;; *) echo "author must look like 'Name <email>': $AUTHOR" >&2; exit 2 ;; esac

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOL_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# main checkout of the repo that holds this script (worktrees share it)
TOOL_MAIN="$(cd "$(git -C "$TOOL_ROOT" rev-parse --path-format=absolute --git-common-dir)/.." && pwd)"
PY="${PYTHON:-}"
if [ -z "$PY" ]; then
  for c in "$TOOL_MAIN/.venv/Scripts/python.exe" "$TOOL_MAIN/.venv/bin/python" python3 python py; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -c "import sys; sys.exit(sys.version_info < (3, 10))" 2>/dev/null; then PY="$c"; break; fi
  done
fi
[ -n "$PY" ] || { echo "need Python 3.10+" >&2; exit 2; }

REPO="$(cd "$REPO" && git rev-parse --show-toplevel)"
COMMIT="$(git -C "$REPO" rev-parse --verify "$REF^{commit}")"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
DEST="$OUT/$NAME-$DATE"
MARK=".git/public-snapshot-source"

if [ -e "$DEST" ]; then
  if [ "$REPLACE" = 1 ] && [ -f "$DEST/$MARK" ] && [ -z "$(git -C "$DEST" remote)" ]; then
    echo "replacing $DEST (made by this script, no remote)"
    rm -rf -- "$DEST"
  else
    echo "refusing: $DEST exists (use --replace only for a folder this script made)" >&2
    exit 2
  fi
fi

# exclude list: the commit's .publish/exclude.txt + --exclude; .publish/ itself is always left out
PATTERNS=(".publish/")
if git -C "$REPO" cat-file -e "$COMMIT:.publish/exclude.txt" 2>/dev/null; then
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    line="$(printf '%s' "$line" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    case "$line" in ""|\#*) continue ;; esac
    PATTERNS+=("$line")
  done < <(git -C "$REPO" show "$COMMIT:.publish/exclude.txt")
fi
PATTERNS+=("${EXCLUDES[@]+"${EXCLUDES[@]}"}")
PATHSPECS=(".")
SCAN_EXCLUDES=()
for p in "${PATTERNS[@]}"; do
  [ -n "$p" ] || continue
  g="$p"; case "$g" in */) g="${g}**" ;; esac
  PATHSPECS+=(":(exclude,glob)$g")
  SCAN_EXCLUDES+=(--exclude "$p")
done

echo "source:  $REPO @ ${COMMIT:0:12} ($REF)"
echo "name:    $NAME"
echo "output:  $DEST"
echo "author:  $AUTHOR"
echo "exclude: ${PATTERNS[*]}"

TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT
git -C "$REPO" -c core.autocrlf=false archive --format=tar -o "$TMP/tree.tar" "$COMMIT" -- "${PATHSPECS[@]}"
mkdir -p "$DEST"
tar -xf "$TMP/tree.tar" -C "$DEST"

NAME_PART="${AUTHOR% <*}"
EMAIL_PART="${AUTHOR##*<}"; EMAIL_PART="${EMAIL_PART%>}"
git -C "$DEST" init -q -b main
git -C "$DEST" config core.autocrlf false
git -C "$DEST" config user.name "$NAME_PART"
git -C "$DEST" config user.email "$EMAIL_PART"
git -C "$DEST" add -A --force   # every extracted file is wanted, even if the tree's own .gitignore matches it
# copy executable bits and symlink modes from the source commit (Windows checkouts lose them)
git -C "$REPO" ls-tree -r -z "$COMMIT" | while IFS= read -r -d '' ent; do
  mode="${ent%% *}"; path="${ent#*$'\t'}"
  if [ "$mode" = 100755 ] && [ -f "$DEST/$path" ]; then
    git -C "$DEST" update-index --chmod=+x -- "$path"
  fi
done
GIT_AUTHOR_NAME="$NAME_PART" GIT_AUTHOR_EMAIL="$EMAIL_PART" \
GIT_COMMITTER_NAME="$NAME_PART" GIT_COMMITTER_EMAIL="$EMAIL_PART" \
  git -C "$DEST" commit -q -m "$MESSAGE"
printf '%s %s %s\n' "$COMMIT" "$REF" "$REPO" > "$DEST/$MARK"
echo "commit:  $(git -C "$DEST" log -1 --format='%h %an <%ae> %s')"
echo "files:   $(git -C "$DEST" ls-files | wc -l | tr -d ' ')"

[ "$SCAN" = 1 ] || exit 0

if [ ${#ENV_FILES[@]} -eq 0 ]; then
  for f in "$TOOL_MAIN/.env" "$HOME/.semgate/.env"; do [ -f "$f" ] && ENV_FILES+=("$f"); done
fi
[ -n "$PRIVATE_DIR" ] || PRIVATE_DIR="$TOOL_MAIN/evals/private"
[ -n "$AGPL_DATA" ] || AGPL_DATA="$TOOL_MAIN/evals/data"
ENV_ARGS=()
for f in "${ENV_FILES[@]+"${ENV_FILES[@]}"}"; do ENV_ARGS+=(--env-file "$f"); done

"$PY" "$SCRIPT_DIR/publish_scan.py" \
  --snapshot "$DEST" --source-repo "$REPO" --source-commit "$COMMIT" --author "$AUTHOR" \
  --secretfinder-root "$TOOL_ROOT" --private-dir "$PRIVATE_DIR" --agpl-data "$AGPL_DATA" \
  --report "$OUT/$NAME-$DATE.scan.json" \
  "${SCAN_EXCLUDES[@]+"${SCAN_EXCLUDES[@]}"}" "${ENV_ARGS[@]+"${ENV_ARGS[@]}"}"
