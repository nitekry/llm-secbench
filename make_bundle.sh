#!/usr/bin/env bash
# Package the repo for sharing:
#   1. run the offline self-tests
#   2. write a git bundle (full history)          -> $BUNDLE  (default ~/llm-secbench.bundle)
#   3. copy the repo as a clean git checkout      -> $DEST/llm-secbench (default ~/Documents/github)
#      (first run clones; later runs fast-forward the existing copy)
# Only committed work is included: commit first.
#
#   bash make_bundle.sh
#   DEST=/some/dir BUNDLE=/tmp/x.bundle bash make_bundle.sh
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
NAME=llm-secbench
DEST=${DEST:-$HOME/Documents/github}
BUNDLE=${BUNDLE:-$HOME/$NAME.bundle}
COPY="$DEST/$NAME"
cd "$SRC"

if [ -n "$(git status --porcelain)" ]; then
  echo "warning: uncommitted changes are NOT included:" >&2
  git status --short >&2
fi

echo "== self-tests"
python3 -m unittest discover -s tests 2>&1 | tail -1
find . -name __pycache__ -type d -prune -exec rm -rf {} +

echo "== bundle -> $BUNDLE"
git bundle create "$BUNDLE" --all
git bundle verify -q "$BUNDLE"

echo "== copy -> $COPY"
mkdir -p "$DEST"
if [ -d "$COPY/.git" ]; then
  git -C "$COPY" pull -q --ff-only "$SRC" main
elif [ -e "$COPY" ]; then
  echo "error: $COPY exists and is not a git repo; move it away first" >&2
  exit 1
else
  git clone -q "$SRC" "$COPY"
fi

echo "== done: $(git log -1 --format='%h %s')"
echo "   bundle: $BUNDLE ($(du -h "$BUNDLE" | cut -f1))"
echo "   copy:   $COPY ($(git -C "$COPY" log -1 --format=%h))"
