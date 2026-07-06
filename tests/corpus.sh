#!/bin/sh
# Corpus regression test: import each binary in tests/corpus/ with the
# built loader and compare the loader facts (chosen loader, memory blocks
# with content hashes, entry point) against the committed expectation
# file in tests/expect/<name>.expect.
#
# The binaries themselves are not committed (tests/corpus/ is gitignored);
# a binary that has an expectation file but is missing locally is reported
# as SKIP, so the suite still passes where the corpus is absent.
#
# Usage:
#   corpus.sh        verify every binary that has an expectation file
#   corpus.sh -u     (re-)record expectations for every corpus binary
#
# Required env:
#   GHIDRA_INSTALL_DIR   path to a Ghidra installation
#
# Builds the extension on demand if dist/*.zip is missing.
set -eu

: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
CORPUS_DIR="$SCRIPT_DIR/corpus"
EXPECT_DIR="$SCRIPT_DIR/expect"

UPDATE=0
if [ "${1:-}" = "-u" ]; then
    UPDATE=1
fi

if ! ls "$REPO_DIR/dist/"*.zip >/dev/null 2>&1; then
    echo "No dist/*.zip; building extension..."
    (cd "$REPO_DIR" && gradle --no-daemon buildExtension)
fi
EXT_ZIP=$(ls -t "$REPO_DIR/dist/"*.zip | head -1)
# The zip unpacks to the extension's directory, not the zip basename.
EXT_NAME=$(unzip -Z1 "$EXT_ZIP" | head -1 | cut -d/ -f1)

EXT_ROOT="$GHIDRA_INSTALL_DIR/Ghidra/Extensions"
EXT_DIR="$EXT_ROOT/$EXT_NAME"

cleanup() {
    rm -rf "$EXT_DIR"
}
trap cleanup EXIT

rm -rf "$EXT_DIR"
unzip -q "$EXT_ZIP" -d "$EXT_ROOT"

if [ "$UPDATE" -eq 1 ]; then
    mkdir -p "$EXPECT_DIR"
    set -- "$CORPUS_DIR"/*
else
    set -- "$EXPECT_DIR"/*.expect
fi

failures=0
total=0

for item do
    [ -f "$item" ] || continue

    if [ "$UPDATE" -eq 1 ]; then
        binary="$item"
        name=$(basename "$binary")
    else
        name=$(basename "$item" .expect)
        binary="$CORPUS_DIR/$name"
    fi
    expect="$EXPECT_DIR/$name.expect"

    total=$((total + 1))
    if [ ! -f "$binary" ]; then
        echo "corpus[$total] SKIP: $name — binary not in tests/corpus/"
        continue
    fi

    TMP_PROJ=$(mktemp -d)
    RESULT_FILE=$(mktemp)
    FACTS_FILE=$(mktemp)

    set +e
    LX_SMOKE_RESULT_FILE="$RESULT_FILE" \
    LX_SMOKE_FACTS_FILE="$FACTS_FILE" \
        "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" \
            "$TMP_PROJ" corpus \
            -import "$binary" \
            -noanalysis \
            -scriptPath "$SCRIPT_DIR" \
            -postScript SmokeAssertions.java \
            -deleteProject >/tmp/headless.log 2>&1
    rc=$?
    set -e

    status=$(head -n 1 "$RESULT_FILE" 2>/dev/null || true)
    if [ "$status" != "OK" ]; then
        echo "corpus[$total] FAIL: $name — import/assertions failed (rc=$rc)" >&2
        tail -n 20 /tmp/headless.log >&2
        failures=$((failures + 1))
    elif [ "$UPDATE" -eq 1 ]; then
        cp "$FACTS_FILE" "$expect"
        echo "corpus[$total] RECORDED: $name"
    elif diff -u "$expect" "$FACTS_FILE" >/tmp/corpus.diff 2>&1; then
        echo "corpus[$total] PASS: $name"
    else
        echo "corpus[$total] FAIL: $name — facts differ from tests/expect/$name.expect" >&2
        cat /tmp/corpus.diff >&2
        failures=$((failures + 1))
    fi

    rm -rf "$TMP_PROJ" "$RESULT_FILE" "$FACTS_FILE"
done

if [ "$failures" -gt 0 ]; then
    echo "$failures of $total corpus entries failed" >&2
    exit 1
fi
echo "all $total corpus entries processed"
