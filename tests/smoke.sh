#!/bin/sh
# Headless smoke test: import each binary in LX_TEST_BINARY with the built
# loader and assert the result looks sane (loader chosen, segments created,
# entry point disassembles).
#
# Required env:
#   LX_TEST_BINARY       colon-separated paths to LX/LE executables
#   GHIDRA_INSTALL_DIR   path to a Ghidra installation
#
# Builds the extension on demand if dist/*.zip is missing.
set -eu

: "${LX_TEST_BINARY:?set LX_TEST_BINARY to one or more LX/LE executables (colon-separated)}"
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_DIR=$(cd "$SCRIPT_DIR/.." && pwd)

if ! ls "$REPO_DIR/dist/"*.zip >/dev/null 2>&1; then
    echo "No dist/*.zip; building extension..."
    (cd "$REPO_DIR" && gradle --no-daemon buildExtension)
fi
EXT_ZIP=$(ls -t "$REPO_DIR/dist/"*.zip | head -1)
EXT_NAME=$(basename "$EXT_ZIP" .zip)

EXT_ROOT="$GHIDRA_INSTALL_DIR/Ghidra/Extensions"
EXT_DIR="$EXT_ROOT/$EXT_NAME"

cleanup() {
    rm -rf "$EXT_DIR"
}
trap cleanup EXIT

rm -rf "$EXT_DIR"
unzip -q "$EXT_ZIP" -d "$EXT_ROOT"

failures=0
total=0

IFS=:
for binary in $LX_TEST_BINARY; do
    unset IFS
    total=$((total + 1))
    if [ ! -f "$binary" ]; then
        echo "smoke[$total] FAIL: $binary not found" >&2
        failures=$((failures + 1))
        IFS=:
        continue
    fi

    TMP_PROJ=$(mktemp -d)
    RESULT_FILE=$(mktemp)

    set +e
    LX_SMOKE_RESULT_FILE="$RESULT_FILE" \
        "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" \
            "$TMP_PROJ" smoke \
            -import "$binary" \
            -scriptPath "$SCRIPT_DIR" \
            -postScript SmokeAssertions.java \
            -deleteProject >/tmp/headless.log 2>&1
    rc=$?
    set -e

    if [ ! -s "$RESULT_FILE" ]; then
        echo "smoke[$total] FAIL: $binary — assertion script did not run (rc=$rc)" >&2
        tail -n 20 /tmp/headless.log >&2
        failures=$((failures + 1))
    else
        status=$(head -n 1 "$RESULT_FILE")
        message=$(tail -n +2 "$RESULT_FILE")
        if [ "$status" = "OK" ]; then
            echo "smoke[$total] PASS: $binary — $message"
        else
            echo "smoke[$total] FAIL: $binary — $message" >&2
            failures=$((failures + 1))
        fi
    fi

    rm -rf "$TMP_PROJ" "$RESULT_FILE"
    IFS=:
done
unset IFS

if [ "$failures" -gt 0 ]; then
    echo "$failures of $total binaries failed" >&2
    exit 1
fi
echo "all $total binaries passed"
