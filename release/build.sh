#!/bin/sh
# Build the ghidra-lx-loader extension inside Docker and copy the .zip to ./dist.
set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_DIR=$(cd "$SCRIPT_DIR/.." && pwd)

IMAGE="${IMAGE:-ghidra-lx-loader-build}"
OUT_DIR="${OUT_DIR:-$REPO_DIR/dist}"

docker build -t "$IMAGE" -f "$SCRIPT_DIR/Dockerfile" "$@" "$REPO_DIR"

mkdir -p "$OUT_DIR"
CID=$(docker create "$IMAGE")
trap 'docker rm -f "$CID" >/dev/null' EXIT
docker cp "$CID:/build/ghidra-lx-loader/dist/." "$OUT_DIR/"

ls -l "$OUT_DIR"
