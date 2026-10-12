#!/bin/sh
# Run from any directory. Keep all profiles and reports in the caller's isolated target directory.
set -eu

: "${CARGO_TARGET_DIR:?Set CARGO_TARGET_DIR to an absolute isolated build directory}"
KV_RELAY_TOOLCHAIN="${KV_RELAY_TOOLCHAIN:-stable}"
KV_RELAY_CRATE_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$KV_RELAY_CRATE_DIR/../.."

KV_RELAY_FULL_FILTER='/src/tests[./]'
KV_RELAY_CI_FILTER='/src/tests[./]|/src/(main|process|windows)\.rs|/src/(platform|helper|queue)/native\.rs'

cargo "+$KV_RELAY_TOOLCHAIN" llvm-cov -p kv-relay-client --all-targets --locked \
    --ignore-filename-regex "$KV_RELAY_FULL_FILTER" \
    --json --output-path "$CARGO_TARGET_DIR/coverage-final-full.json"
cargo "+$KV_RELAY_TOOLCHAIN" llvm-cov report -p kv-relay-client \
    --ignore-filename-regex "$KV_RELAY_CI_FILTER" \
    --json --output-path "$CARGO_TARGET_DIR/coverage-final-ci.json" \
    --fail-under-lines 100 \
    --fail-under-functions 100 --fail-uncovered-lines 0
cargo "+$KV_RELAY_TOOLCHAIN" llvm-cov report -p kv-relay-client \
    --ignore-filename-regex "$KV_RELAY_FULL_FILTER" \
    --html --output-dir "$CARGO_TARGET_DIR/coverage-html"
