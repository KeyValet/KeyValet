#!/bin/sh
# Run from any directory. cargo-llvm-cov and llvm-tools-preview are tooling prerequisites.
set -eu
task_script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
task_rust_dir=$(CDPATH= cd -- "$task_script_dir/../../.." && pwd)
cd "$task_rust_dir"
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-"$task_rust_dir/target-w7"}
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
mkdir -p "$CARGO_TARGET_DIR"
cargo +1.99.0 llvm-cov -p kv-cli --locked --no-cfg-coverage --json \
    --output-path "$CARGO_TARGET_DIR/coverage.json"
python3 "$task_script_dir/check-w7-coverage.py" "$CARGO_TARGET_DIR/coverage.json"
