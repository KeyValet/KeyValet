#!/bin/sh
set -eu

# Run from any directory. This measures every kv-server production module and the CLI.
relay_workspace=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
cd "$relay_workspace"
export CARGO_TARGET_DIR="$relay_workspace/target-w2"
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
relay_toolchain=${KV_RELAY_TOOLCHAIN:-1.99.0}
relay_coverage="$CARGO_TARGET_DIR/coverage"
mkdir -p "$relay_coverage"
# Exclude test source and other crates, including dependencies compiled by kv-core.
relay_ignore='(/kv-server/src/(tests\.rs$|tests/|unit_tests/)|/kv-server/tests/|/crates/(kv-core|kv-platform|kv-i18n|kv-protocols|kv-proxy|kv-vault|kv-ipc)/)'

cargo "+$relay_toolchain" llvm-cov -p kv-server --locked --no-cfg-coverage \
    --fail-under-lines 100 --fail-under-functions 100 --fail-under-regions 100 \
    --json --output-path "$relay_coverage/coverage.json" \
    --ignore-filename-regex "$relay_ignore" "$@"
# cargo-llvm-cov 0.9.1's per-file gate uses > rather than >=. Check exact counts
# instead, and require all production files so an exclusion cannot mask a module.
python3 - "$relay_coverage/coverage.json" <<'PY'
import json
import sys
from pathlib import Path

root = Path("crates/kv-server/src").resolve()
expected = {
    path.resolve()
    for path in root.rglob("*.rs")
    if path.name != "tests.rs" and not ({"tests", "unit_tests"} & set(path.relative_to(root).parts))
}
report = json.loads(Path(sys.argv[1]).read_text())["data"][0]
observed = {Path(file["filename"]).resolve() for file in report["files"]}
if observed != expected:
    raise SystemExit(f"Coverage source mismatch: missing {expected - observed}, extra {observed - expected}")
for file in report["files"]:
    for metric in ("lines", "functions", "regions"):
        summary = file["summary"][metric]
        if summary["count"] != summary["covered"]:
            raise SystemExit(f"Incomplete {metric} coverage: {file['filename']} {summary}")
print(f"Verified 100% line, function and region coverage in all {len(expected)} production files.")
PY
cargo "+$relay_toolchain" llvm-cov report -p kv-server --html \
    --output-dir "$relay_coverage" --ignore-filename-regex "$relay_ignore"
cargo "+$relay_toolchain" llvm-cov report -p kv-server --show-missing-lines \
    --ignore-filename-regex "$relay_ignore" > "$relay_coverage/summary.txt"
cat "$relay_coverage/summary.txt"
