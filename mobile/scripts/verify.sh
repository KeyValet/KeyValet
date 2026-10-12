#!/bin/sh
set -eu
KV_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$KV_ROOT/rust/target-r2c}"
export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
cd "$KV_ROOT/rust"
cargo +1.99.0 fmt -p kv-mobile-core -p kv-push -- --check
cargo +1.99.0 clippy -p kv-mobile-core -p kv-push --locked --all-targets -- -D warnings
cargo +1.99.0 build -p kv-mobile-core -p kv-push --locked
cargo +1.99.0 test -p kv-mobile-core -p kv-push --locked
cd "$KV_ROOT/mobile"
flutter analyze
flutter test
