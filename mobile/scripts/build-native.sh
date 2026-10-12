#!/bin/sh
set -eu
KV_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$KV_ROOT/rust/target-r2c}"
export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
KV_MANIFEST="$KV_ROOT/rust/Cargo.toml"
KV_TOOLCHAIN=${KV_RUST_TOOLCHAIN:-1.99.0}
KV_PLATFORM=${1:-ios}
KV_PROFILE=${KV_NATIVE_PROFILE:-debug}
case "$KV_PROFILE" in
  debug) set -- ;;
  release) set -- --release ;;
  *) echo 'KV_NATIVE_PROFILE must be debug or release' >&2; exit 2 ;;
esac
case "$KV_PLATFORM" in
  ios|ios-sim)
    export IPHONEOS_DEPLOYMENT_TARGET=15.0
    if [ "$KV_PLATFORM" = ios ]; then KV_TARGET=aarch64-apple-ios; else KV_TARGET=aarch64-apple-ios-sim; fi
    cargo "+$KV_TOOLCHAIN" build --manifest-path "$KV_MANIFEST" -p kv-mobile-core -p kv-push --lib --locked "$@" --target "$KV_TARGET"
    mkdir -p "$KV_ROOT/mobile/native/$KV_PLATFORM"
    cp "$CARGO_TARGET_DIR/$KV_TARGET/$KV_PROFILE/libkv_mobile_core.a" "$KV_ROOT/mobile/native/$KV_PLATFORM/"
    ;;
  android)
    KV_NDK=${KV_ANDROID_NDK:-${ANDROID_HOME:-$HOME/Library/Android/sdk}/ndk/28.2.13676358}
    KV_BIN="$KV_NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin"
    export CC_aarch64_linux_android="$KV_BIN/aarch64-linux-android31-clang"
    export AR_aarch64_linux_android="$KV_BIN/llvm-ar"
    export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CC_aarch64_linux_android"
    cargo "+$KV_TOOLCHAIN" build --manifest-path "$KV_MANIFEST" -p kv-mobile-core -p kv-push --lib --locked "$@" --target aarch64-linux-android
    mkdir -p "$KV_ROOT/mobile/native/android/arm64-v8a"
    cp "$CARGO_TARGET_DIR/aarch64-linux-android/$KV_PROFILE/libkv_mobile_core.so" "$KV_ROOT/mobile/native/android/arm64-v8a/"
    ;;
  *) echo 'Usage: build-native.sh ios|ios-sim|android' >&2; exit 2 ;;
esac
