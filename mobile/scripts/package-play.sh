#!/bin/sh
# Produces a signed AAB for manual Play internal-track upload. Secrets remain external.
set -eu
KV_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
: "${KV_ANDROID_KEYSTORE:?External keystore path is required}"
: "${KV_ANDROID_STORE_PASSWORD:?Keystore password is required}"
: "${KV_ANDROID_KEY_ALIAS:?Signing alias is required}"
: "${KV_ANDROID_KEY_PASSWORD:?Key password is required}"
export KV_NATIVE_PROFILE=release
"$KV_ROOT/mobile/scripts/build-native.sh" android
cd "$KV_ROOT/mobile"
flutter pub get
flutter analyze
flutter test
flutter build appbundle --release --target-platform android-arm64
mkdir -p dist/play-internal
cp build/app/outputs/bundle/release/*.aab dist/play-internal/
