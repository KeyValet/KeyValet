#!/bin/sh
# Produces an IPA for manual TestFlight upload. No account authentication or publication.
set -eu
KV_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
: "${KV_IOS_EXPORT_OPTIONS:?Path to a provisioned App Store export options plist is required}"
export KV_NATIVE_PROFILE=release
"$KV_ROOT/mobile/scripts/build-xcframework.sh"
cd "$KV_ROOT/mobile"
flutter pub get
flutter analyze
flutter test
flutter build ipa --release --export-options-plist="$KV_IOS_EXPORT_OPTIONS"
mkdir -p dist/testflight
cp build/ios/ipa/*.ipa dist/testflight/
