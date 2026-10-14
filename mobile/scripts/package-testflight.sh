#!/bin/sh
# Build and verify a distribution IPA. Upload is a separate explicit command.
set -eu
KV_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$KV_ROOT/mobile"
KV_HELPER=scripts/testflight-signing.mjs
KV_ARCHIVE=build/ios/archive/Runner.xcarchive
KV_APP="$KV_ARCHIVE/Products/Applications/Runner.app"
KV_READY=build/ios/keyvalet-testflight-ready.json
KV_SNAPSHOT=build/ios/keyvalet-testflight-source.json
KV_OPTIONS=${KV_IOS_EXPORT_OPTIONS:-ios/ExportOptions.example.plist}
case "${1:-build}" in
  build)
    KV_BUILD=${2:-1}
    case "$KV_BUILD" in ''|*[!0-9]*) echo 'Build number must be a positive integer' >&2; exit 2 ;; esac
    [ "$KV_BUILD" -gt 0 ] || exit 2
    mkdir -p build/ios
    node "$KV_HELPER" invalidate-build "$KV_READY"
    node "$KV_HELPER" credentials-check
    export KV_NATIVE_PROFILE=release
    "$KV_ROOT/mobile/scripts/build-xcframework.sh"
    flutter pub get
    flutter analyze --no-pub
    flutter test --no-pub
    flutter build ios --config-only --no-codesign --release --build-number="$KV_BUILD"
    mkdir -p build/ios dist/testflight
    node "$KV_HELPER" export-options "$KV_OPTIONS" build/ios/KeyValetExportOptions.plist export
    node "$KV_HELPER" snapshot "$KV_SNAPSHOT"
    node "$KV_HELPER" xcodebuild -workspace ios/Runner.xcworkspace -scheme Runner -configuration Release \
      -sdk iphoneos -destination 'generic/platform=iOS' -archivePath "$KV_ARCHIVE" archive \
      DEVELOPMENT_TEAM=PWCRJPY7YC CODE_SIGN_STYLE=Automatic CODE_SIGNING_ALLOWED=YES CODE_SIGNING_REQUIRED=YES
    node "$KV_HELPER" verify-app "$KV_APP" "$KV_BUILD"
    node "$KV_HELPER" xcodebuild -exportArchive -archivePath "$KV_ARCHIVE" \
      -exportOptionsPlist build/ios/KeyValetExportOptions.plist -exportPath build/ios/ipa
    set -- build/ios/ipa/*.ipa
    [ "$#" = 1 ] && [ -f "$1" ] || { echo 'Export did not produce exactly one IPA' >&2; exit 1; }
    node "$KV_HELPER" verify-ipa "$1" "$KV_APP"
    cp "$1" dist/testflight/KeyValet.ipa
    node "$KV_HELPER" seal-build dist/testflight/KeyValet.ipa "$KV_APP" "$KV_SNAPSHOT" "$KV_READY"
    echo "Verified IPA: dist/testflight/KeyValet.ipa (build $KV_BUILD). Not uploaded."
    ;;
  upload)
    node "$KV_HELPER" verify-build dist/testflight/KeyValet.ipa "$KV_APP" "$KV_READY"
    node "$KV_HELPER" verify-ipa dist/testflight/KeyValet.ipa "$KV_APP"
    node "$KV_HELPER" export-options "$KV_OPTIONS" build/ios/KeyValetUploadOptions.plist upload
    node "$KV_HELPER" xcodebuild -exportArchive -archivePath "$KV_ARCHIVE" \
      -exportOptionsPlist build/ios/KeyValetUploadOptions.plist -exportPath build/ios/upload
    ;;
  *) echo 'Usage: package-testflight.sh build [number] | upload' >&2; exit 2 ;;
esac
