# KeyValet mobile

Flutter renders Rust display types and submits intents. Hardware key operations are exclusively
native callbacks. The iOS notification extension and Android FCM/Quick services run native code
and Rust without a Dart background isolate. Google or Apple sign-in is required before
opening the control pages. The relay is fixed to https://relay.keyvalet.dev/; its
address is neither displayed nor configurable in the app. See [account setup](docs/account-login.md).

Run `scripts/codegen.sh` with flutter_rust_bridge_codegen 2.11.1 on PATH. Committed Dart output
is in `lib/src/rust/`; the native C ABI header is generated from `scripts/generate-c-header.py`
into `ios/KeyValetNSE/Generated/` and both plugin implementations. Native commands return the
same Rust view types. JSON commands cannot perform arbitrary signing or Strong decisions.

Run `scripts/verify.sh` against the main workspace and its shared lockfile. Code generation
uses `prepare-workspace.py` to inspect unchanged source through symlinks in an isolated
workspace under `rust/target-w8/verification/`; it never rewrites shared manifests or locks.

Run `scripts/build-xcframework.sh` before `flutter build ios --simulator` or device packaging.
The Xcode project includes a standalone `KeyValetNSE` target, App Group
`group.dev.keyvalet.mobile`, bundle IDs `dev.keyvalet.mobile` and
`dev.keyvalet.mobile.KeyValetNSE`, and team `PWCRJPY7YC`. Enable those capabilities in the
developer portal and supply both provisioning profiles. Release builds select `RunnerRelease.entitlements` with production App Attest/APNs.
Both release provisioning profiles must authorize the App Group and notification capabilities. Simulator deliberately has no software key fallback.

Run `scripts/build-native.sh android` before `flutter build apk --debug --target-platform android-arm64`.
Native builds default to debug; `KV_NATIVE_PROFILE=release` selects optimized Rust libraries.
Both store packaging scripts select release automatically.
Requires Android API 31+, NDK 28.2.13676358, strong biometrics and TEE/StrongBox on device.
The app and native instrumentation APK explicitly target API 36 (Android 16).
After building both, run `python3 scripts/check-android-apks.py build/app/outputs/flutter-apk/app-debug.apk build/kv_native/outputs/apk/androidTest/debug/kv_native-debug-androidTest.apk`.
This inspects packaged manifests and native ELF dependencies; compileSdk alone does not opt into current privacy behavior.
The checker also rejects compiler-host paths in the JNI bridge and verifies the Rust library is bundled.
Place an external Firebase project's `google-services.json` in `android/app/` to enable FCM;
the file is ignored. Without Firebase configuration the foreground relay still works.

`scripts/package-testflight.sh` requires `KV_IOS_EXPORT_OPTIONS` pointing to a real export
plist (see the placeholder example). `scripts/package-play.sh` requires an external keystore
and the four `KV_ANDROID_*` signing variables. Neither script uploads or publishes anything.

Physical signing-gate tests are `RunnerTests/StrongSigningGateTests.swift` and the plugin's
`StrongSigningGateTest.kt`. They directly invoke AK_s while skipping the UI. iOS Simulator
cannot test Secure Enclave; Android emulators normally cannot prove TEE/StrongBox protection.
Run on provisioned, biometric-enrolled devices. Software CI tests separately verify that failed
hardware signing cannot enqueue or consume a Strong decision.
The Android test class also boots Rust through JNI, hardware DK ECDH and encrypted SQLite,
so packaged native loader failures are caught before app smoke testing.
