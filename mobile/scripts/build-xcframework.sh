#!/bin/sh
set -eu
KV_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
"$KV_ROOT/mobile/scripts/build-native.sh" ios
"$KV_ROOT/mobile/scripts/build-native.sh" ios-sim
KV_OUTPUT="$KV_ROOT/mobile/native/KvMobileCore.xcframework"
python3 - "$KV_OUTPUT" <<'PYTHON'
from pathlib import Path
import shutil
import sys
output = Path(sys.argv[1])
assert output.name == 'KvMobileCore.xcframework' and output.parent.name == 'native' and not output.is_symlink()
if output.is_dir():
    shutil.rmtree(output)
PYTHON
xcodebuild -create-xcframework -library "$KV_ROOT/mobile/native/ios/libkv_mobile_core.a" \
  -headers "$KV_ROOT/mobile/packages/kv_native/ios/Classes/Generated" \
  -library "$KV_ROOT/mobile/native/ios-sim/libkv_mobile_core.a" \
  -headers "$KV_ROOT/mobile/packages/kv_native/ios/Classes/Generated" -output "$KV_OUTPUT"
ln -sfn ../../../native/KvMobileCore.xcframework "$KV_ROOT/mobile/packages/kv_native/ios/KvMobileCore.xcframework"
