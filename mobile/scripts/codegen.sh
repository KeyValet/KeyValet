#!/bin/sh
set -eu
KV_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
export CARGO_TARGET_DIR="$KV_ROOT/rust/target-w8"
export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
python3 "$KV_ROOT/mobile/scripts/prepare-workspace.py"
cd "$KV_ROOT/mobile"
export PATH="$KV_ROOT/mobile/scripts:$KV_ROOT/rust/target-w8/tooling:$PATH"
python3 - <<'PY'
from pathlib import Path
root = Path.cwd().parent
text = Path('flutter_rust_bridge.yaml').read_text().replace('../rust/', str(root / 'rust') + '/')
text = text.replace('dart_output: lib/src/rust', 'dart_output: ' + str(root / 'mobile/lib/src/rust'))
text = text.replace('dart_root: .', 'dart_root: ' + str(root / 'mobile'))
(root / 'rust/target-w8/codegen.yaml').write_text(text)
PY
flutter_rust_bridge_codegen generate --config-file "$KV_ROOT/rust/target-w8/codegen.yaml"
python3 scripts/generate-c-header.py
