#!/usr/bin/env python3
"""Drop only W8's regenerable host cache; preserve logs, native libraries and other workflows."""
from pathlib import Path
import shutil
import sys

root = Path(__file__).resolve().parents[2]
target = root / 'rust/target-w8'
names = ['aarch64-apple-ios', 'aarch64-apple-ios-sim', 'aarch64-linux-android'] if '--native' in sys.argv else ['debug']
assert target.is_dir() and (target / 'verification/Cargo.lock').is_file()
for name in names:
    cache = target / name
    assert cache.parent.resolve() == target.resolve() and not cache.is_symlink()
    if cache.is_dir():
        shutil.rmtree(cache)
