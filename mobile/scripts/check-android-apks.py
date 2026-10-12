#!/usr/bin/env python3
"""Check actual APK target SDKs, including standalone native instrumentation packages."""
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('apks', nargs='+', type=Path)
    arguments = parser.parse_args()
    sdk = Path(os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT')
               or str(Path.home() / 'Library/Android/sdk'))
    executable = os.environ.get('AAPT2') or shutil.which('aapt2')
    if not executable:
        candidates = sorted(
            (sdk / 'build-tools').glob('*/aapt2'),
            key=lambda path: tuple(int(n) for n in re.findall(r'\d+', path.parent.name)),
        )
        if candidates:
            executable = str(candidates[-1])
    if not executable:
        parser.error('Set ANDROID_HOME or AAPT2 to an installed Android SDK toolchain')
    reader = os.environ.get('LLVM_READELF') or shutil.which('llvm-readelf')
    if not reader:
        readers = sorted((sdk / 'ndk').glob('*/toolchains/llvm/prebuilt/*/bin/llvm-readelf'))
        if readers:
            reader = str(readers[-1])
    if not reader:
        parser.error('Set ANDROID_HOME or LLVM_READELF to an installed Android NDK toolchain')
    failed = False
    for apk in arguments.apks:
        result = subprocess.run([executable, 'dump', 'badging', str(apk)],
                                text=True, capture_output=True, check=True)
        package = re.search(r"^package: name='([^']+)'", result.stdout, re.MULTILINE)
        target = re.search(r"^targetSdkVersion:'(\d+)'", result.stdout, re.MULTILINE)
        if not package or not target:
            print(f'{apk}: missing explicit package or target SDK metadata', file=sys.stderr)
            failed = True
            continue
        api = int(target.group(1))
        print(f'{apk}: {package.group(1)}, targetSdk={api}')
        if api < 36:
            print(f'{apk}: targetSdk must be at least 36 (Android 16)', file=sys.stderr)
            failed = True
        with zipfile.ZipFile(apk) as archive:
            bridges = [name for name in archive.namelist()
                       if re.fullmatch(r'lib/[^/]+/libkv_native\.so', name)]
            if not bridges:
                print(f'{apk}: missing native JNI bridge', file=sys.stderr)
                failed = True
            for bridge in bridges:
                with tempfile.NamedTemporaryFile(suffix='.so') as binary:
                    binary.write(archive.read(bridge))
                    binary.flush()
                    dynamic = subprocess.run([reader, '-d', binary.name],
                                             text=True, capture_output=True, check=True).stdout
                needed = re.findall(r'\(NEEDED\).*\[([^\]]+)\]', dynamic)
                if any('/' in name for name in needed) or 'libkv_mobile_core.so' not in needed:
                    print(f'{apk}: {bridge} has non-portable native dependencies: {needed}',
                          file=sys.stderr)
                    failed = True
                elif str(Path(bridge).parent / 'libkv_mobile_core.so') not in archive.namelist():
                    print(f'{apk}: missing Rust library for {bridge}', file=sys.stderr)
                    failed = True
                else:
                    print(f'{apk}: {bridge} loads bundled libkv_mobile_core.so by name')
    return int(failed)


if __name__ == '__main__':
    sys.exit(main())
