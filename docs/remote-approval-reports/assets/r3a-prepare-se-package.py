#!/usr/bin/env python3
"""Prepare the reviewed producer package; no service changes or approval requests."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

os.umask(0o077)
root = Path('/Users/guang/dev/keyvalet')
assets = root / 'docs/remote-approval-reports/assets'
ci = json.loads((assets / 'r3a-se-closure-final-ci-summary.json').read_text())
expected = json.loads((assets / 'r3a-se-closure-final-ci-source.json').read_text())['paths']
if ci.get('checks') != {'fmt': 0, 'clippy': 0, 'build': 0, 'test': 0} or not ci.get('source_unchanged_during_checks'):
    raise SystemExit('four_checks_not_ready')
if any(hashlib.sha256((root / name).read_bytes()).hexdigest() != digest for name, digest in expected.items()):
    raise SystemExit('source_changed_since_checks')
free = shutil.disk_usage(root).free
if free < 15 * 10**9:
    raise SystemExit('less_than_15_GB_free')
command = ['/usr/bin/env', 'CARGO_INCREMENTAL=0', 'CARGO_PROFILE_DEV_DEBUG=0',
           'CARGO_PROFILE_TEST_DEBUG=0', 'CARGO_TARGET_DIR=' + str(root / 'rust/target-r2a'),
           'cargo', '+1.99.0', 'build', '--release', '-p', 'kv-helper', '-p', 'kv-cli',
           '-p', 'kv-touchid', '--locked']
with (assets / 'r3a-se-release.log').open('w') as output:
    result = subprocess.run(command, cwd=root / 'rust', stdout=output, stderr=subprocess.STDOUT)
if result.returncode:
    raise SystemExit('release_build_failed')
stage = root / 'rust/target-r2a/r3a-se-staging/bin'
stage.mkdir(parents=True, exist_ok=True)
names = {'kv-helper': 'helper', 'kv-cli': 'cli', 'kv-touchid': 'touchid', 'kv-relay-client': 'relay-client'}
receipt = {'built_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'release_exit': 0, 'ci_evidence': 'r3a-se-closure-final-ci-summary.json',
           'source_unchanged_since_ci': True, 'new_agent_installed': False,
           'touch_id_requests': 0, 'secret_values_in_evidence': False, 'binaries': {}}
for name, identifier in names.items():
    rebuilt = name != 'kv-relay-client'
    source = root / 'rust/target-r2a/release' / name if rebuilt else Path('/usr/local/lib/keyvalet/bin') / name
    if source.is_symlink() or not source.is_file():
        raise SystemExit('package_source_invalid')
    destination = stage / name
    if destination.is_symlink():
        raise SystemExit('package_destination_invalid')
    shutil.copyfile(source, destination)
    os.chmod(destination, 0o755)
    if rebuilt:
        result = subprocess.run(['/usr/bin/codesign', '--force', '--sign',
                                 '2732BEDE1859B84EC72A8D90C2BAD6965B531093', '--options', 'runtime',
                                 '--timestamp', '--identifier', 'dev.keyvalet.' + identifier,
                                 str(destination)], capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise SystemExit('package_signing_failed')
    requirement = '=identifier "dev.keyvalet.' + identifier + '" and anchor apple generic and certificate leaf[subject.OU] = "PWCRJPY7YC"'
    verified = subprocess.run(['/usr/bin/codesign', '--verify', '--strict', '-R', requirement,
                               str(destination)], capture_output=True, text=True, timeout=15)
    if verified.returncode:
        raise SystemExit('strict_package_requirement_failed')
    receipt['binaries'][name] = {'sha256': hashlib.sha256(destination.read_bytes()).hexdigest(),
                                'bytes': destination.stat().st_size, 'identifier': 'dev.keyvalet.' + identifier,
                                'team': 'PWCRJPY7YC', 'strict_requirement_exit': 0,
                                'reused_installed': not rebuilt}
if any(hashlib.sha256((root / name).read_bytes()).hexdigest() != digest for name, digest in expected.items()):
    raise SystemExit('source_changed_during_package_build')
(assets / 'r3a-se-signed-build.json').write_text(json.dumps(receipt, indent=2) + '\n')
print('Producer package signed; four strict requirements verified. Not installed.', flush=True)
