#!/usr/bin/env python3
"""Run the required checks with a byte-accurate space guard and a source snapshot."""
import datetime
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path('/Users/guang/dev/keyvalet')
ASSETS = ROOT / 'docs/remote-approval-reports/assets'
STEM = 'r3a-se-closure-final-ci'
PREFIX = ['/usr/bin/env', 'CARGO_INCREMENTAL=0', 'CARGO_PROFILE_DEV_DEBUG=0',
          'CARGO_PROFILE_TEST_DEBUG=0', 'CARGO_TARGET_DIR=' + str(ROOT / 'rust/target-r2a'),
          'cargo', '+1.99.0']


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def snapshot():
    paths = [path for path in (ROOT / 'rust/crates').rglob('*')
             if path.is_file() and path.suffix in ('.rs', '.toml', '.sql', '.json', '.swift')]
    paths.extend([ROOT / 'rust/Cargo.toml', ROOT / 'rust/Cargo.lock'])
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(paths)}


baseline = json.loads((ASSETS / 'r3a-se-closure-ci2-summary.json').read_text())
previous = json.loads((ASSETS / 'r3a-se-closure-ci2-source.json').read_text())['paths']
before = snapshot()
if baseline.get('checks') != {'fmt': 0, 'clippy': 0, 'build': 0} or before != previous:
    raise SystemExit('successful_three_checks_source_not_current')
receipt = {'started_utc': now(), 'rust': '1.99.0', 'checks': dict(baseline['checks']), 'space_checks': [],
           'source_files': len(before), 'minimum_free_bytes': 15 * 10**9,
           'secret_values_in_evidence': False}
checks = [('fmt', ['fmt', '--all', '--', '--check']),
          ('clippy', ['clippy', '--workspace', '--all-targets', '--', '-D', 'warnings']),
          ('build', ['build', '--workspace', '--locked']),
          ('test', ['test', '--workspace', '--locked'])]
try:
    for name, arguments in checks:
        if name != 'test':
            continue
        free = shutil.disk_usage(ROOT).free
        receipt['space_checks'].append({'check': name, 'free_bytes': free})
        if free < receipt['minimum_free_bytes']:
            receipt['stopped_reason'] = 'less_than_15_GB_free'
            print('Space guard stopped before ' + name, flush=True)
            break
        path = ASSETS / (STEM + '-' + name + '.log')
        with path.open('w') as output:
            process = subprocess.run(PREFIX + arguments, cwd=ROOT / 'rust',
                                     stdout=output, stderr=subprocess.STDOUT)
        receipt['checks'][name] = process.returncode
        print(name + ' exit ' + str(process.returncode), flush=True)
        if process.returncode:
            break
finally:
    after = snapshot()
    changed = sorted(path for path in before.keys() | after.keys()
                     if before.get(path) != after.get(path))
    receipt['source_unchanged_during_checks'] = not changed
    receipt['changed_source_files'] = changed
    if 'test' in receipt['checks']:
        output = (ASSETS / (STEM + '-test.log')).read_text()
        groups = re.findall(r'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', output)
        receipt.update({'passed': sum(int(group[0]) for group in groups),
                        'failed': sum(int(group[1]) for group in groups),
                        'ignored': sum(int(group[2]) for group in groups), 'groups': len(groups)})
    receipt['finished_utc'] = now()
    receipt['preceding_successful_checks'] = 'r3a-se-closure-ci2-summary.json'
    receipt['checks_evidence'] = {name: 'r3a-se-closure-ci2-' + name + '.log'
                                 for name in ('fmt', 'clippy', 'build')}
    receipt['checks_evidence']['test'] = STEM + '-test.log'
    (ASSETS / (STEM + '-summary.json')).write_text(json.dumps(receipt, indent=2) + '\n')
    (ASSETS / (STEM + '-source.json')).write_text(json.dumps({'observed_utc': now(), 'paths': after}, indent=2) + '\n')
if receipt['checks'] != {name: 0 for name, _ in checks} or changed:
    raise SystemExit(1)
