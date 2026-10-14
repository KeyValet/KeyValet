"""Four required checks, current sources, existing isolated target directory."""
import datetime
import argparse
import json
import os
import pathlib
import shutil
import subprocess
import time

ROOT = pathlib.Path('/Users/guang/dev/keyvalet')
ASSETS = ROOT / 'docs/remote-approval-reports/assets'
ENV = dict(os.environ, CARGO_TARGET_DIR=str(ROOT / 'rust/target-r2b'),
           CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0')
COMMANDS = [
    ['cargo', '+1.99.0', 'fmt', '--all', '--', '--check'],
    ['cargo', '+1.99.0', 'clippy', '--workspace', '--all-targets', '--', '-D', 'warnings'],
    ['cargo', '+1.99.0', 'build', '--workspace', '--locked'],
    ['cargo', '+1.99.0', 'test', '--workspace', '--locked'],
]
results = []
parser = argparse.ArgumentParser()
parser.add_argument('--prefix', default='r3b-unsigned-mac-ci')
options = parser.parse_args()
for index, command in enumerate(COMMANDS, 1):
    if shutil.disk_usage(ROOT).free < 15 * 1024**3:
        raise SystemExit('free space below 15 GiB; no build/cache/backups removed')
    name = f'{options.prefix}-{index}.log'
    started = time.monotonic()
    with (ASSETS / name).open('w') as output:
        result = subprocess.run(command, cwd=ROOT / 'rust', env=ENV, stdout=output,
                                stderr=subprocess.STDOUT)
    row = {'command': ' '.join(command), 'exit_code': result.returncode,
           'seconds': time.monotonic() - started, 'log': name}
    results.append(row)
    (ASSETS / f'{options.prefix}.json').write_text(json.dumps({
        'passed': len(results) == 4 and all(row['exit_code'] == 0 for row in results),
        'commands': results, 'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }, indent=2) + '\n')
    print(json.dumps(row), flush=True)
    if result.returncode:
        raise SystemExit(result.returncode)
