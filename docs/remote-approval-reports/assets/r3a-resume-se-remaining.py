#!/usr/bin/env python3
"""Attended continuation after verified installation; no installation or dialog retry."""
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import datetime

ASSETS = Path(__file__).resolve().parent
REPO = ASSETS.parents[2]


def main():
    if os.getuid() != 501:
        raise SystemExit('run_as_mac_owner_without_sudo')
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    summary = json.loads((ASSETS / 'r3a-se-closure-final-ci-summary.json').read_text())
    if summary.get('checks') != {'fmt': 0, 'clippy': 0, 'build': 0, 'test': 0}:
        raise SystemExit('remaining_full_ci_not_green')
    source = json.loads((ASSETS / 'r3a-se-closure-final-ci-source.json').read_text())['paths']
    changed = [name for name, wanted in source.items()
               if not (REPO / name).is_file() or hashlib.sha256((REPO / name).read_bytes()).hexdigest() != wanted]
    manifest = json.loads((ASSETS / 'r3a-se-signed-build.json').read_text())['binaries']
    for name, row in manifest.items():
        path = Path('/usr/local/lib/keyvalet/bin') / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != row['sha256']:
            raise SystemExit('remaining_installed_package_mismatch')
        requirement = '=identifier "' + row['identifier'] + '" and anchor apple generic and certificate leaf[subject.OU] = "PWCRJPY7YC"'
        checked = subprocess.run(['/usr/bin/codesign', '--verify', '--strict', '-R', requirement, str(path)],
                                 stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
        if checked.returncode:
            raise SystemExit('remaining_installed_requirement_failed')
    (ASSETS / 'r3a-remaining-resume-package-check.json').write_text(json.dumps({
        'observed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'ci_evidence': 'r3a-se-closure-final-ci-summary.json',
        'native_package_matches_that_ci_build': True,
        'current_tree_changes_since_that_ci': changed,
        'strict_installed_requirements_passed': len(manifest),
        'installation_requests': 0, 'approval_started': False,
        'secret_values_in_evidence': False,
    }, ensure_ascii=False, indent=2) + '\n')
    print('已安装修复包的签名、哈希及其四项 CI 收据核对完成；不重装，先恢复真实在场信号。', flush=True)
    process = subprocess.run(['/usr/bin/python3', str(ASSETS / 'r3a-native-remaining.py'), '--refresh-presence'])
    raise SystemExit(process.returncode)


if __name__ == '__main__':
    main()
