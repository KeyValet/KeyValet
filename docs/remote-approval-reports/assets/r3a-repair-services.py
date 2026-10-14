#!/usr/bin/env python3
"""Finish launchd startup after the stopped, hung helper has actually exited."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import time

if os.geteuid() != 0:
    raise SystemExit('Run in the owner sudo terminal')
os.umask(0o077)
assets = Path('/Users/guang/dev/keyvalet/docs/remote-approval-reports/assets')
bin_dir = Path('/usr/local/lib/keyvalet/bin')
units = {'system/dev.keyvalet.helper': '/Library/LaunchDaemons/dev.keyvalet.helper.plist',
         'gui/501/dev.keyvalet.agent': '/Library/LaunchAgents/dev.keyvalet.agent.plist',
         'gui/501/dev.keyvalet.relay': '/Library/LaunchAgents/dev.keyvalet.relay.plist'}
receipt = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'touch_id_requests': 0, 'bootstrap': {}, 'probes': [], 'before': {}, 'after': {}}
backup = sorted(Path('/private/var/backups').glob('keyvalet-r3a-*'))[-1]
archive = backup / 'state-and-install.tar'
receipt['backup'] = str(backup)
receipt['backup_sha256'] = hashlib.sha256(archive.read_bytes()).hexdigest()
signed = json.loads((assets / 'r3a-signed-build.json').read_text())['binaries']
with tarfile.open(archive) as tar:
    for name in signed:
        old = tar.extractfile('usr/local/lib/keyvalet/bin/' + name)
        receipt['before'][name] = hashlib.sha256(old.read()).hexdigest()
        receipt['after'][name] = hashlib.sha256((bin_dir / name).read_bytes()).hexdigest()
        if receipt['after'][name] != signed[name]['sha256']:
            raise SystemExit('Installed checksum verification failed')
for domain, plist in units.items():
    loaded = subprocess.run(['/bin/launchctl', 'print', domain], capture_output=True, text=True)
    if loaded.returncode == 0:
        continue
    target = 'system' if domain.startswith('system/') else 'gui/501'
    p = subprocess.run(['/bin/launchctl', 'bootstrap', target, plist], capture_output=True, text=True)
    receipt['bootstrap'][domain] = {'exit': p.returncode, 'error': p.stderr[:300]}
    if p.returncode:
        out = assets / 'r3a-service-repair-failure.json'
        out.write_text(json.dumps(receipt, indent=2) + '\n')
        os.chown(out, 501, 20)
        raise SystemExit('Service bootstrap still failed; fixed diagnostics saved')
time.sleep(2)
receipt['services_after'] = {}
for domain in units:
    p = subprocess.run(['/bin/launchctl', 'print', domain], capture_output=True, text=True)
    pid = re.search(r'\n\s*pid = (\d+)', p.stdout)
    receipt['services_after'][domain] = {'exit': p.returncode, 'pid': int(pid[1]) if pid else None,
                                       'running': bool(re.search(r'\n\s*state = running', p.stdout))}
for args in [['devices', 'list']] * 5 + [['status']]:
    start = time.monotonic()
    p = subprocess.run([str(bin_dir / 'kv-cli'), '--lang', 'en', *args, '--json'],
                       capture_output=True, text=True, timeout=30)
    try:
        value = json.loads(p.stdout)
    except ValueError:
        value = {}
    result = value.get('result', {})
    receipt['probes'].append({'command': args, 'exit': p.returncode,
                              'elapsed_s': round(time.monotonic() - start, 6), 'ok': value.get('ok') is True,
                              'error_code': value.get('error', {}).get('code'),
                              'device_count': len(result.get('devices', [])),
                              'state': {k: result[k] for k in ('relay_connected', 'mode', 'presence') if k in result}})
receipt['owner_ipc_ok'] = all(p['exit'] == 0 and p['ok'] for p in receipt['probes'][:5])
receipt['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
out = assets / 'r3a-native-install.json'
out.write_text(json.dumps(receipt, indent=2) + '\n')
os.chown(out, 501, 20)
os.chmod(out, 0o600)
print('Three launchd services restored. Owner IPC:', receipt['owner_ipc_ok'])
