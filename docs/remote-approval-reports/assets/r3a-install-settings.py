#!/usr/bin/env python3
"""Install the reviewed signed R3-A binaries; preserve vault/config and emit metadata only."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

ROOT = Path('/Users/guang/dev/keyvalet')
ASSETS = ROOT / 'docs/remote-approval-reports/assets'
STAGE = ROOT / 'rust/target-r2a/r3a-settings-staging/bin'
BIN = Path('/usr/local/lib/keyvalet/bin')
TEAM = 'PWCRJPY7YC'
NAMES = {'kv-helper': 'helper', 'kv-cli': 'cli',
         'kv-touchid': 'touchid', 'kv-relay-client': 'relay-client'}
PLISTS = {'system/dev.keyvalet.helper': Path('/Library/LaunchDaemons/dev.keyvalet.helper.plist'),
          'gui/501/dev.keyvalet.agent': Path('/Library/LaunchAgents/dev.keyvalet.agent.plist'),
          'gui/501/dev.keyvalet.relay': Path('/Library/LaunchAgents/dev.keyvalet.relay.plist')}

def run(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, timeout=60, **kw)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def service(domain):
    p = run(['/bin/launchctl', 'print', domain])
    pid = re.search(r'\n\s*pid = (\d+)', p.stdout)
    return {'exit': p.returncode, 'pid': int(pid[1]) if pid else None,
            'running': bool(re.search(r'\n\s*state = running', p.stdout))}

def probe(args):
    start = time.monotonic()
    p = run([str(BIN / 'kv-cli'), '--lang', 'en', *args, '--json'])
    try:
        value = json.loads(p.stdout)
    except ValueError:
        value = {}
    result = value.get('result', {})
    return {'command': args, 'exit': p.returncode,
            'elapsed_s': round(time.monotonic() - start, 6),
            'ok': value.get('ok') is True,
            'error_code': value.get('error', {}).get('code'),
            'device_count': len(result['devices']) if 'devices' in result else None,
            'state': {k: result[k] for k in ('relay_connected', 'mode', 'presence') if k in result}}

if os.geteuid() != 0:
    raise SystemExit('Run in the owner sudo terminal')
os.umask(0o077)
receipt = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'touch_id_requests': 0, 'before': {}, 'after': {}, 'probes': []}
expected = json.loads((ASSETS / 'r3a-settings-signed-build.json').read_text())['binaries']
for name, ident in NAMES.items():
    source = STAGE / name
    if not source.is_file() or source.is_symlink() or sha(source) != expected[name]['sha256']:
        raise SystemExit('Stage checksum/type verification failed')
    requirement = f'identifier "dev.keyvalet.{ident}" and anchor apple generic and certificate leaf[subject.OU] = "{TEAM}"'
    if run(['/usr/bin/codesign', '--verify', '--strict', '-R', '=' + requirement, str(source)]).returncode:
        raise SystemExit('Stage signature verification failed')
    receipt['before'][name] = sha(BIN / name)
for domain, path in PLISTS.items():
    if not path.is_file() or path.is_symlink():
        raise SystemExit('Installed service plist verification failed')

backup = Path('/private/var/backups') / ('keyvalet-r3a-settings-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
backup.mkdir(mode=0o700)
receipt['backup'] = str(backup)
archive = backup / 'state-and-install.tar'
p = run(['/usr/bin/tar', '-cpf', str(archive), '-C', '/',
         'usr/local/lib/keyvalet', 'var/db/keyvalet',
         *[str(path).lstrip('/') for path in PLISTS.values()]])
if p.returncode:
    raise SystemExit('Backup failed; nothing installed')
receipt['backup_sha256'] = sha(archive)
receipt['services_before'] = {domain: service(domain) for domain in PLISTS}
for domain in reversed(PLISTS):
    p = run(['/bin/launchctl', 'bootout', domain])
    if p.returncode:
        raise SystemExit('Service stop failed; nothing installed')
# bootout returns before a hung job receives launchd's eventual SIGKILL. Do not
# bootstrap a replacement while launchd is still removing that job.
stop_deadline = time.monotonic() + 15
for before in receipt['services_before'].values():
    pid = before['pid']
    while pid and time.monotonic() < stop_deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        if pid:
            raise SystemExit('Prior service did not finish stopping; nothing installed')
for name in NAMES:
    dest = BIN / name
    if not dest.is_file() or dest.is_symlink():
        raise SystemExit('Installed binary type verification failed')
    temporary = BIN / ('.' + name + '.r3a-new')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
    with os.fdopen(fd, 'wb') as output:
        output.write((STAGE / name).read_bytes())
        output.flush()
        os.fsync(output.fileno())
        os.fchown(output.fileno(), 0, 0)
        os.fchmod(output.fileno(), 0o755)
    os.replace(temporary, dest)
    receipt['after'][name] = sha(dest)
for domain, path in PLISTS.items():
    target = 'system' if domain.startswith('system/') else 'gui/501'
    p = run(['/bin/launchctl', 'bootstrap', target, str(path)])
    if p.returncode:
        raise SystemExit('Service bootstrap failed; see the root-only backup')
time.sleep(2)
receipt['services_after'] = {domain: service(domain) for domain in PLISTS}
for _ in range(5):
    receipt['probes'].append(probe(['devices', 'list']))
receipt['probes'].append(probe(['status']))
receipt['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
receipt['owner_ipc_ok'] = all(p['exit'] == 0 and p['ok'] for p in receipt['probes'][:5])
out = ASSETS / ('r3a-settings-install-' + datetime.datetime.now(datetime.timezone.utc).strftime('%H%M%S') + '.json')
out.write_text(json.dumps(receipt, indent=2) + '\n')
os.chown(out, 501, 20)
os.chmod(out, 0o600)
print('Signed R3-A binaries installed; vault/config preserved. Owner IPC:', receipt['owner_ipc_ok'])
