#!/usr/bin/env python3
"""Archive only an unused, server-revoked remote singleton, then use normal pairing."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import sqlite3
import subprocess
import sys
import time

ROOT = Path('/Users/guang/dev/keyvalet')
ASSETS = ROOT / 'docs/remote-approval-reports/assets'
REMOTE = Path('/var/db/keyvalet/remote')
CLI = '/usr/local/lib/keyvalet/bin/kv-cli'
UNITS = {'system/dev.keyvalet.helper': '/Library/LaunchDaemons/dev.keyvalet.helper.plist',
         'gui/501/dev.keyvalet.agent': '/Library/LaunchAgents/dev.keyvalet.agent.plist',
         'gui/501/dev.keyvalet.relay': '/Library/LaunchAgents/dev.keyvalet.relay.plist'}
TABLES = ('pending_approvals', 'grants', 'issued_grants', 'issued_approvals',
          'issued_directives', 'directives', 'nonces', 'remote_outbox')

def run(args, timeout=30):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)

def counts():
    db = sqlite3.connect('file:' + str(REMOTE / 'approvals.sqlite3') + '?mode=ro', uri=True)
    try:
        return {name: db.execute('SELECT count(*) FROM ' + name).fetchone()[0] for name in TABLES}
    finally:
        db.close()

def save(receipt):
    path = ASSETS / 'r3a-fresh-approver.json'
    path.write_text(json.dumps(receipt, indent=2) + '\n')
    os.chown(path, 501, 20)
    os.chmod(path, 0o600)

if os.geteuid() != 0:
    raise SystemExit('Run in the owner sudo terminal')
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
os.umask(0o077)
if shutil.disk_usage(ROOT).free < 15_000_000_000:
    raise SystemExit('Less than 15 GB free; stopped')
proof_path = ASSETS / ('r3a-relay-tombstone-current.json' if '--current' in sys.argv else 'r3a-relay-tombstone.json')
proof = json.loads(proof_path.read_text())
OLD_ID = proof.get('device_id')
if not OLD_ID or not proof.get('revoked_utc') or not (proof.get('r2a_public_dk_matches') is True or proof.get('local_dk_matches') is True):
    raise SystemExit('Read-only tombstone evidence does not match the original device')
p = run([CLI, '--lang', 'en', 'devices', 'list', '--json'])
value = json.loads(p.stdout)
devices = value.get('result', {}).get('devices', [])
if p.returncode or len(devices) != 1 or devices[0].get('device_id') != OLD_ID or devices[0].get('os') != 'macos':
    raise SystemExit('Not the expected local singleton; nothing archived')
receipt = {'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'old_device_id': OLD_ID, 'server_revoked_utc': proof['revoked_utc'],
           'preflight_counts': counts(), 'old_server_tombstone_modified': False,
           'old_secure_enclave_keys_deleted': False}
if any(receipt['preflight_counts'].values()):
    save(receipt)
    raise SystemExit('Remote authority/history exists; nothing archived')
credential_file = Path('/var/db/keyvalet/vault.enc')
before = hashlib.sha256(credential_file.read_bytes()).hexdigest()
receipt['credential_vault_sha256_before'] = before
for domain in reversed(UNITS):
    p = run(['/bin/launchctl', 'bootout', domain])
    if p.returncode:
        raise SystemExit('Service stop failed; nothing archived')
# launchd removal is asynchronous. Wait for the known old helper, not an
# arbitrary process, before opening a replacement instance of the same job.
time.sleep(6)
receipt['stopped_counts'] = counts()
if any(receipt['stopped_counts'].values()):
    for domain, plist in UNITS.items():
        run(['/bin/launchctl', 'bootstrap', 'system' if domain.startswith('system/') else 'gui/501', plist])
    save(receipt)
    raise SystemExit('Authority/history changed during stop; nothing archived')
if REMOTE.is_symlink() or REMOTE.stat().st_uid != 0:
    raise SystemExit('Remote directory ownership/type verification failed')
backup = Path('/private/var/backups') / ('keyvalet-r3a-reenroll-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
backup.mkdir(mode=0o700)
os.rename(REMOTE, backup / 'remote')
receipt['archived_remote_directory'] = str(backup / 'remote')
REMOTE.mkdir(mode=0o700)
for domain, plist in UNITS.items():
    p = run(['/bin/launchctl', 'bootstrap', 'system' if domain.startswith('system/') else 'gui/501', plist])
    if p.returncode:
        save(receipt)
        raise SystemExit('Fresh service bootstrap failed; archive retained')
receipt['credential_vault_sha256_after'] = hashlib.sha256(credential_file.read_bytes()).hexdigest()
receipt['credential_vault_unchanged'] = receipt['credential_vault_sha256_after'] == before
receipt['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
save(receipt)
if not receipt['credential_vault_unchanged']:
    raise SystemExit('Credential vault checksum changed; pairing not started')
print('旧的未使用远程身份已保留在 root-only 归档；现在按产品正常 bootstrap 创建全新 SE 审批身份。', flush=True)
time.sleep(1)
paired = subprocess.run(['/usr/bin/python3', str(ASSETS / 'r3a-live-pair.py')])
print('本段执行结束，退出码：', paired.returncode, flush=True)
