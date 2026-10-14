#!/usr/bin/env python3
"""Install the reviewed CLI and inspect the current candidate before any new UI."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

assets = Path('/Users/guang/dev/keyvalet/docs/remote-approval-reports/assets')
cli = Path('/usr/local/lib/keyvalet/bin/kv-cli')
stage = Path('/Users/guang/dev/keyvalet/rust/target-r2a/r3a-native-staging/bin/kv-cli')
if os.geteuid() != 0:
    raise SystemExit('Run in the owner sudo terminal')
os.umask(0o077)
sha = hashlib.sha256(stage.read_bytes()).hexdigest()
expected = json.loads((assets / 'r3a-signed-build.json').read_text())['binaries']['kv-cli']['sha256']
requirement = '=identifier "dev.keyvalet.cli" and anchor apple generic and certificate leaf[subject.OU] = "PWCRJPY7YC"'
p = subprocess.run(['/usr/bin/codesign', '--verify', '--strict', '-R', requirement, str(stage)], capture_output=True)
if sha != expected or p.returncode:
    raise SystemExit('CLI checksum/signature verification failed')
backup = Path('/private/var/backups') / ('keyvalet-r3a-cli-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
backup.mkdir(mode=0o700)
shutil.copy2(cli, backup / 'kv-cli')
temporary = cli.with_name('.kv-cli-r3a-resume')
shutil.copyfile(stage, temporary)
os.chown(temporary, 0, 0)
os.chmod(temporary, 0o755)
os.replace(temporary, cli)
p = subprocess.run([str(cli), 'devices', 'list', '--json'], capture_output=True, text=True, timeout=30)
devices = json.loads(p.stdout).get('result', {}).get('devices', [])
if p.returncode or len(devices) != 1 or devices[0].get('os') != 'macos':
    raise SystemExit('Expected an unpaired local Mac singleton')
local = devices[0]
device_id = local['device_id']
if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', device_id):
    raise SystemExit('Invalid public device id')
code = """import sqlite3,json,datetime
db=sqlite3.connect('file:/var/lib/keyvalet-relay-server/relay.sqlite3?mode=ro',uri=True)
row=db.execute('SELECT record,revoked_at FROM devices WHERE id=?',(DEVICE_ID,)).fetchone()
if row:
 r=json.loads(row[0])
 print(json.dumps({'device_id':DEVICE_ID,'dk_pub':r['dk_pub'],'revoked_utc':datetime.datetime.fromtimestamp(row[1],datetime.timezone.utc).isoformat() if row[1] else None,'read_only':True}))
else: print('{}')
db.close()
""".replace('DEVICE_ID', repr(device_id))
p = subprocess.run(['/usr/bin/sudo', '-u', 'guang', '/usr/bin/ssh', '-o', 'BatchMode=yes',
                    '-o', 'ConnectTimeout=8', 'simvito', 'sudo -n /usr/bin/python3 -'],
                   input=code, capture_output=True, text=True, timeout=30)
if p.returncode:
    raise SystemExit('Read-only relay inspection failed')
proof = json.loads(p.stdout)
proof['local_dk_matches'] = proof.get('dk_pub') == local.get('dk_pub')
proof['observed_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
out = assets / 'r3a-relay-tombstone-current.json'
out.write_text(json.dumps(proof, indent=2) + '\n')
os.chown(out, 501, 20)
os.chmod(out, 0o600)
if proof.get('revoked_utc') and proof['local_dk_matches']:
    print('当前未完成候选已到期，保留墓碑并重新走全新身份的标准配对。', flush=True)
    subprocess.run(['/usr/bin/python3', str(assets / 'r3a-fresh-approver.py'), '--current'])
elif proof['local_dk_matches']:
    print('当前候选仍有效；通过已测试的 pair --resume 继续原 SAS/原 exp。', flush=True)
    subprocess.run(['/usr/bin/python3', str(assets / 'r3a-live-pair.py'), '--resume'])
else:
    raise SystemExit('Local and relay public identity mismatch; pairing not started')
