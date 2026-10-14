#!/usr/bin/env python3
"""Install only the reviewed Linux helper, with a quiescent root-only backup."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

if os.geteuid()!=0:
    raise SystemExit('root_required')
os.umask(0o077)
source=Path('/tmp/keyvalet-r2a-20261013T072000/target/release/kv-helper')
installed=Path('/usr/local/lib/keyvalet/bin/kv-helper')
cli=installed.with_name('kv-cli')
expected='296ea14dcd320d96cbcb8a6936971d6086ce7613d10b7a77147dd0d8e53a685a'
units=['keyvalet-relay.service','keyvalet.service','keyvalet-peer.service']
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def run(args,check=True):
    p=subprocess.run(args,capture_output=True,text=True,timeout=30)
    if check and p.returncode:raise RuntimeError('native_install_step_failed')
    return p
def status():
    deadline=time.monotonic()+15
    while True:
        p=run(['/usr/sbin/runuser','-u','guang','--','/usr/local/bin/keyvalet','status','--json'],False)
        try:value=json.loads(p.stdout)
        except ValueError:value={}
        remote=value.get('result',{}).get('remote') if isinstance(value,dict) and isinstance(value.get('result'),dict) else None
        if p.returncode==0 and value.get('ok') is True and isinstance(remote,dict):
            return {k:remote[k] for k in ['device_id','account_id','mode','pending_n','grants_n','unattended','relay']}
        if time.monotonic()>=deadline:raise RuntimeError('native_owner_status_unavailable')
        time.sleep(.3)

for p in (source,installed,cli,Path('/var/lib/keyvalet/vault.enc')):
    if p.is_symlink() or not p.is_file():raise SystemExit('unsafe_install_path')
if sha(source)!=expected:raise SystemExit('staged_checksum_mismatch')
before=status()
if before['pending_n'] or before['grants_n'] or before['unattended']:
    raise SystemExit('native_state_not_quiescent')
stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
backup=Path('/var/backups')/('keyvalet-r3a-revocations-'+stamp)
backup.mkdir(mode=0o700)
receipt={'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'backup':str(backup),
         'expected_sha256':expected,'old_sha256':sha(installed),'cli_sha256_before':sha(cli),
         'vault_sha256_before':sha(Path('/var/lib/keyvalet/vault.enc')),'before':before,
         'authentication_requests_started':0,'secret_values_in_evidence':False}
stopped=False
replaced=False
try:
    run(['systemctl','stop',*units]);stopped=True
    run(['cp','--preserve=all',str(installed),str(backup/'kv-helper')])
    archive=backup/'state-and-install.tar'
    run(['tar','-cpf',str(archive),'-C','/','var/lib/keyvalet','var/lib/keyvalet-relay',
         'etc/keyvalet','usr/local/lib/keyvalet/bin/kv-helper','usr/local/lib/keyvalet/bin/kv-cli'])
    os.chmod(archive,0o600);receipt['backup_sha256']=sha(archive)
    temporary=installed.with_name('.kv-helper.r3a-revocations-new')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o700)
    with os.fdopen(fd,'wb') as out:
        out.write(source.read_bytes());out.flush();os.fsync(out.fileno())
        os.fchown(out.fileno(),0,0);os.fchmod(out.fileno(),0o755)
    os.replace(temporary,installed);replaced=True
    run(['systemctl','start','keyvalet-peer.service','keyvalet.service','keyvalet-relay.service'])
    for _ in range(30):
        if all(run(['systemctl','is-active','--quiet',u],False).returncode==0 for u in units):break
        time.sleep(.3)
    else:raise RuntimeError('native_services_not_active')
    after=status();receipt['after']=after
    if (after['device_id'],after['account_id'])!=(before['device_id'],before['account_id']):
        raise RuntimeError('native_identity_changed')
    receipt['installed_sha256']=sha(installed)
    receipt['cli_sha256_after']=sha(cli)
    receipt['vault_sha256_after']=sha(Path('/var/lib/keyvalet/vault.enc'))
    if receipt['cli_sha256_before']!=receipt['cli_sha256_after'] or receipt['vault_sha256_before']!=receipt['vault_sha256_after']:
        raise RuntimeError('unrelated_native_state_changed')
    receipt['services']={}
    for unit in units:
        p=run(['systemctl','show',unit,'--property=MainPID,User,ActiveState,CapabilityBoundingSet,AmbientCapabilities','--no-pager'])
        receipt['services'][unit]=dict(line.split('=',1) for line in p.stdout.splitlines() if '=' in line)
    for unit in ('keyvalet.service','keyvalet-relay.service'):
        if receipt['services'][unit]['CapabilityBoundingSet'] or receipt['services'][unit]['AmbientCapabilities']:
            raise RuntimeError('unexpected_service_capability')
    if receipt['services']['keyvalet-peer.service']['CapabilityBoundingSet']!='cap_sys_ptrace':
        raise RuntimeError('unexpected_broker_capability')
    receipt['installed']=True
except Exception as error:
    receipt['fixed_error']=str(error) if isinstance(error,RuntimeError) else 'native_install_failed'
    if replaced:
        run(['systemctl','stop',*units],False)
        run(['cp','--preserve=all',str(backup/'kv-helper'),str(installed)])
        receipt['rolled_back']=True
    if stopped:run(['systemctl','start','keyvalet-peer.service','keyvalet.service','keyvalet-relay.service'],False)
finally:
    receipt['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    print(json.dumps(receipt))
raise SystemExit(0 if receipt.get('installed') is True else 1)
