#!/usr/bin/env python3
"""Back up and install the tested Linux helper/broker without reading secret output."""
import datetime
import json
from pathlib import Path
import subprocess

assets = Path('/Users/guang/dev/keyvalet/docs/remote-approval-reports/assets')
code = r'''
import datetime,hashlib,json,os,shutil,subprocess,time
from pathlib import Path
if os.geteuid()!=0: raise SystemExit(1)
os.umask(0o077)
source=Path('/tmp/keyvalet-r2a-20261013T072000/target/release/kv-helper')
installed=Path('/usr/local/lib/keyvalet/bin/kv-helper')
stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
backup=Path('/var/backups')/('keyvalet-r3a-process-proof-'+stamp)
backup.mkdir(mode=0o700)
receipt={'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'backup':str(backup),'runtime_config_changed':False,'vault_changed':False,
 'new_capabilities':False,'new_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
 'old_sha256':hashlib.sha256(installed.read_bytes()).hexdigest()}
units=['keyvalet-relay.service','keyvalet.service','keyvalet-peer.service']
def call(args):
 result=subprocess.run(args,capture_output=True)
 if result.returncode: raise RuntimeError('step_failed')
 return result
call(['systemctl','stop',*units])
shutil.copy2(installed,backup/'kv-helper')
call(['tar','-cf',str(backup/'state-and-install.tar'),'-C','/',
 'var/lib/keyvalet','var/lib/keyvalet-relay','etc/keyvalet',
 'usr/local/lib/keyvalet/bin/kv-helper'])
os.chmod(backup/'state-and-install.tar',0o600)
temporary=installed.with_name('kv-helper.r3a-new')
if temporary.exists() or temporary.is_symlink(): raise RuntimeError('temporary_exists')
shutil.copyfile(source,temporary);os.chown(temporary,0,0);os.chmod(temporary,0o755)
os.replace(temporary,installed)
try:
 call(['systemctl','start','keyvalet-peer.service','keyvalet.service','keyvalet-relay.service'])
 for _ in range(30):
  if all(subprocess.run(['systemctl','is-active','--quiet',u]).returncode==0 for u in units): break
  time.sleep(0.5)
 else: raise RuntimeError('services_not_active')
except Exception:
 subprocess.run(['systemctl','stop',*units],capture_output=True)
 shutil.copyfile(backup/'kv-helper',installed);os.chown(installed,0,0);os.chmod(installed,0o755)
 subprocess.run(['systemctl','start','keyvalet-peer.service','keyvalet.service','keyvalet-relay.service'],capture_output=True)
 receipt['rolled_back']=True;print(json.dumps(receipt));raise SystemExit(1)
receipt['installed_sha256']=hashlib.sha256(installed.read_bytes()).hexdigest()
receipt['services']={}
for unit in units:
 result=call(['systemctl','show',unit,'--property=MainPID,User,ActiveState,CapabilityBoundingSet,AmbientCapabilities','--no-pager'])
 receipt['services'][unit]=dict(line.split('=',1) for line in result.stdout.decode().splitlines() if '=' in line)
for unit in ['keyvalet.service','keyvalet-relay.service']:
 assert receipt['services'][unit]['CapabilityBoundingSet']==''
 assert receipt['services'][unit]['AmbientCapabilities']==''
assert receipt['services']['keyvalet-peer.service']['CapabilityBoundingSet']=='cap_sys_ptrace'
for _ in range(30):
 result=subprocess.run(['/usr/local/lib/keyvalet/bin/kv-cli','devices','list','--json'],capture_output=True)
 if result.returncode==0: break
 time.sleep(0.5)
else:
 receipt['fixed_error']='owner_ipc_not_ready';print(json.dumps(receipt));raise SystemExit(1)
value=json.loads(result.stdout)
value=value.get('result',value) if isinstance(value,dict) else value
devices=value.get('devices',[]) if isinstance(value,dict) else value
receipt['device_ids']=[v['device_id'] for v in devices if isinstance(v,dict) and isinstance(v.get('device_id'),str)]
receipt['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
assert receipt['installed_sha256']==receipt['new_sha256']
print(json.dumps(receipt))
'''
result = subprocess.run(['ssh', 'ndu', 'sudo -n /usr/bin/python3 -'],
                        input=code, capture_output=True, text=True, timeout=90)
try:
    receipt = json.loads(result.stdout)
except (ValueError, TypeError):
    receipt = {'install_exit': result.returncode, 'fixed_error': 'receipt_unavailable'}
receipt['install_exit'] = result.returncode
receipt['observed_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
(assets / 'r3a-ndu-process-install.json').write_text(json.dumps(receipt, indent=2)+'\n')
print(json.dumps(receipt))
raise SystemExit(result.returncode)
