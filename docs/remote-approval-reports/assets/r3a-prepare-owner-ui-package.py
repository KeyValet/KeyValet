#!/usr/bin/env python3
"""Sign the rebuilt helper, retain installed peer binaries, and verify the package."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

os.umask(0o077)
root = Path('/Users/guang/dev/keyvalet')
stage = root/'rust/target-r2a/r3a-owner-ui-staging/bin'
stage.mkdir(parents=True,exist_ok=True)
names = {'kv-helper':'helper','kv-cli':'cli','kv-touchid':'touchid','kv-relay-client':'relay-client'}
for name in names:
    source = root/'rust/target-r2a/release/kv-helper' if name == 'kv-helper' else Path('/usr/local/lib/keyvalet/bin')/name
    if source.is_symlink() or not source.is_file():
        raise SystemExit('unsafe_package_source')
    dest = stage/name
    if dest.is_symlink():
        raise SystemExit('unsafe_package_destination')
    shutil.copyfile(source,dest)
    os.chmod(dest,0o755)
process = subprocess.run(['/usr/bin/codesign','--force','--sign','2732BEDE1859B84EC72A8D90C2BAD6965B531093',
                          '--options','runtime','--timestamp','--identifier','dev.keyvalet.helper',str(stage/'kv-helper')],
                         capture_output=True,text=True,timeout=60)
if process.returncode:
    raise SystemExit('helper_signing_failed')
receipt = {'observed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'team':'PWCRJPY7YC','new_binary':'kv-helper','binaries':{},
           'ci_receipt':'r3a-owner-ui-ci-summary.json',
           'workspace_test_exit':101,'owner_regressions_passed':5,
           'installed':False,'secret_values_in_evidence':False}
for name,identifier in names.items():
    requirement = '=identifier "dev.keyvalet.'+identifier+'" and anchor apple generic and certificate leaf[subject.OU] = "PWCRJPY7YC"'
    process = subprocess.run(['/usr/bin/codesign','--verify','--strict','-R',requirement,str(stage/name)],
                             capture_output=True,text=True,timeout=15)
    if process.returncode:
        raise SystemExit('package_signature_requirement_failed')
    receipt['binaries'][name] = {'sha256':hashlib.sha256((stage/name).read_bytes()).hexdigest(),
                                'strict_requirement':True,'rebuilt':name=='kv-helper'}
(root/'docs/remote-approval-reports/assets/r3a-owner-ui-signed-build.json').write_text(json.dumps(receipt,indent=2)+'\n')
print('Signed helper package verified; four strict requirements passed. Not installed.',flush=True)
