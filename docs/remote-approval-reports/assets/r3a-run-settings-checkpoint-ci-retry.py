#!/usr/bin/env python3
"""Run the four prescribed commands and retain per-command exits and source hashes."""
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess

root=Path('/Users/guang/dev/keyvalet')
assets=root/'docs/remote-approval-reports/assets'
def snapshot():
    paths=list((root/'rust/crates').rglob('*.rs'))+list((root/'rust').glob('*.toml'))+list((root/'rust/crates').rglob('Cargo.toml'))+[root/'rust/Cargo.lock']
    return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
before=snapshot()
receipt={'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'rust':'1.99.0','checks':{},'source_files':len(before)}
prefix=['/usr/bin/env','CARGO_INCREMENTAL=0','CARGO_PROFILE_DEV_DEBUG=0','CARGO_PROFILE_TEST_DEBUG=0',
        'CARGO_TARGET_DIR=/Users/guang/dev/keyvalet/rust/target-r2a','cargo','+1.99.0']
checks=[('fmt',['fmt','--all','--','--check']),('clippy',['clippy','--workspace','--all-targets','--','-D','warnings']),
        ('build',['build','--workspace','--locked']),('test',['test','--workspace','--locked'])]
for name,args in checks:
    path=assets/('r3a-settings-checkpoint-retry-ci2-'+name+'.log')
    with path.open('w') as output:
        process=subprocess.run(prefix+args,cwd=root/'rust',stdout=output,stderr=subprocess.STDOUT)
    receipt['checks'][name]=process.returncode
    print(name+' exit '+str(process.returncode),flush=True)
    if process.returncode:break
after=snapshot()
changed=[name for name,digest in before.items() if after.get(name)!=digest]
receipt['source_unchanged_during_checks']=not changed
receipt['changed_source_files']=changed
if receipt['checks'].get('test')==0:
    output=(assets/'r3a-settings-checkpoint-retry-ci2-test.log').read_text()
    groups=re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;',output)
    receipt.update({'passed':sum(int(g[0]) for g in groups),'failed':sum(int(g[1]) for g in groups),
                    'ignored':sum(int(g[2]) for g in groups),'groups':len(groups)})
receipt['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
(assets/'r3a-settings-checkpoint-retry-ci-summary.json').write_text(json.dumps(receipt,indent=2)+'\n')
(assets/'r3a-settings-checkpoint-retry-source-after-ci.json').write_text(json.dumps({'observed_utc':receipt['finished_utc'],'paths':after},indent=2)+'\n')
