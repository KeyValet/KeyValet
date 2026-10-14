#!/usr/bin/env python3
"""Run on ndu; link the maintenance program against the exact helper dependency graph."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

root=Path('/tmp/keyvalet-r2a-20261013T072000')
release=root/'target/release'
deps=release/'deps'
fingerprints=release/'.fingerprint'
env=dict(os.environ,CARGO_HOME='/tmp/keyvalet-owner-isolation-20261012/cargo',
         RUSTUP_HOME='/tmp/keyvalet-owner-isolation-20261012/rustup',
         PATH='/tmp/keyvalet-owner-isolation-20261012/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin')
helper=max(deps.glob('libkv_helper-*.rlib'),key=lambda p:p.stat().st_mtime)
suffix=helper.stem.removeprefix('libkv_helper-')
meta=json.loads((fingerprints/('kv-helper-'+suffix)/'lib-kv_helper.json').read_text())
expected={row[1]:row[-1] for row in meta['deps']}
binary=root/'target/r3a-settings-checkpoint'
args=['rustc','+1.99.0','--edition=2021',str(root/'source/scripts/linux/r3a-settings-checkpoint.rs'),
      '-C','panic=abort','-C','opt-level=2','-A','dead_code','-L','dependency='+str(deps),
      '-o',str(binary),'--extern','kv_helper='+str(helper)]
for name in ('kv_core','kv_vault','kv_platform','serde','serde_json','zeroize','rusqlite','libc'):
    matches=[]
    for directory in fingerprints.iterdir():
        value=directory/('lib-'+name)
        if value.is_file() and int.from_bytes(bytes.fromhex(value.read_text().strip()),'little')==expected[name]:
            artifact=deps/('lib'+name+'-'+directory.name.rsplit('-',1)[-1]+'.rlib')
            if artifact.is_file():matches.append(artifact)
    if len(matches)!=1:raise SystemExit('ambiguous_compiler_dependency_'+name)
    args+=['--extern',name+'='+str(matches[0])]
result=subprocess.run(args,env=env)
if result.returncode:raise SystemExit(result.returncode)
print(json.dumps({'maintenance_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
                  'helper_sha256':hashlib.sha256((release/'kv-helper').read_bytes()).hexdigest(),
                  'cli_sha256':hashlib.sha256((release/'kv-cli').read_bytes()).hexdigest()}))
