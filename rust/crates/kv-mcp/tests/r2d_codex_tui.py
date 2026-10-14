#!/usr/bin/env python3
"""PTY measurements of the installed Codex TUI with the Rust fake-helper fixture."""
import argparse
import concurrent.futures
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import shutil
import signal
import struct
import subprocess
import tempfile
import termios
import time
import tomllib

parser=argparse.ArgumentParser();parser.add_argument("--binary",required=True);parser.add_argument("--output",required=True)
args=parser.parse_args()
def run(kind):
    out=Path(args.output).resolve()/('codex-tui-'+kind);out.mkdir(parents=True,exist_ok=True)
    work=Path(tempfile.mkdtemp(prefix='kv-r2d-tui-',dir='/tmp'));os.chmod(work,0o700)
    fixture_env={"W5_APPROVE_AFTER_S":"240","KEYVALET_WAIT_IN_CALL_S":"300",
                 "KEYVALET_RUNTIME_BUDGETS":'{"codex-mcp-client":300}',"KEYVALET_LANG":"en",
                 "R2D_HELPER_SOCKET":str(work/'h.sock'),"R2D_HELPER_LOG":str(out/'helper.json'),"R2D_WIRE_LOG":str(out/'wire.jsonl')}
    user=tomllib.loads((Path.home()/'.codex/config.toml').read_text())
    cmd=['codex','--no-alt-screen','-a','never','-s','read-only','-c','features.hooks=false',
         '-c','projects.'+str(work)+'.trust_level="trusted"']
    for name in user.get('mcp_servers',{}):cmd+=['-c','mcp_servers.'+name+'.enabled=false']
    for name in user.get('plugins',{}):cmd+=['-c','plugins.'+name+'.enabled=false']
    cmd+=['-c','mcp_servers.r2dprobe.command='+json.dumps(str(Path(args.binary).resolve())),
          '-c','mcp_servers.r2dprobe.args=[]','-c','mcp_servers.r2dprobe.default_tools_approval_mode="approve"']
    for key,value in fixture_env.items():cmd+=['-c','mcp_servers.r2dprobe.env.'+key+'='+json.dumps(value)]
    cmd+=['This is an isolated runtime experiment using only MCP server r2dprobe, a Rust KeyValet server with a fake helper and no real vault. '
          'Do not use built-in tools, edit files or run commands. Call r2d_block_'+kind+' exactly once with empty arguments. '
          'Wait for its response, report it, and finish. Never repeat it if it times out.']
    master,slave=pty.openpty();fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',45,160,0,0))
    start=time.monotonic();proc=subprocess.Popen(cmd,cwd=work,stdin=slave,stdout=slave,stderr=slave,start_new_session=True,env={**os.environ,'TERM':'xterm-256color'})
    os.close(slave);completed=None;status='supervisor_deadline'
    with (out/'terminal.log').open('wb') as log:
        while time.monotonic()-start<420 and proc.poll() is None:
            if select.select([master],[],[],0.3)[0]:
                try:data=os.read(master,65536)
                except OSError:break
                log.write(data);log.flush()
                if b'\x1b[6n' in data:os.write(master,b'\x1b[1;1R')
                if b'\x1b]11;' in data:os.write(master,b'\x1b]11;rgb:0000/0000/0000\x1b\\')
            wire=out/'wire.jsonl'
            if wire.exists():
                try:events=[json.loads(line) for line in wire.read_text().splitlines()]
                except json.JSONDecodeError:continue
                if any(e['event']=='tool_completed' for e in events) and completed is None:completed=time.monotonic()
            if completed is not None and time.monotonic()-completed>20:
                status='completed_tool_then_supervised_exit';break
    if proc.poll() is None:
        os.killpg(proc.pid,signal.SIGTERM)
        try:proc.wait(timeout=3)
        except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);proc.wait()
    else:status='exited'
    os.close(master);shutil.rmtree(work)
    record={'command':cmd,'exit':proc.returncode,'status':status,'elapsed_s':round(time.monotonic()-start,3),'private_config_removed':True}
    (out/'run.json').write_text(json.dumps(record,indent=2)+'\n');print(kind,status,flush=True)
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:list(pool.map(run,['progress','silent']))
