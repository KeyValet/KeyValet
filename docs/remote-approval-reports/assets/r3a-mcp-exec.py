#!/usr/bin/env python3
"""Expose only the PID before exec into the installed, authenticated MCP binary."""
import os
from pathlib import Path
import sys

directory = Path('/tmp/keyvalet-r3a-native')
if directory.is_symlink() or directory.stat().st_uid != os.getuid():
    raise SystemExit('Unexpected acceptance directory owner')
name = sys.argv[1]
if name not in ('setup', 'claude', 'samples'):
    raise SystemExit('Unknown acceptance phase')
path = directory / (name + '.pid')
temporary = directory / (name + '.pid.new')
with temporary.open('x') as file:
    file.write(str(os.getpid()) + '\n')
os.chmod(temporary, 0o600)
os.replace(temporary, path)
os.execv('/usr/local/lib/keyvalet/bin/kv-mcp', ['/usr/local/lib/keyvalet/bin/kv-mcp'])
