#!/bin/sh
# WSL interop preserves stdin/stdout and the active Windows account. The native launcher
# authenticates the SYSTEM service and requests a protected worker; this is not a TCP proxy.
set -eu

fail() { printf '%s\n' "KeyValet WSL: $*" >&2; exit 1; }

case "${1:-}" in
  mcp) windows_binary='C:\Program Files\KeyValet\bin\kv-mcp.exe' ;;
  hook) windows_binary='C:\Program Files\KeyValet\bin\kv-hook.exe' ;;
  cli) windows_binary='C:\Program Files\KeyValet\bin\kv-cli.exe' ;;
  *) fail 'usage: bridge.sh mcp|hook|cli [arguments...]' ;;
esac
shift

if [ -z "${WSL_DISTRO_NAME:-}" ]; then
  [ -r /proc/sys/kernel/osrelease ] || fail 'run this bridge inside WSL.'
  case "$(cat /proc/sys/kernel/osrelease)" in
    *[Mm]icrosoft*) ;;
    *) fail 'run this bridge inside WSL.' ;;
  esac
fi
command -v wslpath >/dev/null 2>&1 || fail 'wslpath is missing; enable Windows interop in this distribution.'
binary=$(wslpath -u "$windows_binary") || fail 'cannot translate the Windows installation path.'
[ -f "$binary" ] || fail 'install KeyValet on Windows first (C:\Program Files\KeyValet).'

# Replace flags on our own variables so an inherited /p cannot turn a language or grant
# mode into a path. Preserve the caller's unrelated WSLENV entries without evaluating them.
forwarded='KEYVALET_LANG/w:KEYVALET_SESSION_TTL_MINUTES/w:KEYVALET_GRANT_MODE/w:KEYVALET_HOOKS/w'
old_ifs=$IFS
IFS=:
set -f
for entry in ${WSLENV:-}; do
  case "$entry" in
    KEYVALET_LANG|KEYVALET_LANG/*|KEYVALET_SESSION_TTL_MINUTES|KEYVALET_SESSION_TTL_MINUTES/*|KEYVALET_GRANT_MODE|KEYVALET_GRANT_MODE/*|KEYVALET_HOOKS|KEYVALET_HOOKS/*|'') ;;
    *) forwarded="$forwarded:$entry" ;;
  esac
done
IFS=$old_ifs
WSLENV=$forwarded
export WSLENV

# No banner, buffering, JSON rewriting or extra child shell: EOF and the native exit status
# reach the Windows launcher directly. In particular, EOF still revokes the worker session.
exec "$binary" "$@"
