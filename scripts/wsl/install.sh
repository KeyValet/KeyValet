#!/bin/sh
# Run as the Linux user whose AI clients should use the Windows vault. No sudo or Linux vault.
set -eu
[ "$(id -u)" -ne 0 ] || { printf '%s\n' 'Run the WSL installer as your regular Linux user, without sudo.' >&2; exit 1; }
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
command -v python3 >/dev/null 2>&1 || { printf '%s\n' 'Install python3 first.' >&2; exit 1; }
# Public status authenticates the installed service without creating a key or opening Hello.
sh "$source_dir/bridge.sh" cli status >/dev/null
exec python3 "$source_dir/configure.py" install --source "$source_dir" "$@"
