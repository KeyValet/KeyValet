#!/bin/sh
# Remove this user's bridge/configuration only. The Windows installation and vault remain.
set -eu
[ "$(id -u)" -ne 0 ] || { printf '%s\n' 'Run the WSL uninstaller as your regular Linux user, without sudo.' >&2; exit 1; }
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
exec python3 "$source_dir/configure.py" uninstall "$@"
