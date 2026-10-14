"""Task-local SSH helpers. Output is restricted to explicit metadata/results."""
import base64
import json
import pathlib
import subprocess

ROOT = pathlib.Path('/Users/guang/dev/keyvalet')
ASSETS = ROOT / 'docs/remote-approval-reports/assets'
TASK = ROOT / 'rust/target-r2b/unsigned-20261014'
TASK.mkdir(exist_ok=True)


def ssh_args(host):
    common = ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8',
              '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2']
    if host == 'physical':
        return ['-i', '/Users/guang/.ssh/niumate_win_ed25519', '-o', 'IdentitiesOnly=yes',
                *common, '11516@192.168.1.182']
    return [*common, 'win11']


def powershell(host, script, timeout=40):
    encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
    return subprocess.run(['ssh', *ssh_args(host),
                           'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + encoded],
                          capture_output=True, timeout=timeout)


def metadata(host, script, filename, timeout=40):
    result = powershell(host, script, timeout)
    try:
        data = json.loads(result.stdout.decode('utf-8-sig'))
    except (UnicodeError, ValueError):
        data = {'json_obtained': False}
    data['ssh_exit'] = result.returncode
    (ASSETS / filename).write_text(json.dumps(data, indent=2, ensure_ascii=False) + '\n')
    return data


def copy_to(host, source, destination):
    args = ssh_args(host)
    target = args.pop()
    subprocess.run(['scp', *args, str(source), target + ':' + destination],
                   check=True, capture_output=True, timeout=60)


def copy_from(host, source, destination):
    args = ssh_args(host)
    target = args.pop()
    subprocess.run(['scp', *args, target + ':' + source, str(destination)],
                   check=True, capture_output=True, timeout=60)
