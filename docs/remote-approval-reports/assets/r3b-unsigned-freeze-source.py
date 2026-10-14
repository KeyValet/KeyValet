"""Freeze exact build/package inputs without copying targets or user state."""
import argparse
import datetime
import hashlib
import io
import json
import pathlib
import subprocess
import tarfile

ROOT = pathlib.Path('/Users/guang/dev/keyvalet')
ASSETS = ROOT / 'docs/remote-approval-reports/assets'
TASK = ROOT / 'rust/target-r2b/unsigned-20261014'
parser = argparse.ArgumentParser()
parser.add_argument('--name', required=True)
parser.add_argument('--previous', required=True)
args = parser.parse_args()
if not args.name.replace('-', '').isalnum():
    raise SystemExit('invalid snapshot name')
previous = json.loads((ASSETS / args.previous).read_text())
previous_hashes = {entry['path']: entry['sha256'] for entry in previous['files']}
paths = {entry['path'] for entry in previous['files']}
listed = subprocess.check_output(['rg', '--files', '--hidden', 'rust'], cwd=ROOT,
                                 text=True).splitlines()
paths.update(path for path in listed if not path.startswith('rust/target'))
paths.update(['LICENSE', 'README.md', 'SECURITY.md', 'templates/catalog.json',
              'docs/windows.md', 'docs/wsl.md'])
payloads = {}
for name in sorted(paths):
    path = ROOT / name
    if not path.is_file():
        continue
    if path.is_symlink() or not path.resolve().is_relative_to(ROOT):
        raise SystemExit('source input is outside workspace')
    payloads[name] = path.read_bytes()
files = [{'path': name, 'sha256': hashlib.sha256(data).hexdigest()}
         for name, data in payloads.items()]
fingerprint = hashlib.sha256(json.dumps(files, sort_keys=True,
                                       separators=(',', ':')).encode()).hexdigest()
manifest = {
    'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'fingerprint': fingerprint,
    'fingerprint_algorithm': 'sha256(compact sorted-key JSON files array)',
    'files': files,
    'previous': args.previous,
    'changed_from_previous': [entry['path'] for entry in files
                              if previous_hashes.get(entry['path']) != entry['sha256']],
}
archive = TASK / (args.name + '.tar.gz')
manifest_path = ASSETS / (args.name + '.json')
if archive.exists() or manifest_path.exists():
    raise SystemExit('snapshot already exists; preserve previous evidence')
TASK.mkdir(exist_ok=True)
source_mtime = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
with tarfile.open(archive, 'w:gz') as output:
    for name, data in payloads.items():
        info = tarfile.TarInfo(name)
        info.size = len(data)
        info.mode = 0o644
        # Cargo's source freshness check uses mtimes. Epoch timestamps can make
        # different source bytes look older than an existing compiled artifact.
        info.mtime = source_mtime
        output.addfile(info, io.BytesIO(data))
manifest['archive_sha256'] = hashlib.sha256(archive.read_bytes()).hexdigest()
manifest['archive_bytes'] = archive.stat().st_size
manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + '\n')
print(json.dumps({'manifest': str(manifest_path), 'archive': str(archive),
                  'files': len(files), 'fingerprint': fingerprint,
                  'archive_bytes': manifest['archive_bytes']}))
