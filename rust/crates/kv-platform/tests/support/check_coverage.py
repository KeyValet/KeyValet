"""Check executable W1 production lines in LLVM LCOV reports.

Run after cargo llvm-cov and the instrumented check_w0.py harness. The default
gate requires the Windows and Swift reports too; --allow-unmeasured-platforms
checks the measured subset and explicitly lists the remaining platform paths.
"""
import argparse
from pathlib import Path
import re
import subprocess
import sys


NEW_RUST = [
    "kv-platform/src/device_key.rs",
    "kv-platform/src/device_key/agent.rs",
    "kv-platform/src/device_key/software.rs",
    "kv-platform/src/device_key/tpm.rs",
    "kv-platform/src/device_key/windows.rs",
    "kv-platform/src/presence.rs",
    "kv-platform/src/presence/linux.rs",
    "kv-platform/src/presence/macos.rs",
    "kv-platform/src/presence/windows.rs",
    "kv-platform/src/presence/windows_logic.rs",
    "kv-platform/src/remote_process.rs",
    "kv-touchid/src/device_key.rs",
    "kv-agent/src/presence.rs",
    "kv-agent/src/presence/windows.rs",
    "kv-agent/src/hello/remote_key.rs",
]
MODIFIED = [
    "kv-platform/src/agent.rs",
    "kv-touchid/src/agent.rs",
    "kv-touchid/src/main.rs",
    "kv-touchid/src/enclave.swift",
    "kv-agent/src/main.rs",
    "kv-agent/src/hello.rs",
    "kv-agent/src/hello_crypto.rs",
]
PLATFORM_PATHS = {
    "kv-platform/src/device_key/windows.rs": "Windows CNG/PCP/DPAPI",
    "kv-platform/src/presence/windows.rs": "Windows WTS/input/display APIs",
    "kv-agent/src/presence/windows.rs": "Windows Hello availability",
    "kv-agent/src/hello/remote_key.rs": "Windows Hello create/sign bridge",
    "kv-agent/src/main.rs": "Windows service-pipe dispatch",
    "kv-agent/src/hello.rs": "Windows WinRT dispatch",
    "kv-touchid/src/enclave.swift": "Swift Secure Enclave bridge",
}


def lcov_lines(paths, root):
    files = {}
    for path in paths:
        current = None
        for line in path.read_text().splitlines():
            if line.startswith("SF:"):
                source = line[3:].replace("\\", "/")
                owned = re.search(r"(?:^|/)crates/(kv-platform|kv-touchid|kv-agent)/(.+)$", source)
                path = (root / "rust/crates" / owned.group(1) / owned.group(2)) if owned else Path(source)
                current = files.setdefault(path.resolve(), {})
            elif line.startswith("DA:") and current is not None:
                number, count, *_ = line[3:].split(",")
                number, count = int(number), int(count)
                current[number] = max(current.get(number, 0), count)
            elif line == "end_of_record":
                current = None
    return files


def production_end(path):
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if line.strip() == "#[cfg(test)]":
            return number
    return len(path.read_text().splitlines()) + 1


def added_lines(root, path, base):
    diff = subprocess.check_output(
        ["git", "diff", "--unified=0", base, "--", str(path)], cwd=root, text=True,
    )
    added = set()
    number = None
    for line in diff.splitlines():
        if line.startswith("@@"):
            number = int(re.search(r"\+(\d+)", line).group(1))
        elif line.startswith("+") and not line.startswith("+++"):
            added.add(number)
            number += 1
        elif number is not None and line.startswith(" "):
            number += 1
    return added


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lcov", nargs="+", type=Path)
    parser.add_argument("--base", default="HEAD", help="Revision before W1 changes")
    parser.add_argument("--allow-unmeasured-platforms", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[5]
    crates = root / "rust/crates"
    files = lcov_lines(args.lcov, root)
    covered, measured = 0, 0
    missing = []
    unmeasured = []
    for name in NEW_RUST + MODIFIED:
        path = crates / name
        lines = files.get(path.resolve(), {})
        selected = {n: count for n, count in lines.items() if n < production_end(path)}
        if name in MODIFIED:
            added = added_lines(root, path, args.base)
            selected = {n: count for n, count in selected.items() if n in added}
        if not selected:
            if name in PLATFORM_PATHS:
                unmeasured.append((name, PLATFORM_PATHS[name]))
            else:
                missing.append(name + ": missing coverage data")
            continue
        count = sum(value > 0 for value in selected.values())
        print(f"{name}: {count}/{len(selected)}")
        covered += count
        measured += len(selected)
        missing.extend(f"{name}:{n}" for n, value in sorted(selected.items()) if value == 0)
    if "kv-platform/src/device_key/windows.rs" in [name for name, _ in unmeasured]:
        unmeasured.append(("kv-platform/src/device_key.rs / device_key/agent.rs", "cfg(windows) role/provider branches"))
    if not any(path.name == "linux.rs" and path.parent == crates / "kv-platform/src" for path in files):
        unmeasured.append(("kv-platform/src/device_key.rs", "cfg(target_os=linux) Strong role branch"))
    print(f"Measured production lines: {covered}/{measured}")
    for item in missing:
        print("Uncovered: " + item, file=sys.stderr)
    for name, reason in unmeasured:
        print(f"Unmeasured: {name} ({reason})")
    if missing or not measured or (unmeasured and not args.allow_unmeasured_platforms):
        print("W1 coverage gate failed; full-scope 100% is not established.", file=sys.stderr)
        return 1
    if unmeasured:
        print("Measured subset is 100%; full-scope acceptance remains open.")
    else:
        print("W1 Rust/Swift production-line coverage is 100%.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
