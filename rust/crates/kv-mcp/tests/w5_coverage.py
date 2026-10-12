#!/usr/bin/env python3
"""Gate changed Rust logic lines using llvm-cov LCOV and a read-only git diff.

Run from any directory: python3 rust/crates/kv-mcp/tests/w5_coverage.py coverage.lcov.
--base selects the reviewed base commit (HEAD by default). Untracked production files
are entirely new. The exclusions describe process/OS entry points, not uncovered
business paths; the report prints their instrumented line counts separately.
"""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[4]
CRATES = ("kv-mcp", "kv-hook", "kv-proxy", "kv-protocols")
# Native trust/process bridges require installed binaries or OS identity. Injectable
# framing, deadlines, recovery, notices and HTTP/Stop decisions stay in the denominator.
BOUNDARY_FUNCTIONS = {
    "kv-hook/src/stop.rs": ("run_stop", "verify_peer"),
    "kv-mcp/src/approval.rs": ("from_env",),
    "kv-proxy/src/approval.rs": ("configure_keepalive",),
    "kv-proxy/src/transparent.rs": ("dial",),
}
SUPPORT_FILES = {"kv-mcp/src/fake_helper.rs", "kv-mcp/src/approval_tests.rs", "kv-mcp/src/session_remote_tests.rs"}


def block_lines(lines, index):
    depth, opened, result = 0, False, set()
    for end in range(index, len(lines)):
        depth += lines[end].count("{") - lines[end].count("}")
        opened |= "{" in lines[end]
        result.add(end + 1)
        if opened and depth == 0:
            break
    return result


def function_lines(lines, name):
    result = set()
    for index, line in enumerate(lines):
        if re.search(r"\bfn\s+" + name + r"\b", line):
            result.update(block_lines(lines, index))
    return result


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lcov", type=Path)
    parser.add_argument("--base", default="HEAD")
    args = parser.parse_args()
    changed = {}
    diff = git("diff", "--no-ext-diff", "--unified=0", args.base, "--", *[f"rust/crates/{crate}/src" for crate in CRATES])
    path = None
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            path = ROOT / line[6:]
        elif match := re.match(r"@@ .* \+(\d+)(?:,(\d+))? @@", line):
            start, count = int(match[1]), int(match[2] or 1)
            changed.setdefault(path, set()).update(range(start, start + count))
    for name in git("ls-files", "--others", "--exclude-standard", *[f"rust/crates/{crate}/src" for crate in CRATES]).splitlines():
        path = ROOT / name
        if path.suffix == ".rs":
            changed[path] = set(range(1, len(path.read_text().splitlines()) + 1))

    records, path = {}, None
    for line in args.lcov.read_text().splitlines():
        if line.startswith("SF:"):
            path = Path(line[3:]).resolve()
        elif line.startswith("DA:") and path in changed:
            number, hits, *_ = line[3:].split(",")
            entries = records.setdefault(path, {})
            entries[int(number)] = entries.get(int(number), 0) + int(hits)

    totals, missed = {"covered": 0, "lines": 0, "excluded": 0}, []
    files = []
    for path, new_lines in sorted(changed.items()):
        relative = str(path.relative_to(ROOT / "rust/crates"))
        if relative in SUPPORT_FILES or path.name == "main.rs":
            continue
        source = path.read_text().splitlines()
        excluded = set()
        for name in BOUNDARY_FUNCTIONS.get(relative, ()):
            excluded.update(function_lines(source, name))
        if relative == "kv-mcp/src/continuation.rs":
            # Thin native file/network effects; formatter decisions and error UI are
            # driven through the same Effects interface with deterministic CI runners.
            for index, line in enumerate(source):
                if line == "impl Mail for NativeMail {":
                    excluded.update(block_lines(source, index))
        # Test support is not production logic, even when embedded beside production items.
        for index, line in enumerate(source):
            if line == "#[cfg(test)]" and index + 1 < len(source) and re.match(r"mod \w+ \{", source[index + 1]):
                excluded.update(block_lines(source, index + 1))
        # This dispatch arm invokes the real signature/socket-trust runner. The fake
        # connector's selection and all auth/read/write budget logic remain measured.
        if relative == "kv-mcp/src/session.rs":
            excluded.update(index + 1 for index, line in enumerate(source) if "None => connect_helper().await" in line)
        if relative == "kv-proxy/src/gateway.rs":
            # Closing the real native socket when setsockopt fails is an OS bridge.
            # check_keepalive's error classification is covered by an injected I/O error.
            for index, line in enumerate(source):
                if "check_keepalive(keepalive" in line:
                    excluded.update(block_lines(source, index))
        if relative == "kv-proxy/src/transparent.rs":
            for index, line in enumerate(source):
                if "if approval::configure_keepalive(&connection).is_err()" in line:
                    excluded.update(block_lines(source, index))
        entries = records.get(path, {})
        if not entries and any(
            re.search(r"\bfn\s+", line) and index + 1 not in excluded
            for index, line in enumerate(source)
        ):
            raise SystemExit(f"Missing LCOV instrumentation for {relative}; run coverage after ordinary cargo checks, sequentially")
        counted = (new_lines & entries.keys()) - excluded
        uncovered = sorted(number for number in counted if not entries[number])
        excluded_count = len(new_lines & entries.keys() & excluded)
        totals["lines"] += len(counted)
        totals["covered"] += len(counted) - len(uncovered)
        totals["excluded"] += excluded_count
        if counted:
            files.append({"file": relative, "covered": len(counted) - len(uncovered), "lines": len(counted), "missing": uncovered, "excluded": excluded_count})
        missed.extend(f"{relative}:{number}: {source[number-1].strip()}" for number in uncovered)
    if not totals["lines"]:
        raise SystemExit("No instrumented changed production lines found")
    totals["percent"] = round(totals["covered"] * 100 / totals["lines"], 4)
    print(json.dumps({"base": args.base, "total": totals, "files": files}, indent=2))
    for line in missed:
        print(line, file=sys.stderr)
    raise SystemExit(bool(missed))


if __name__ == "__main__":
    main()
