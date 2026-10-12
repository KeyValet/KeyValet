#!/usr/bin/env python3
"""Verify every executable source line and instrumented branch of the W4 core.

The real OS peer trust runner is reported separately, as required by AGENTS.md.
No business line, function or branch is excluded. Source hashes prevent accepting
a report after concurrent edits have made it stale.
"""

import argparse
import hashlib
import json
from pathlib import Path


SOURCE = Path(__file__).resolve().parents[1] / "src" / "remote"


def source_hashes():
    return {
        str(path.resolve()): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(SOURCE.rglob("*"))
        if path.is_file()
    }


def lcov_records(path):
    records = {}
    for block in path.read_text().split("end_of_record"):
        name = None
        lines = {}
        for entry in block.splitlines():
            if entry.startswith("SF:"):
                name = str(Path(entry[3:]).resolve())
            elif entry.startswith("DA:"):
                line, count, *_ = entry[3:].split(",")
                lines[int(line)] = max(lines.get(int(line), 0), int(count))
        if name:
            records[name] = lines
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path)
    parser.add_argument("--lcov", type=Path)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--sources", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.capture:
        args.capture.write_text(json.dumps(source_hashes(), indent=2) + "\n")
        return 0
    if not all((args.lcov, args.json, args.sources, args.output)):
        parser.error("verification requires --lcov, --json, --sources and --output")
    if json.loads(args.sources.read_text()) != source_hashes():
        parser.error("W4 sources changed during measurement; rerun the coverage tests")
    lines = lcov_records(args.lcov)
    llvm = {
        str(Path(file["filename"]).resolve()): file
        for file in json.loads(args.json.read_text())["data"][0]["files"]
    }
    files = []
    for path in sorted(SOURCE.glob("*.rs")):
        if path.name in {"tests.rs", "process.rs"}:
            continue
        name = str(path.resolve())
        if not lines.get(name) or name not in llvm:
            parser.error(f"missing instrumentation for {path.name}")
        missing_lines = [line for line, count in lines[name].items() if count == 0]
        missing_branches = [
            {"line": branch[0], "column": branch[1], "true": branch[4], "false": branch[5]}
            for branch in llvm[name]["branches"]
            if branch[4] == 0 or branch[5] == 0
        ]
        summary = llvm[name]["summary"]
        files.append({
            "file": path.name,
            "lines": len(lines[name]),
            "covered_lines": len(lines[name]) - len(missing_lines),
            "branches": summary["branches"]["count"],
            "covered_branches": summary["branches"]["covered"],
            "missing_lines": missing_lines,
            "missing_branches": missing_branches,
            "llvm_instantiation_line_summary": summary["lines"],
        })
    passed = all(
        not file["missing_lines"] and not file["missing_branches"]
        and file["covered_branches"] == file["branches"]
        for file in files
    )
    result = {
        "passed": passed,
        "metric": "unique LCOV DA source lines and every LLVM instrumented branch",
        "files": files,
        "lines": sum(file["lines"] for file in files),
        "covered_lines": sum(file["covered_lines"] for file in files),
        "branches": sum(file["branches"] for file in files),
        "covered_branches": sum(file["covered_branches"] for file in files),
        "os_runner": llvm[str((SOURCE / "process.rs").resolve())]["summary"],
        "source_hashes": source_hashes(),
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in ["passed", "lines", "covered_lines", "branches", "covered_branches"]}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
