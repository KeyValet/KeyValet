"""Check LLVM's per-file line totals for the portable W6 production modules."""
import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[5]
    source = repository / "rust/crates/kv-agent/src/remote"
    required = {
        path.resolve()
        for path in source.rglob("*.rs")
        if path.name not in ("tests.rs", "windows.rs") and not path.name.endswith("_tests.rs")
    }
    measured = {}
    for group in json.loads(args.report.read_text())["data"]:
        for file in group["files"]:
            path = Path(file["filename"]).resolve()
            if path in required:
                measured.setdefault(path, []).append(file["summary"]["lines"])
    failures = []
    total = 0
    for path in sorted(required):
        variants = measured.get(path, [])
        if not variants:
            failures.append(f"{path.name}: not measured")
            continue
        if len(variants) != 2:
            failures.append(f"{path.name}: expected both desktop builds, found {len(variants)}")
        for variant in variants:
            if variant["count"] == 0 or variant["count"] != variant["covered"]:
                failures.append(f"{path.name}: {variant['covered']}/{variant['count']}")
        counts = {variant["count"] for variant in variants}
        if len(counts) != 1:
            failures.append(f"{path.name}: inconsistent source line totals")
        total += max(counts)
        print(f"{path.name}: {variants[0]['covered']}/{variants[0]['count']} ({len(variants)} builds)")
    if failures:
        raise SystemExit("W6 portable line coverage failed:\n" + "\n".join(failures))
    print(f"W6 portable production code: {total}/{total} lines (100%). Native OS/GUI adapters are reported separately.")


if __name__ == "__main__":
    main()
