#!/usr/bin/env python3
"""Check exact line/function coverage for the agreed W7 logic scope."""

import json
import sys
from pathlib import Path

crate = Path(__file__).resolve().parent.parent
scope = [
    crate / "src/remote.rs",
    *(crate / "src/remote" / name for name in (
        "args.rs", "audit.rs", "output.rs", "relay.rs", "transport.rs"
    )),
]
report = json.loads(Path(sys.argv[1]).read_text())
files = {
    Path(file["filename"]).resolve(): file["summary"]
    for data in report["data"]
    for file in data["files"]
}
failed = False
for path in scope:
    summary = files.get(path)
    if summary is None:
        print(f"FAIL: missing coverage for {path.relative_to(crate)}")
        failed = True
        continue
    print(path.relative_to(crate))
    for metric in ("lines", "functions", "regions"):
        counts = summary[metric]
        print(f"  {metric}: {counts['covered']}/{counts['count']}")
        if metric != "regions" and (
            counts["count"] == 0 or counts["covered"] != counts["count"]
        ):
            failed = True
adapter = files.get(crate / "src/remote/system.rs")
if adapter is not None:
    print("System adapter (reported separately):", json.dumps(adapter, sort_keys=True))
sys.exit(1 if failed else 0)
