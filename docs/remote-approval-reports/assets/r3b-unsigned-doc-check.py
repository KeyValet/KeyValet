"""Check the current Windows closure documents without accessing installed data."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DOCUMENTS = [
    "docs/remote-approval-architecture-2026-10.zh-CN.md",
    "docs/remote-approval-product-2026-10.zh-CN.md",
    "docs/review-2026-10.zh-CN.md",
    "docs/windows.md",
    "docs/windows-native-acceptance-2026-10-12.zh-CN.md",
    "docs/windows-signpath-setup.zh-CN.md",
    "docs/remote-approval-reports/OPEN-QUESTIONS.md",
    "docs/remote-approval-reports/R3-B-unsigned-acceptance.md",
]

errors = []
tables = 0
for filename in DOCUMENTS:
    fence = False
    expected = None
    for line_number, line in enumerate((ROOT / filename).read_text().splitlines(), 1):
        if line.lstrip().startswith("```"):
            fence = not fence
            expected = None
            continue
        if fence:
            continue
        if line.strip().startswith("|"):
            count = len(re.findall(r"(?<!\\)\|", line))
            if expected is None:
                expected = count
                tables += 1
            if expected != count:
                errors.append({"file": filename, "line": line_number,
                               "pipes": count, "expected": expected})
        else:
            expected = None

architecture = (ROOT / DOCUMENTS[0]).read_text()
headings = set(re.findall(r"^#{1,6}\s+(\d+(?:\.\d+)*)(?=[\s.])", architecture, re.M))
references = set(re.findall(r"§(\d+(?:\.\d+)*)", architecture))
external = {"10.3", "10.4", "11.4"}
general = (ROOT / "docs/architecture-2026-10.md").read_text()
general_headings = set(re.findall(r"^#{1,6}\s+(\d+(?:\.\d+)*)(?=[\s.])", general, re.M))
assert external <= general_headings
appendices = set(re.findall(r"^#{1,6}\s+(?:附录\s+)?([A-F](?:\.\d+)?)(?=[\s.])", architecture, re.M))
appendix_refs = set(re.findall(r"附录\s+([A-F](?:\.\d+)?)", architecture))
missing_links = []
for filename in [DOCUMENTS[-1], DOCUMENTS[5]]:
    path = ROOT / filename
    for target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", path.read_text()):
        if ":" in target or target.startswith("#"):
            continue
        file = target.split("#", 1)[0]
        if file and not (path.parent / file).exists():
            missing_links.append({"file": filename, "target": target})

result = {
    "files": DOCUMENTS, "table_groups": tables, "table_errors": errors,
    "section_refs_missing": sorted(references - headings - external),
    "external_section_refs_verified": sorted(external),
    "appendix_refs_missing": sorted(appendix_refs - appendices),
    "new_document_links_missing": missing_links,
}
Path(__file__).with_suffix(".json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
print(json.dumps(result, ensure_ascii=False))
assert not (errors or result["section_refs_missing"] or result["appendix_refs_missing"] or missing_links)
