#!/usr/bin/env python3
"""Keep shared Cargo.toml/Cargo.lock untouched while W0 integrates W8's dependency edges."""
import pathlib
import shutil

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "rust"
SHADOW = SOURCE / "target-w8" / "verification"
SHADOW.mkdir(parents=True, exist_ok=True)
shutil.copyfile(SOURCE / "Cargo.toml", SHADOW / "Cargo.toml")
if not (SHADOW / "Cargo.lock").exists():
    shutil.copyfile(SOURCE / "Cargo.lock", SHADOW / "Cargo.lock")
for crate in (SOURCE / "crates").iterdir():
    if not (crate / "Cargo.toml").is_file():
        continue
    destination = SHADOW / "crates" / crate.name
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(crate / "Cargo.toml", destination / "Cargo.toml")
    for item in crate.iterdir():
        if item.name == "Cargo.toml" or item.suffix == ".profraw":
            continue
        link = destination / item.name
        if not link.exists() and not link.is_symlink():
            link.symlink_to(item)
print(SHADOW / "Cargo.toml")
