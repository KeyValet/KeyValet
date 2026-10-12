"""Run W0 compatibility tests without adding a platform -> core dependency.

CARGO_TARGET_DIR=target-w1 python3 crates/kv-platform/tests/support/check_w0.py
Append --ignored remote_se_w0 on an unlocked Apple Silicon Mac for hardware tests.
Set W1_INSTRUMENT_COVERAGE=1 to export the standalone object's coverage-w0.lcov.
"""
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    crate = Path(__file__).resolve().parents[2]
    workspace = Path(os.environ.get("W1_RUST_ROOT", crate.parents[1])).resolve()
    target = Path(os.environ.get("CARGO_TARGET_DIR", workspace / "target-w1")).resolve()
    toolchain = os.environ.get("W1_TOOLCHAIN", "1.99.0")
    target.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ, CARGO_TARGET_DIR=str(target))
    instrument = os.environ.get("W1_INSTRUMENT_COVERAGE") == "1"
    binary = target / ("w0-compatibility.exe" if os.name == "nt" else "w0-compatibility")
    if instrument:
        profile_dir = target / "coverage-w0"
        profile_dir.mkdir(exist_ok=True)
        previous = {path: path.stat().st_mtime_ns for path in profile_dir.glob("*.profraw")}
        environment["LLVM_PROFILE_FILE"] = str(profile_dir / "%p-%m.profraw")
    artifacts = subprocess.run(
        ["cargo", "+" + toolchain, "build", "-p", "kv-core", "-p", "kv-platform",
         "-p", "kv-agent", "-p", "kv-touchid", "--locked", "--message-format=json"],
        cwd=workspace, env=environment, text=True, stdout=subprocess.PIPE,
    )
    libraries = {}
    for line in artifacts.stdout.splitlines():
        event = json.loads(line)
        if event.get("reason") == "compiler-message" and event["message"]["level"] == "error":
            diagnostic = event["message"]
            code = (diagnostic.get("code") or {}).get("code", "compile_error")
            span = next((span for span in diagnostic["spans"] if span["is_primary"]), None)
            location = (span["file_name"] + ":" + str(span["line_start"])) if span else "unknown location"
            print("Cargo diagnostic " + code + " at " + location, file=sys.stderr)
        if event.get("reason") == "compiler-artifact":
            for filename in event["filenames"]:
                if filename.endswith(".rlib"):
                    libraries[event["target"]["name"]] = filename
    if artifacts.returncode:
        raise SystemExit(artifacts.returncode)
    args = ["rustc", "+" + toolchain, "--edition=2021", "--test",
            "--error-format=json",
            str(crate / "tests/support/w0_compatibility.rs"),
            "-L", "dependency=" + str(target / "debug/deps"),
            "-o", str(binary)]
    if instrument:
        args += ["-C", "instrument-coverage"]
    for name in ["kv_core", "kv_platform", "kv_ipc", "kv_agent", "serde_json", "zeroize", "tempfile", "rsa", "sha2", "libc"]:
        args += ["--extern", name + "=" + libraries[name]]
    compiled = subprocess.run(args, cwd=workspace, env=dict(environment, CARGO_MANIFEST_DIR=str(crate)),
                              text=True, stderr=subprocess.PIPE)
    for line in compiled.stderr.splitlines():
        diagnostic = json.loads(line)
        if diagnostic.get("level") == "error":
            code = (diagnostic.get("code") or {}).get("code", "compile_error")
            span = next((span for span in diagnostic.get("spans", []) if span["is_primary"]), None)
            location = (span["file_name"] + ":" + str(span["line_start"])) if span else "unknown location"
            print("Rust diagnostic " + code + " at " + location, file=sys.stderr)
    if compiled.returncode:
        raise SystemExit(compiled.returncode)
    tested = subprocess.run([str(binary), *sys.argv[1:]], env=environment)
    if instrument and tested.returncode == 0:
        version = subprocess.check_output(["rustc", "+" + toolchain, "-vV"], text=True)
        host = next(line.removeprefix("host: ") for line in version.splitlines() if line.startswith("host: "))
        sysroot = Path(subprocess.check_output(["rustc", "+" + toolchain, "--print", "sysroot"], text=True).strip())
        suffix = ".exe" if os.name == "nt" else ""
        llvm = sysroot / "lib/rustlib" / host / "bin"
        profiles = [path for path in profile_dir.glob("*.profraw")
                    if previous.get(path) != path.stat().st_mtime_ns]
        merged = profile_dir / "merged.profdata"
        subprocess.run([str(llvm / ("llvm-profdata" + suffix)), "merge", "-sparse",
                        *[str(path) for path in profiles], "-o", str(merged)], check=True)
        with (target / "coverage-w0.lcov").open("w") as output:
            subprocess.run([str(llvm / ("llvm-cov" + suffix)), "export", "-format=lcov",
                            "-instr-profile=" + str(merged), str(binary)], stdout=output, check=True)
        print("Standalone coverage exported to " + str(target / "coverage-w0.lcov"))
    raise SystemExit(tested.returncode)


if __name__ == "__main__":
    main()
