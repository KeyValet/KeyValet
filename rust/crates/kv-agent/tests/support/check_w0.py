"""Compile current W0 contracts with existing artifacts, without adding crate dependencies.

CARGO_TARGET_DIR=rust/target-w6 W6_W0_DEPS=rust/target-w1/debug/deps python3 rust/crates/kv-agent/tests/support/check_w0.py
W6_W0_DEPS selects W0's existing build artifacts; current W0 and W6 source is compiled fresh.
"""
import json
import os
from pathlib import Path
import subprocess
import re


def main():
    crate = Path(__file__).resolve().parents[2]
    original = crate.parents[1]
    target = Path(os.environ.get("CARGO_TARGET_DIR", original / "target-w6")).resolve()
    cached = Path(os.environ["W6_W0_DEPS"]).resolve()
    toolchain = os.environ.get("W6_TOOLCHAIN", "1.99.0")
    environment = dict(os.environ, CARGO_TARGET_DIR=str(target))
    generated = target / "w6-w0"
    generated.mkdir(exist_ok=True)
    core = Path(os.environ.get("W6_W0_CORE", str(sorted(cached.glob("libkv_core-*.rlib"))[0])))
    metadata = subprocess.check_output(["rustc", "+" + toolchain, "-Z", "ls=root", str(core)], env=dict(environment, RUSTC_BOOTSTRAP="1"), text=True)
    w0_libraries = {}
    for line in metadata.splitlines():
        matched = re.match(r"\d+ ([a-z0-9_]+)-([a-f0-9]+) hash", line)
        if matched and matched[1] not in w0_libraries:
            w0_libraries[matched[1]] = str(cached / ("lib" + matched[1] + "-" + matched[2] + ".rlib"))
    source = "#[allow(dead_code)]\npub mod remote {\n"
    for name in ["canonical", "error", "keys", "pairing", "types", "validation"]:
        path = original / "crates/kv-core/src/remote" / (name + ".rs")
        source += '#[path = ' + json.dumps(str(path)) + '] pub mod ' + name + ';\n'
    source += "pub use error::{RemoteError, Result};\npub use types::*;\npub use keys::{DeviceKeyProvider, MessageSigner, SoftwareDeviceKey};\n}\n"
    source += '#[path = ' + json.dumps(str(crate / "src/remote/mod.rs")) + '] pub mod ui;\n'
    source += '#[path = ' + json.dumps(str(crate / "src/presence.rs")) + '] pub mod presence;\n'
    (generated / "w0_source.rs").write_text(source)
    library = generated / "libw6_w0.rlib"
    compile_w0 = ["rustc", "+" + toolchain, "--edition=2021", "--crate-name=w6_w0", "--crate-type=rlib", str(generated / "w0_source.rs"), "-L", "dependency=" + str(cached), "-o", str(library)]
    for name in ["kv_ipc", "serde", "serde_json", "serde_jcs", "p256", "rsa", "sha2", "hkdf", "rand_core", "base64", "zeroize"]:
        compile_w0 += ["--extern", name + "=" + w0_libraries[name]]
    compile_w0 += ["--extern", "kv_i18n=" + str(sorted(cached.glob("libkv_i18n-*.rlib"))[0])]
    subprocess.run(compile_w0, check=True, env=environment)
    binary = generated / "flows"
    command = ["rustc", "+" + toolchain, "--edition=2021", "--test", str(crate / "tests/support/w0_flows.rs"), "-L", "dependency=" + str(cached), "-o", str(binary)]
    command += ["--extern", "w6_w0=" + str(library)]
    for name in ["kv_ipc", "serde_json", "base64", "zeroize"]:
        command += ["--extern", name + "=" + w0_libraries[name]]
    subprocess.run(command, check=True, env=dict(environment, CARGO_MANIFEST_DIR=str(crate), OUT_DIR=str(generated)))
    subprocess.run([str(binary)], check=True, env=environment)


if __name__ == "__main__":
    main()
