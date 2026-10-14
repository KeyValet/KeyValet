#!/usr/bin/env python3
"""Capture or tap KeyValet only; discard screenshots if foreground ownership changes."""
import argparse
import pathlib
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", default="28301FDH200GY5")
    actions = parser.add_subparsers(dest="action", required=True)
    capture = actions.add_parser("capture")
    capture.add_argument("output", type=pathlib.Path)
    tap = actions.add_parser("tap")
    tap.add_argument("x", type=int)
    tap.add_argument("y", type=int)
    swipe = actions.add_parser("swipe")
    for name in ("x1", "y1", "x2", "y2"):
        swipe.add_argument(name, type=int)
    swipe.add_argument("duration_ms", type=int, nargs="?", default=350)
    args = parser.parse_args()
    adb = ["adb", "-s", args.serial]

    def require_keyvalet():
        dump = subprocess.check_output(adb + ["shell", "dumpsys", "window"], text=True)
        focus = next((line for line in dump.splitlines() if "mCurrentFocus=" in line), "")
        app = next((line for line in dump.splitlines() if "mFocusedApp=" in line), "")
        own_activity = "dev.keyvalet.mobile/" in focus
        own_prompt = "dev.keyvalet.mobile/" in app and "BiometricPrompt" in focus
        if not (own_activity or own_prompt):
            raise SystemExit("Skipped: KeyValet or its biometric prompt is not focused.")

    require_keyvalet()
    if args.action == "capture":
        if args.output.suffix != ".png":
            parser.error("capture output must be a PNG")
        # Let task-switch animation finish, then check again before and after capture.
        time.sleep(0.5)
        require_keyvalet()
        png = subprocess.check_output(adb + ["exec-out", "screencap", "-p"])
        require_keyvalet()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(png)
        print(f"captured={args.output} at_unix_ms={time.time_ns() // 1_000_000}")
    elif args.action == "tap":
        if args.x < 0 or args.y < 0:
            parser.error("tap coordinates must be nonnegative")
        subprocess.run(adb + ["shell", "input", "tap", str(args.x), str(args.y)], check=True)
        print(f"tap=({args.x},{args.y}) at_unix_ms={time.time_ns() // 1_000_000}")
    else:
        if min(args.x1, args.y1, args.x2, args.y2) < 0 or not 1 <= args.duration_ms <= 2000:
            parser.error("swipe coordinates must be nonnegative and duration must be 1–2000 ms")
        subprocess.run(adb + ["shell", "input", "swipe", str(args.x1), str(args.y1), str(args.x2), str(args.y2), str(args.duration_ms)], check=True)
        print(f"swipe=({args.x1},{args.y1})->({args.x2},{args.y2}) at_unix_ms={time.time_ns() // 1_000_000}")


if __name__ == "__main__":
    main()
