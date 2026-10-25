#!/usr/bin/env python3
"""Load Garlic Jimple with a fixed Soot jar.

The script is explicit. It is not part of the default test set.
"""

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path


def parse_args():
    parser = argparse.ArgumentParser(
        description="Write one class as Jimple and load it with Soot."
    )
    parser.add_argument("--garlic", required=True, help="path to the garlic binary")
    parser.add_argument("--soot-jar", required=True, help="Soot jar, including dependencies")
    parser.add_argument("--dex", required=True, help="DEX or APK input")
    parser.add_argument("--class", dest="class_name", required=True,
                        help="class name or DEX descriptor")
    parser.add_argument("--java", default="java", help="java command")
    parser.add_argument("--boot-jar", action="append", default=[],
                        help="jar placed on the Soot classpath; repeatable")
    parser.add_argument("--android-jar",
                        help="android.jar passed to Soot as -force-android-jar")
    return parser.parse_args()


def jimple_filename(class_name):
    name = class_name
    if name.startswith("L") and name.endswith(";"):
        name = name[1:-1]
    return name.replace("/", ".") + ".jimple"


def soot_class(class_name):
    name = class_name
    if name.startswith("L") and name.endswith(";"):
        name = name[1:-1]
    return name.replace("/", ".")


def main():
    args = parse_args()
    garlic = Path(args.garlic)
    soot_jar = Path(args.soot_jar)
    dex = Path(args.dex)
    if not garlic.is_file() or not soot_jar.is_file() or not dex.is_file():
        print("input file is missing", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="garlic-jimple-") as tmp:
        out_dir = Path(tmp)
        jimple_path = out_dir / jimple_filename(args.class_name)
        print(f"jimple_write class={args.class_name}", file=sys.stderr)
        write = subprocess.run(
            [str(garlic), str(dex), "--jimple", "-c", args.class_name, "-o", str(jimple_path)],
            capture_output=True,
            text=True,
        )
        if write.returncode != 0 or not jimple_path.is_file() or jimple_path.stat().st_size == 0:
            sys.stderr.write(write.stderr)
            print(f"jimple_write_failed exit={write.returncode}", file=sys.stderr)
            return 1

        classpath = [str(out_dir)]
        classpath.extend(args.boot_jar)
        command = [
            args.java, "-jar", str(soot_jar),
            "-src-prec", "jimple",
            "-f", "n",
            "-cp", ":".join(classpath),
            "-allow-phantom-refs",
        ]
        if args.android_jar:
            command.extend(["-force-android-jar", args.android_jar])
        command.append(soot_class(args.class_name))
        print("soot_load " + " ".join(command), file=sys.stderr)
        loaded = subprocess.run(command, capture_output=True, text=True)
        if loaded.returncode != 0:
            sys.stderr.write(loaded.stdout)
            sys.stderr.write(loaded.stderr)
            print(f"soot_load_failed exit={loaded.returncode}", file=sys.stderr)
            return 1

    print(f"ok class={soot_class(args.class_name)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
