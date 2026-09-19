#!/usr/bin/env python3
"""Regression: compile a small guard to DEX, decompile, then execute its Java.

Origin: missing boolean NOT assignment and missing generic superclass observed
in DEX output. Expected behavior is the fixture's Java truth table, not golden
decompiler text. All generated files stay in a disposable temporary directory.
Requires a local JDK and Android build-tools d8; never downloads dependencies.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile


def run(*args):
    subprocess.run([str(arg) for arg in args], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--garlic", required=True)
    parser.add_argument("--d8", required=True)
    parser.add_argument("--javac", default="javac")
    parser.add_argument("--java", default="java")
    args = parser.parse_args()
    fixture = Path(__file__).parent / "fixtures" / "dex-rendering"
    with tempfile.TemporaryDirectory(prefix="garlic-dex-rendering-") as temporary:
        root = Path(temporary)
        original, dex, output, roundtrip = [root / p for p in ("original", "dex", "output", "roundtrip")]
        for directory in (original, dex, output, roundtrip):
            directory.mkdir()
        run(args.javac, "--release", "8", "-d", original, fixture / "Guard.java")
        run(args.d8, "--output", dex, *sorted(original.rglob("*.class")))
        run(args.javac, "--release", "8", "-cp", original, "-d", original, fixture / "CheckGuard.java")
        run(args.java, "-cp", original, "regression.CheckGuard")
        run(args.garlic, dex / "classes.dex", "-t", "1", "-o", output)
        run(args.javac, "--release", "8", "-d", roundtrip,
            output / "regression" / "Guard.java", fixture / "CheckGuard.java")
        run(args.java, "-cp", roundtrip, "regression.CheckGuard")


if __name__ == "__main__":
    main()
