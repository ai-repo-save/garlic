"""Opt-in Linux CLI regression: multidex smali lookup must release scanned DEXes.

The observed bug exhausted memory while searching an APK, although each DEX
could be queried independently. A temporary APK repeats a legal DEX with a large
source-name string, followed by the requested class. A child-only address-space
limit makes that failure reproducible without exhausting the host. This checks
successful lookup and not-found semantics, not throughput or a memory benchmark.
DEX035 layout: https://source.android.com/docs/core/runtime/dex-format
"""

import argparse
import hashlib
from pathlib import Path
import resource
import struct
import subprocess
import tempfile
import zipfile
import zlib


MEMORY_LIMIT = 128 * 1024 * 1024
EXPECTED = (
    ".class public abstract LTarget;\n"
    ".super Ljava/lang/Object;\n"
    '.source "Target.java"\n'
)


def uleb128(value):
    result = bytearray()
    while value >= 0x80:
        result.append((value & 0x7f) | 0x80)
        value >>= 7
    result.append(value)
    return result


def dex_fixture(descriptor, source):
    """One abstract class; ASCII strings keep MUTF-8 and UTF-16 lengths equal."""
    strings = sorted([descriptor, b"Ljava/lang/Object;", source])
    types = sorted([descriptor, b"Ljava/lang/Object;"], key=strings.index)
    string_ids_off = 112
    type_ids_off = string_ids_off + 4 * len(strings)
    class_defs_off = type_ids_off + 4 * len(types)
    data_off = class_defs_off + 32
    data = bytearray(data_off)
    offsets = []
    for text in strings:
        offsets.append(len(data))
        data.extend(uleb128(len(text)) + text + b"\0")
    while len(data) % 4:
        data.append(0)
    map_off = len(data)
    entries = [
        (0x0000, 1, 0),
        (0x0001, len(strings), string_ids_off),
        (0x0002, len(types), type_ids_off),
        (0x0006, 1, class_defs_off),
        (0x2002, len(strings), offsets[0]),
        (0x1000, 1, map_off),
    ]
    data.extend(struct.pack("<I", len(entries)))
    for kind, size, offset in entries:
        data.extend(struct.pack("<HHII", kind, 0, size, offset))
    data[:8] = b"dex\n035\0"
    struct.pack_into(
        "<20I", data, 32,
        len(data), 112, 0x12345678, 0, 0, map_off,
        len(strings), string_ids_off, len(types), type_ids_off,
        0, 0, 0, 0, 0, 0, 1, class_defs_off, len(data) - data_off, data_off,
    )
    struct.pack_into("<3I", data, string_ids_off, *offsets)
    struct.pack_into("<2I", data, type_ids_off, *(strings.index(t) for t in types))
    struct.pack_into(
        "<8I", data, class_defs_off,
        types.index(descriptor), 0x401, types.index(b"Ljava/lang/Object;"),
        0, strings.index(source), 0, 0, 0,
    )
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]))
    return data


def limit_child_memory():
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY_LIMIT, MEMORY_LIMIT))


def query(binary, path, class_name):
    return subprocess.run(
        [str(binary), str(path), "-s", "-c", class_name],
        capture_output=True, text=True, timeout=60, preexec_fn=limit_child_memory,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("binary", type=Path, help="Garlic executable to verify")
    binary = parser.parse_args().binary.resolve()
    with tempfile.TemporaryDirectory(prefix="garlic-smali-lookup-") as directory:
        root = Path(directory)
        absent = dex_fixture(b"LAbsent;", b"A" * (256 * 1024))
        target = dex_fixture(b"LTarget;", b"Target.java")
        dex = root / "target.dex"
        dex.write_bytes(target)
        apk = root / "multidex.apk"
        with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for i in range(512):
                archive.writestr(f"classes{i + 1}.dex", absent)
            archive.writestr("classes513.dex", target)
        nested = root / "nested.apk"
        with zipfile.ZipFile(nested, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(apk, "splits/base.apk")
        for path in [dex, apk, nested]:
            result = query(binary, path, "Target")
            assert (result.returncode, result.stdout, result.stderr) == (0, EXPECTED, ""), (
                path.name, result.returncode, result.stdout, result.stderr,
            )
        result = query(binary, apk, "Missing")
        assert (result.returncode, result.stdout, result.stderr) == (
            1, "", "[garlic] Class not found: Missing\n",
        ), (result.returncode, result.stdout, result.stderr)
    print("Smali lookup lifetime regression passed: DEX, multidex APK, nested APK, not found")


if __name__ == "__main__":
    main()
