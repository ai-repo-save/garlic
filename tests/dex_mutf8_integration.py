"""Regression: DEX string_data_item MUTF-8 boundaries through CLI smali.

Independent authorities:
https://source.android.com/docs/core/runtime/dex-format#mutf-8
https://source.android.com/docs/core/runtime/dex-format#string-data-item
https://www.unicode.org/versions/Unicode16.0.0/core-spec/chapter-3/#G7404
Only 1/2/3-byte encodings are used; NUL is C0 80, supplementary characters
are two UTF-16 surrogates, and utf16_size counts code units, not encoded bytes.
All bytes/expected escapes below are explicit, not encoded by Garlic or an SDK.
"""

import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import zlib


# name, MUTF-8 bytes, UTF-16 code-unit count, expected smali string contents.
BOUNDARIES = [
    ("nul", b"\xc0\x80", 1, r"\u0000"),
    ("u0001", b"\x01", 1, r"\u0001"),
    ("u007e", b"\x7e", 1, "~"),
    ("u007f", b"\x7f", 1, r"\u007f"),
    ("u0080", b"\xc2\x80", 1, r"\u0080"),
    ("u07ff", b"\xdf\xbf", 1, r"\u07ff"),
    ("u0800", b"\xe0\xa0\x80", 1, r"\u0800"),
    ("ud7ff", b"\xed\x9f\xbf", 1, r"\ud7ff"),
    ("ud800", b"\xed\xa0\x80", 1, r"\ud800"),
    ("udbff", b"\xed\xaf\xbf", 1, r"\udbff"),
    ("udc00", b"\xed\xb0\x80", 1, r"\udc00"),
    ("udfff", b"\xed\xbf\xbf", 1, r"\udfff"),
    ("ue000", b"\xee\x80\x80", 1, r"\ue000"),
    ("uffff", b"\xef\xbf\xbf", 1, r"\uffff"),
    ("u10000", b"\xed\xa0\x80\xed\xb0\x80", 2, r"\ud800\udc00"),
    ("u10ffff", b"\xed\xaf\xbf\xed\xbf\xbf", 2, r"\udbff\udfff"),
]


def dex_fixture(payload, utf16_size):
    """DEX035: one abstract class, using the test string as its source name.

    Test payloads are empty or start with 'A', before the two descriptors in
    UTF-16 sort order. No bytecode, compiler, APK, or checked-in DEX is needed.
    """
    string_ids_off = 112
    type_ids_off = string_ids_off + 3 * 4
    class_defs_off = type_ids_off + 2 * 4
    data_off = class_defs_off + 32
    data = bytearray(data_off)
    string_offsets = []
    for size, encoded in [(utf16_size, payload), (7, b"LMutf8;"), (18, b"Ljava/lang/Object;")]:
        assert 0 <= size < 0x80  # All fixture length prefixes fit one ULEB128 byte.
        string_offsets.append(len(data))
        data.extend(bytes([size]) + encoded + b"\0")
    while len(data) % 4:
        data.append(0)
    map_off = len(data)
    entries = [
        (0x0000, 1, 0),
        (0x0001, 3, string_ids_off),
        (0x0002, 2, type_ids_off),
        (0x0006, 1, class_defs_off),
        (0x2002, 3, string_offsets[0]),
        (0x1000, 1, map_off),
    ]
    data.extend(struct.pack("<I", len(entries)))
    for kind, size, offset in entries:
        data.extend(struct.pack("<HHII", kind, 0, size, offset))
    data[:8] = b"dex\n035\0"
    struct.pack_into(
        "<20I", data, 32,
        len(data), 112, 0x12345678, 0, 0, map_off,
        3, string_ids_off, 2, type_ids_off, 0, 0, 0, 0, 0, 0,
        1, class_defs_off, len(data) - data_off, data_off,
    )
    struct.pack_into("<3I", data, string_ids_off, *string_offsets)
    struct.pack_into("<2I", data, type_ids_off, 1, 2)
    struct.pack_into("<8I", data, class_defs_off, 0, 0x401, 1, 0, 0, 0, 0, 0)
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]))
    return data


def main():
    binary = str(Path(sys.argv[1]).resolve())
    valid = [("empty", b"", 0, "")]
    # Sentinels detect truncation or accidental consumption of the following byte.
    valid += [(name, b"A" + raw + b"Z", size + 2, "A" + text + "Z")
              for name, raw, size, text in BOUNDARIES]
    invalid = [
        ("early-nul", b"A\0Z", 3),
        ("bare-continuation-80", b"A\x80Z", 3),
        ("bare-continuation-bf", b"A\xbfZ", 3),
        ("length-too-short", b"A\x7fZ", 2),
        ("length-too-long", b"A\x7fZ", 4),
    ]
    with tempfile.TemporaryDirectory(prefix="garlic-dex-mutf8-") as directory:
        for name, payload, size, expected in valid:
            fixture = Path(directory, name + ".dex")
            fixture.write_bytes(dex_fixture(payload, size))
            result = subprocess.run(
                [binary, str(fixture), "-s", "-c", "Mutf8"],
                capture_output=True, text=True, timeout=10,
            )
            assert result.returncode == 0, (name, result.returncode, result.stderr)
            lines = [line.strip() for line in result.stdout.splitlines()]
            assert ".class public abstract LMutf8;" in lines, (name, result.stdout)
            sources = [line for line in lines if line.startswith(".source ")]
            assert sources == [f'.source "{expected}"'], (name, sources, expected)
        for name, payload, size in invalid:
            fixture = Path(directory, name + ".dex")
            fixture.write_bytes(dex_fixture(payload, size))
            result = subprocess.run(
                [binary, str(fixture), "-s", "-c", "Mutf8"],
                capture_output=True, text=True, timeout=10,
            )
            assert result.returncode == 2, (name, result.returncode, result.stderr)
            assert not result.stdout, (name, result.stdout)
    print(f"DEX MUTF-8 regression passed: {len(valid)} valid boundaries, {len(invalid)} rejected strings")


if __name__ == "__main__":
    main()
