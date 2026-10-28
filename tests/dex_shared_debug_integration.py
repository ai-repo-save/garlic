"""Shared DEX debug streams retain each method's parameter and position semantics.

Independent authority: Android DEX debug_info_item and Dalvik instruction formats:
https://source.android.com/docs/core/runtime/dex-format#debug-info-item
https://source.android.com/docs/core/runtime/instruction-formats
Hand-encoded streams use code-unit addresses, signed line deltas, local lifetimes,
and two parameter names excluding 'this'. Smali directives are decoded to semantic
records rather than compared as formatted text. No SDK or external APK is used.
"""

import argparse
import hashlib
import re
import struct
import subprocess
import tempfile
import zipfile
import zlib
from pathlib import Path


def uleb128(value):
    result = bytearray()
    while value >= 0x80:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return result


def dex_fixture(suffix, line_start, invalid=False):
    descriptor = f"LDebug{suffix};"
    strings = sorted(
        ["I", "J", descriptor, "Ljava/lang/Object;", "V", "VIJ", "VJI"]
        + list("abcde")
        + [f"arg{suffix}", f"wide{suffix}", f"local{suffix}", f"file{suffix}"]
    )
    string_id = {text: i for i, text in enumerate(strings)}
    types = ["I", "J", descriptor, "Ljava/lang/Object;", "V"]
    type_id = {text: i for i, text in enumerate(types)}
    string_ids_off = 112
    type_ids_off = string_ids_off + len(strings) * 4
    proto_ids_off = type_ids_off + len(types) * 4
    method_ids_off = proto_ids_off + 2 * 12
    class_defs_off = method_ids_off + 5 * 8
    data_off = class_defs_off + 32
    data = bytearray(data_off)

    def align():
        while len(data) % 4:
            data.append(0)

    string_offsets = []
    for text in strings:
        string_offsets.append(len(data))
        data.extend(uleb128(len(text)) + text.encode() + b"\0")
    align()
    type_lists_off = len(data)
    data.extend(struct.pack("<IHHIHH", 2, 0, 1, 2, 1, 0))

    def debug_stream(start):
        stream = bytearray(uleb128(start) + b"\x02")
        stream.extend(uleb128(string_id[f"wide{suffix}"] + 1))
        stream.extend(uleb128(string_id[f"arg{suffix}"] + 1))
        # Prologue, initial position, local v0:I; then PC +1, line +3.
        stream.extend(b"\x07\x0e\x03\x00")
        name = len(strings) + 1 if invalid else string_id[f"local{suffix}"] + 1
        stream.extend(uleb128(name) + b"\x01\x01\x01\x02\x03\x0e")
        # Special opcode: address +2 and line -1. End/restart local v0.
        stream.extend(b"\x2b\x05\x00\x01\x01\x06\x00\x09")
        stream.extend(uleb128(string_id[f"file{suffix}"] + 1))
        # Extended local v1:J with signature J, then line +18 at PC 5.
        stream.extend(b"\x04\x01")
        stream.extend(uleb128(string_id[f"local{suffix}"] + 1))
        stream.extend(b"\x02" + uleb128(string_id["J"] + 1))
        stream.extend(b"\x01\x01\x02\x12\x08\x0e\x00")
        return stream

    debug_off = len(data)
    data.extend(debug_stream(line_start))
    other_debug_off = len(data)
    data.extend(debug_stream(line_start + 20))
    align()
    code_offsets = []
    # a/c/d/e are static; b is an instance method. c reverses parameter types.
    specs = [(6, 3, False), (7, 4, True), (8, 3, True), (6, 3, False), (6, 3, False)]
    for i, (registers, ins, wide_instruction) in enumerate(specs):
        align()
        code_offsets.append(len(data))
        debug = 0 if i == 4 else other_debug_off if i == 3 else debug_off
        units = (
            [0, 0x0013, 0, 0, 0, 0, 0, 0x000E]
            if wide_instruction
            else [0] * 7 + [0x000E]
        )
        data.extend(struct.pack("<HHHHII8H", registers, ins, 0, 0, debug, 8, *units))
    class_data_off = len(data)
    data.extend(b"\x00\x00\x04\x01")
    for i, diff in [(0, 0), (2, 2), (3, 1), (4, 1)]:
        data.extend(uleb128(diff) + b"\x09" + uleb128(code_offsets[i]))
    data.extend(b"\x01\x01" + uleb128(code_offsets[1]))
    align()
    map_off = len(data)
    entries = [
        (0x0000, 1, 0),
        (0x0001, len(strings), string_ids_off),
        (0x0002, len(types), type_ids_off),
        (0x0003, 2, proto_ids_off),
        (0x0005, 5, method_ids_off),
        (0x0006, 1, class_defs_off),
        (0x2002, len(strings), string_offsets[0]),
        (0x1001, 2, type_lists_off),
        (0x2003, 2, debug_off),
        (0x2001, 5, code_offsets[0]),
        (0x2000, 1, class_data_off),
        (0x1000, 1, map_off),
    ]
    data.extend(struct.pack("<I", len(entries)))
    for kind, size, offset in entries:
        data.extend(struct.pack("<HHII", kind, 0, size, offset))
    data[:8] = b"dex\n035\0"
    struct.pack_into(
        "<20I",
        data,
        32,
        len(data),
        112,
        0x12345678,
        0,
        0,
        map_off,
        len(strings),
        string_ids_off,
        len(types),
        type_ids_off,
        2,
        proto_ids_off,
        0,
        0,
        5,
        method_ids_off,
        1,
        class_defs_off,
        len(data) - data_off,
        data_off,
    )
    struct.pack_into(f"<{len(strings)}I", data, string_ids_off, *string_offsets)
    struct.pack_into(
        f"<{len(types)}I", data, type_ids_off, *(string_id[t] for t in types)
    )
    for i, (shorty, params) in enumerate(
        [("VIJ", type_lists_off), ("VJI", type_lists_off + 8)]
    ):
        struct.pack_into(
            "<III",
            data,
            proto_ids_off + i * 12,
            string_id[shorty],
            type_id["V"],
            params,
        )
    for i, name in enumerate("abcde"):
        struct.pack_into(
            "<HHI",
            data,
            method_ids_off + i * 8,
            type_id[descriptor],
            0 if i == 2 else 1,
            string_id[name],
        )
    struct.pack_into(
        "<8I",
        data,
        class_defs_off,
        type_id[descriptor],
        1,
        type_id["Ljava/lang/Object;"],
        0,
        0xFFFFFFFF,
        0,
        class_data_off,
        0,
    )
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]))
    return data


def debug_records(text):
    methods = {}
    records = None
    offset = 0
    widths = {"nop": 1, "const/16": 2, "return-void": 1}
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith(".method "):
            name = line.split()[-1]
            records = []
            methods[name] = records
            offset = 0
        elif line == ".end method":
            records = None
        elif records is not None:
            if line.startswith(".registers "):
                continue
            if line.startswith(".param "):
                match = re.fullmatch(r'\.param p(\d+), "([^"]+)"', line)
                assert match, line
                records.append(("parameter", int(match[1]), match[2]))
            elif line.startswith(".line "):
                records.append((offset, "line", int(line.split()[1])))
            elif line.startswith(".local "):
                match = re.fullmatch(
                    r'\.local v(\d+), "([^"]+)":(I|J)(?:, "(J)")?', line
                )
                assert match, line
                records.append(
                    (offset, "local", int(match[1]), match[2], match[3], match[4])
                )
            elif line.startswith((".end local ", ".restart local ")):
                operation = "end" if line.startswith(".end ") else "restart"
                records.append((offset, operation, int(line.split()[-1][1:])))
            elif line.startswith(".source "):
                records.append((offset, "source", line.split('"')[1]))
            elif line in (".prologue", ".epilogue"):
                records.append((offset, line[1:]))
            else:
                offset += widths[line.split()[0]]
    return methods


def expected_records(suffix, start, parameters):
    return parameters + [
        (0, "prologue"),
        (0, "line", start),
        (0, "local", 0, f"local{suffix}", "I", None),
        (1, "line", start + 3),
        (3, "line", start + 2),
        (3, "end", 0),
        (4, "restart", 0),
        (4, "source", f"file{suffix}"),
        (4, "local", 1, f"local{suffix}", "J", "J"),
        (5, "epilogue"),
        (5, "line", start + 20),
    ]


def check_class(text, suffix, start):
    static = [("parameter", 0, f"wide{suffix}"), ("parameter", 2, f"arg{suffix}")]
    instance = [("parameter", 1, f"wide{suffix}"), ("parameter", 3, f"arg{suffix}")]
    reversed_types = [
        ("parameter", 0, f"wide{suffix}"),
        ("parameter", 1, f"arg{suffix}"),
    ]
    expected = {
        "a(JI)V": expected_records(suffix, start, static),
        "b(JI)V": expected_records(suffix, start, instance),
        "c(IJ)V": expected_records(suffix, start, reversed_types),
        "d(JI)V": expected_records(suffix, start + 20, static),
        "e(JI)V": [],
    }
    actual = debug_records(text)
    assert actual == expected, (actual, expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("binary", type=Path, help="Garlic executable to verify")
    binary = str(parser.parse_args().binary.resolve())
    with tempfile.TemporaryDirectory(prefix="garlic-shared-debug-") as directory:
        root = Path(directory)
        fixtures = [("A", 40), ("B", 80)]
        dexes = [dex_fixture(suffix, line) for suffix, line in fixtures]
        for dex, (suffix, line) in zip(dexes, fixtures, strict=True):
            path = root / f"{suffix}.dex"
            path.write_bytes(dex)
            result = subprocess.run(
                [binary, str(path), "-s", "-c", f"Debug{suffix}"],
                capture_output=True,
                text=True,
                check=True,
            )
            check_class(result.stdout, suffix, line)
        apk = root / "shared.apk"
        with zipfile.ZipFile(apk, "w") as archive:
            archive.writestr("classes.dex", dexes[0])
            archive.writestr("classes2.dex", dexes[1])
        output = root / "smali"
        subprocess.run(
            [binary, str(apk), "-s", "-t", "4", "-o", str(output)],
            capture_output=True,
            text=True,
            check=True,
        )
        generated = {path.stem: path.read_text() for path in output.rglob("*.smali")}
        assert sorted(generated) == ["DebugA", "DebugB"], generated
        for suffix, line in fixtures:
            check_class(generated[f"Debug{suffix}"], suffix, line)
        malformed = root / "invalid.dex"
        malformed.write_bytes(dex_fixture("A", 40, invalid=True))
        result = subprocess.run(
            [binary, str(malformed), "-s", "-c", "DebugA"],
            check=False,
            capture_output=True,
            text=True,
        )
        assert (result.returncode, result.stdout) == (2, ""), result
    print(
        "Shared DEX debug integration passed: method-local parameters, positions, locals and multidex"
    )


if __name__ == "__main__":
    main()
