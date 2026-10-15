"""Integration regression for shared switch payloads and zero-width array data.

Independent authority: Dalvik bytecode defines packed-switch targets relative to
each switch instruction, and a zero element width is not a representable array
payload width. The code units are hand encoded. Type/prototype tables and
static-method lists are well-formed; the zero array width is deliberately
malformed. The fixture is disassembled, not executed.
"""

import argparse
import hashlib
import struct
import subprocess
import tempfile
import zlib
from pathlib import Path


def uleb128(value):
    data = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            data.append(byte | 0x80)
        else:
            data.append(byte)
            return bytes(data)


def dex_with_code(class_name, method_name, code_units):
    strings = [f"L{class_name};", "Ljava/lang/Object;", "V", method_name]
    type_string_indices = (0, 1, 2)
    type_count = len(type_string_indices)
    string_ids_off = 112
    type_ids_off = string_ids_off + 4 * len(strings)
    proto_ids_off = type_ids_off + 4 * type_count
    method_ids_off = proto_ids_off + 12
    class_defs_off = method_ids_off + 8
    data_off = class_defs_off + 32
    data = bytearray(data_off)
    string_offsets = []
    for text in strings:
        string_offsets.append(len(data))
        data.extend(uleb128(len(text)) + text.encode() + b"\0")
    while len(data) % 4:
        data.append(0)
    code_off = len(data)
    data.extend(struct.pack("<HHHHII", 1, 0, 0, 0, 0, len(code_units)))
    data.extend(struct.pack(f"<{len(code_units)}H", *code_units))
    class_data_off = len(data)
    data.extend(b"\0\0\1\0\0\x09" + uleb128(code_off))
    while len(data) % 4:
        data.append(0)
    map_off = len(data)
    entries = [
        (0x0000, 1, 0),
        (0x0001, len(strings), string_ids_off),
        (0x0002, type_count, type_ids_off),
        (0x0003, 1, proto_ids_off),
        (0x0005, 1, method_ids_off),
        (0x0006, 1, class_defs_off),
        (0x2002, len(strings), string_offsets[0]),
        (0x2001, 1, code_off),
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
        type_count,
        type_ids_off,
        1,
        proto_ids_off,
        0,
        0,
        1,
        method_ids_off,
        1,
        class_defs_off,
        len(data) - data_off,
        data_off,
    )
    struct.pack_into("<4I", data, string_ids_off, *string_offsets)
    struct.pack_into(f"<{type_count}I", data, type_ids_off, *type_string_indices)
    struct.pack_into("<3I", data, proto_ids_off, 2, 2, 0)
    struct.pack_into("<HHI", data, method_ids_off, 0, 0, 3)
    struct.pack_into("<8I", data, class_defs_off, 0, 1, 1, 0, 0xFFFFFFFF, 0, class_data_off, 0)
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]))
    return data


def disassemble(binary, dex_bytes, directory, name):
    fixture = Path(directory, f"{name}.dex")
    output = Path(directory, name)
    fixture.write_bytes(dex_bytes)
    subprocess.run(
        [binary, str(fixture), "-s", "-t", "1", "-o", str(output)],
        check=True,
        capture_output=True,
        text=True,
    )
    return next(output.rglob("*.smali")).read_text()


def payload_targets(text, directive):
    blocks = []
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith(f".{directive}"):
            current = []
        elif line == f".end {directive}" and current is not None:
            blocks.append(current)
            current = None
        elif current is not None and line.startswith(":"):
            current.append(line.split()[-1])
    return blocks


def check_shared_switch(binary, directory):
    # Two packed-switch instructions share one payload. Relative target +3
    # lands at code unit 3 for the first switch and code unit 8 for the second.
    code = [
        0x002B, 0x000A, 0x0000,
        0x000E,
        0x000E,
        0x002B, 0x0005, 0x0000,
        0x000E,
        0x0000,
        0x0100, 0x0001, 0x0001, 0x0000, 0x0003, 0x0000,
    ]
    text = disassemble(binary, dex_with_code("SharedSwitch", "check", code), directory, "switch")
    blocks = payload_targets(text, "packed-switch")
    assert len(blocks) == 2, text
    assert blocks[0] != blocks[1], text
    assert all(blocks), text
    positions = [text.splitlines().index(next(line for line in text.splitlines() if line.strip() == target))
                 for target in (blocks[0][0], blocks[1][0])]
    assert positions[0] < positions[1], text


def check_zero_array_width(binary, directory):
    code = [0x000E, 0x0000, 0x0300, 0x0000, 0x9090, 0x9090]
    text = disassemble(binary, dex_with_code("ZeroArray", "check", code), directory, "array")
    assert ".array-data 1" in text, text
    assert ".end array-data" in text, text
    assert "0x90909090" not in text, text


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("binary", type=Path, help="Garlic executable to verify")
    binary = str(parser.parse_args().binary.resolve())
    with tempfile.TemporaryDirectory(prefix="garlic-smali-payload-") as directory:
        check_shared_switch(binary, directory)
        check_zero_array_width(binary, directory)
    print("Smali payload regression passed: shared switch targets and zero-width array data")


if __name__ == "__main__":
    main()
