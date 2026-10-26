#!/usr/bin/env -S uv run python
"""Opt-in DEX -> MCP Jimple -> Soot class -> JVM arithmetic integration.

Opcode/operand authority:
https://source.android.com/docs/core/runtime/dalvik-bytecode
https://source.android.com/docs/core/runtime/instruction-formats
Soot is used as a consumer; expected numeric results are independent literals.
"""

import argparse
import hashlib
import json
import re
import struct
import subprocess
import tempfile
import zipfile
import zlib
from pathlib import Path


def uleb(value):
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return result


def cases():
    result = []
    # opcodes: int/long 11 operations, float/double 5 operations.
    for kind, base, twoaddr, values, expected in [
        ("I", 0x90, 0xB0, [17, 3], [20, 14, 51, 5, 2, 1, 19, 18, 136, 2, 2]),
        ("J", 0x9B, 0xBB, [17, 3], [20, 14, 51, 5, 2, 1, 19, 18, 136, 2, 2]),
        ("F", 0xA6, 0xC6, [18.0, 4.0], [22.0, 14.0, 72.0, 4.5, 2.0]),
        ("D", 0xAB, 0xCB, [18.0, 4.0], [22.0, 14.0, 72.0, 4.5, 2.0]),
    ]:
        for offset, answer in enumerate(expected):
            params = kind + ("I" if kind == "J" and offset >= 8 else kind)
            right = 6 if kind in "JD" else 5
            for form in ("23x", "12x"):
                units = (
                    [base + offset | 4 << 8, 4 | right << 8]
                    if form == "23x"
                    else [twoaddr + offset | 4 << 8 | right << 12]
                )
                result.append(
                    (
                        f"binary{kind}{offset:02}{form}",
                        kind,
                        params,
                        units,
                        values,
                        answer,
                    )
                )
    for op, kind, answer in [
        (0x7B, "I", -17),
        (0x7C, "I", -18),
        (0x7D, "J", -17),
        (0x7E, "J", -18),
        (0x7F, "F", -17.0),
        (0x80, "D", -17.0),
    ]:
        result.append((f"unary{op:02x}", kind, kind, [op | 0x4400], [17], answer))
    for op, source, target, value, answer in [
        (0x81, "I", "J", 258, 258),
        (0x82, "I", "F", 258, 258.0),
        (0x83, "I", "D", 258, 258.0),
        (0x84, "J", "I", 258, 258),
        (0x85, "J", "F", 258, 258.0),
        (0x86, "J", "D", 258, 258.0),
        (0x87, "F", "I", 17.75, 17),
        (0x88, "F", "J", 17.75, 17),
        (0x89, "F", "D", 17.75, 17.75),
        (0x8A, "D", "I", 17.75, 17),
        (0x8B, "D", "J", 17.75, 17),
        (0x8C, "D", "F", 17.75, 17.75),
        (0x8D, "I", "B", 258, 2),
        (0x8E, "I", "C", 258, 258),
        (0x8F, "I", "S", 65535, -1),
    ]:
        result.append(
            (f"convert{op:02x}", target, source, [op | 0x4400], [value], answer)
        )
    for op, kind, right in [
        (0x2D, "F", 5),
        (0x2E, "F", 5),
        (0x2F, "D", 6),
        (0x30, "D", 6),
        (0x31, "J", 6),
    ]:
        result.append(
            (
                f"compare{op:02x}",
                "I",
                kind + kind,
                [op | 4 << 8, 4 | right << 8],
                [18, 4],
                1,
            )
        )
    return sorted(result)


def dex_fixture(methods):
    descriptors = sorted(
        {"LJimpleArithmetic;", "Ljava/lang/Object;"}
        | {kind for _, ret, params, *_ in methods for kind in ret + params}
    )
    prototypes = sorted(
        {(ret, params) for _, ret, params, *_ in methods},
        key=lambda p: (descriptors.index(p[0]), [descriptors.index(t) for t in p[1]]),
    )
    strings = sorted(
        set(descriptors)
        | {name for name, *_ in methods}
        | {ret + params for ret, params in prototypes}
    )
    sid = {s: i for i, s in enumerate(strings)}
    tid = {s: i for i, s in enumerate(descriptors)}
    pid = {p: i for i, p in enumerate(prototypes)}
    string_off = 112
    type_off = string_off + 4 * len(strings)
    proto_off = type_off + 4 * len(descriptors)
    method_off = proto_off + 12 * len(prototypes)
    class_off = method_off + 8 * len(methods)
    data_off = class_off + 32
    data = bytearray(data_off)

    def align():
        while len(data) % 4:
            data.append(0)

    string_offsets = []
    for text in strings:
        string_offsets.append(len(data))
        data.extend(uleb(len(text)) + text.encode() + b"\0")
    align()
    params_offsets = {}
    type_list_start = len(data)
    for _, params in prototypes:
        if params in params_offsets:
            continue
        params_offsets[params] = len(data)
        data.extend(struct.pack("<I", len(params)))
        data.extend(struct.pack(f"<{len(params)}H", *(tid[t] for t in params)))
        align()
    code_start = len(data)
    code_offsets = []
    for _, ret, params, units, *_ in methods:
        code_offsets.append(len(data))
        slots = sum(2 if t in "JD" else 1 for t in params)
        return_op = 0x10 if ret in "JD" else 0x0F
        # A widening unary result needs v4/v5, so a one-slot parameter starts at v5.
        prefix = [0x5401] if slots == 1 else []  # move v4, v5 (12x)
        units = prefix + units + [return_op | 4 << 8]
        data.extend(
            struct.pack("<HHHHII", max(6, slots + 4), slots, 0, 0, 0, len(units))
        )
        data.extend(struct.pack(f"<{len(units)}H", *units))
        align()
    class_data = len(data)
    data.extend(uleb(0) + uleb(0) + uleb(len(methods)) + uleb(0))
    for i, code in enumerate(code_offsets):
        data.extend(uleb(0 if i == 0 else 1) + uleb(9) + uleb(code))
    align()
    map_off = len(data)
    entries = [
        (0x0000, 1, 0),
        (0x0001, len(strings), string_off),
        (0x0002, len(descriptors), type_off),
        (0x0003, len(prototypes), proto_off),
        (0x0005, len(methods), method_off),
        (0x0006, 1, class_off),
        (0x2002, len(strings), string_offsets[0]),
        (0x1001, len(params_offsets), type_list_start),
        (0x2001, len(methods), code_start),
        (0x2000, 1, class_data),
        (0x1000, 1, map_off),
    ]
    data.extend(struct.pack("<I", len(entries)))
    for kind, count, offset in entries:
        data.extend(struct.pack("<HHII", kind, 0, count, offset))
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
        string_off,
        len(descriptors),
        type_off,
        len(prototypes),
        proto_off,
        0,
        0,
        len(methods),
        method_off,
        1,
        class_off,
        len(data) - data_off,
        data_off,
    )
    for i, offset in enumerate(string_offsets):
        struct.pack_into("<I", data, string_off + i * 4, offset)
    for i, desc in enumerate(descriptors):
        struct.pack_into("<I", data, type_off + i * 4, sid[desc])
    for i, (ret, params) in enumerate(prototypes):
        struct.pack_into(
            "<III",
            data,
            proto_off + i * 12,
            sid[ret + params],
            tid[ret],
            params_offsets[params],
        )
    for i, (name, ret, params, *_) in enumerate(methods):
        struct.pack_into(
            "<HHI",
            data,
            method_off + i * 8,
            tid["LJimpleArithmetic;"],
            pid[ret, params],
            sid[name],
        )
    struct.pack_into(
        "<8I",
        data,
        class_off,
        tid["LJimpleArithmetic;"],
        1,
        tid["Ljava/lang/Object;"],
        0,
        0xFFFFFFFF,
        0,
        class_data,
        0,
    )
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]))
    return data


def mcp(binary, calls):
    messages = [
        {
            "jsonrpc": "2.0",
            "id": i,
            "method": "tools/call",
            "params": {
                "name": "jimple",
                "arguments": {"path": str(path), "class_name": name},
            },
        }
        for i, (path, name) in enumerate(calls, 1)
    ]
    result = subprocess.run(
        [str(binary), "-m"],
        input="".join(json.dumps(m) + "\n" for m in messages),
        capture_output=True,
        text=True,
        check=True,
    )
    replies = [json.loads(line) for line in result.stdout.splitlines()]
    assert [r["id"] for r in replies] == list(range(1, len(calls) + 1)), replies
    return [r["result"]["content"][0]["text"] for r in replies]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--garlic", required=True, type=Path)
    parser.add_argument("--soot-jar", required=True, type=Path)
    parser.add_argument("--java", default="java")
    parser.add_argument("--javac", default="javac")
    args = parser.parse_args()
    methods = cases()
    with tempfile.TemporaryDirectory(prefix="garlic-jimple-arithmetic-") as tmp:
        root = Path(tmp)
        dex = root / "arithmetic.dex"
        dex.write_bytes(dex_fixture(methods))
        apk = root / "arithmetic.apk"
        with zipfile.ZipFile(apk, "w") as archive:
            archive.write(dex, "classes.dex")
        text, descriptor_text, missing = mcp(
            args.garlic.resolve(),
            [
                (apk, "JimpleArithmetic"),
                (dex, "LJimpleArithmetic;"),
                (apk, "MissingClass"),
            ],
        )
        assert text == descriptor_text, (text, descriptor_text)
        assert missing == "Error: class not found: MissingClass", missing
        # 0x3e is reserved by the DEX opcode table; reject it, with the actual site.
        invalid = root / "reserved.dex"
        invalid.write_bytes(dex_fixture([("reserved", "I", "I", [0x003E], [17], 17)]))
        rejected = subprocess.run(
            [
                str(args.garlic.resolve()),
                str(invalid),
                "--jimple",
                "-c",
                "JimpleArithmetic",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert rejected.returncode == 2, rejected
        (failure,) = mcp(args.garlic.resolve(), [(invalid, "JimpleArithmetic")])
        assert failure.splitlines()[0] == (
            f"Error: jimple failed (exit=2; path={invalid}; class=JimpleArithmetic)"
        ), failure
        diagnostic = re.search(
            r"event=jimple_opcode_unmapped op=(\d+) at=(\d+) method=(<[^>]+>)", failure
        )
        assert diagnostic is not None, failure
        assert diagnostic.groups() == (
            "62",
            "1",
            "<JimpleArithmetic: int reserved(int)>",
        ), failure
        (root / "JimpleArithmetic.jimple").write_text(text)
        output = root / "classes"
        subprocess.run(
            [
                args.java,
                "-jar",
                str(args.soot_jar.resolve()),
                "-pp",
                "-src-prec",
                "jimple",
                "-f",
                "class",
                "-d",
                str(output),
                "-cp",
                str(root),
                "-allow-phantom-refs",
                "JimpleArithmetic",
            ],
            check=True,
        )
        java_types = {"I": "int", "J": "long", "F": "float", "D": "double"}
        checks = []
        for name, _, params, _, values, expected in methods:
            types = ",".join(java_types[t] + ".class" for t in params)
            literals = ",".join(
                str(v) + {"I": "", "J": "L", "F": "f", "D": "d"}[t]
                for t, v in zip(params, values, strict=True)
            )
            checks.append(
                f'check("{name}", new Class<?>[]{{{types}}}, '
                f"new Object[]{{{literals}}}, {expected}d);"
            )
        source = root / "Check.java"
        source.write_text(
            """
public class Check {
    static void check(String name, Class<?>[] types, Object[] values, double expected) throws Exception {
        Object value = Class.forName("JimpleArithmetic").getMethod(name, types).invoke(null, values);
        double actual = value instanceof Character ? (Character) value : ((Number) value).doubleValue();
        if (Double.compare(actual, expected) != 0) throw new AssertionError(name + ": " + actual + " != " + expected);
    }
    public static void main(String[] args) throws Exception {
"""
            + "\n".join(checks)
            + "\n    }\n}\n"
        )
        subprocess.run([args.javac, "-d", str(output), str(source)], check=True)
        subprocess.run(
            [args.java, "-Xverify:all", "-cp", str(output), "Check"], check=True
        )
    print(
        f"passed: {len(methods)} DEX arithmetic methods executed via MCP Jimple/Soot/JVM; missing class diagnosed"
    )


if __name__ == "__main__":
    main()
