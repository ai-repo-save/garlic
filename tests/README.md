# Targeted DEX rendering regression

`dex_rendering_integration.py` builds the small checked-in `Guard.java` fixture
with a local JDK and Android `d8`, decompiles that DEX with the built Garlic CLI,
compiles its generated Java, and executes the same independent truth-table and
generic-superclass checks against original and regenerated classes. It covers
lost boolean negation (including short-circuit call predicates) and lost generic
superclasses. It does not assert formatting or claim arbitrary methods compile.
All generated files are temporary; no APK, network, or device is required.

Run explicitly with local tool paths:

```sh
cmake -S . -B build -DGARLIC_DEX_RENDERING_TEST=ON \
  -DGARLIC_TEST_D8=/path/to/android/build-tools/version/d8
cmake --build build
ctest --test-dir build -R '^dex_rendering_integration$' --output-on-failure
```

The option defaults to OFF and never downloads a JDK or SDK. The standalone
Python runner's `--help` describes its paths. The decoder helpers and their
standalone test were removed when the upstream decoder replaced them.

## Raw DEX smali operands

`smali_decode_integration.py` builds a small DEX035 fixture from explicit code
units and reads it through the formal MCP `smali` tool. It checks all nine move
opcodes (12x, 22x, 32x) and signed literals for `const`, `const/high16`,
`const-wide/32`, `const-wide`, and `const-wide/high16`, including minimum/maximum
values and asymmetric halfwords. A plain NOP must occupy its own line before the
following instruction. `filled-new-array/range` cases check zero, one, and three
registers, including a range ending at the method's highest register. The 3rc
count controls the exact register list; each instruction occupies one line.
The comparison decodes hexadecimal literals and register ranges to values,
so it checks instruction semantics rather than the upstream text formatting.
The independent expectations follow Android's
[DEX instruction formats](https://source.android.com/docs/core/runtime/instruction-formats)
and [Dalvik bytecode](https://source.android.com/docs/core/runtime/dalvik-bytecode).
The fixture exercises disassembly; it does not execute or verify register types.
Branch labels, exception metadata, and other opcodes require separate validation.
`smali_payload_integration.py` uses the same option and checks two hand-encoded
edge cases: a packed-switch payload shared by two instructions must keep each
instruction's relative targets, and an array payload with element width 0 must
be rendered as an empty `.array-data 1` block. The zero width is intentionally
malformed; the shared DEX type/prototype tables and direct-method list are
well-formed so both cases reach instruction rendering.

```sh
cmake -S . -B build -DGARLIC_SMALI_DECODE_TEST=ON
cmake --build build
ctest --test-dir build -R '^smali_(decode|payload)_integration$' --output-on-failure
```

This option defaults to OFF. It requires only local Python and the built Garlic;
all DEX files are temporary, with no JDK, SDK, network, or device dependency.

## Multidex single-class smali lookup lifetime

`e2e/dex_smali_lookup_lifetime.py` is an opt-in Linux CLI error regression for
whole-APK lookups exhausting memory while individual DEX lookups succeed. A
temporary APK repeats a legal DEX with a large source-name string before the
requested class. A child-only 128 MiB `RLIMIT_AS` reproduces the accumulation
without exhausting the host. Exact smali output is checked for standalone DEX,
multidex APK, and nested APK; a missing class must still return exit 1 and the
class-not-found diagnostic. This is a lifetime regression, not a throughput or
memory benchmark. It needs only Python's standard library and the built CLI;
there is no external APK, SDK, network, or installed-server dependency.

```sh
cmake -S . -B build -DGARLIC_SMALI_LOOKUP_LIFETIME_TEST=ON
cmake --build build --target garlic
ctest --test-dir build -R '^dex_smali_lookup_lifetime$' --output-on-failure
# Or: python3 tests/e2e/dex_smali_lookup_lifetime.py build/garlic
```

The option defaults to OFF; run this e2e explicitly by name. The address-space
limit is not compatible with sanitizer runtimes that reserve large virtual
address ranges. The runner's `--help` describes its CLI.

## Shared DEX debug streams

`dex_shared_debug_integration.py` hand-builds DEX035 streams shared by static
and instance methods with different register counts and parameter types. It
reads CLI smali into parameter, code-unit position, line, source, and local
lifetime records. Independent expectations follow Android's
[debug_info_item](https://source.android.com/docs/core/runtime/dex-format#debug-info-item)
and [instruction formats](https://source.android.com/docs/core/runtime/instruction-formats).
The same run checks a distinct stream, absent debug information, rejection of an
invalid debug string index, and two DEX files with matching offsets but different
names and lines in a multithreaded APK disassembly. It does not benchmark memory
or throughput, execute the bytecode, or validate Java decompilation.

```sh
cmake -S . -B build -DGARLIC_DEX_SHARED_DEBUG_TEST=ON
cmake --build build --target garlic
ctest --test-dir build -R '^dex_shared_debug_integration$' --output-on-failure
```

The option defaults to OFF and needs only local Python and the built CLI.
Generated DEX, APK, and smali files are temporary; no SDK or network is needed.

## DEX MUTF-8 string boundaries

`dex_mutf8_integration.py` hand-builds a minimal DEX035 class and reads its source
name through CLI smali. Explicit bytes and expected escapes follow the official
[DEX MUTF-8](https://source.android.com/docs/core/runtime/dex-format#mutf-8) and
[string_data_item](https://source.android.com/docs/core/runtime/dex-format#string-data-item)
rules, not Garlic output. Cases cover empty strings, encoded NUL, U+0001,
U+007E/U+007F/U+0080, two-/three-byte boundaries, surrogate boundaries, and the
supplementary minimum/maximum (two UTF-16 code units). Surrounding sentinels
check complete consumption. Early raw NUL, bare continuation bytes, and UTF-16
length mismatches must still be rejected. This is a targeted regression, not a
complete malformed-MUTF-8 verifier test suite.

```sh
cmake -S . -B build -DGARLIC_DEX_MUTF8_TEST=ON
cmake --build build --target garlic
ctest --test-dir build -R '^dex_mutf8_integration$' --output-on-failure
# Or: python3 tests/dex_mutf8_integration.py build/garlic
```

The option defaults to OFF and uses only Python's standard library and the built
CLI. Generated DEX files remain temporary; no APK, JDK, SDK, or network is needed.

## Jimple arithmetic execution

`e2e/jimple_arithmetic.py` hand-encodes DEX arithmetic instructions using Android's
[opcode table](https://source.android.com/docs/core/runtime/dalvik-bytecode) and
[instruction formats](https://source.android.com/docs/core/runtime/instruction-formats).
It reads the same class through MCP from an APK and a DEX descriptor, then uses
Soot 4.6.0 to produce a JVM class. A JDK executes 90 methods against independent
numeric results: 23x/2addr arithmetic, 12x unary/conversions, and comparisons with
overlapping source/destination registers. The same run checks missing-class and
reserved-opcode errors, including the failing method and instruction offset.
This explicit e2e is outside the default test set.

Run on the build environment with JDK 21, `uv`, and the built Garlic:

```sh
mkdir -p build/validation-tools
curl -fL https://repo.maven.apache.org/maven2/org/soot-oss/soot/4.6.0/soot-4.6.0-jar-with-dependencies.jar \
  -o build/validation-tools/soot-4.6.0-jar-with-dependencies.jar
uv run tests/e2e/jimple_arithmetic.py --garlic build/garlic \
  --soot-jar build/validation-tools/soot-4.6.0-jar-with-dependencies.jar
```

Soot and the JDK are test dependencies. This test does not establish correctness
of control-flow type merges or ambiguous DEX constant types in other methods.
