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
Python runner's `--help` describes its paths. The existing operand decoder test
remains available as `build/dex_format_decode_test`.

## Raw DEX smali operands

`smali_decode_integration.py` builds a small DEX035 fixture from explicit code
units and reads it through the formal MCP `smali` tool. It checks all nine move
opcodes (12x, 22x, 32x) and signed literals for `const`, `const/high16`,
`const-wide/32`, `const-wide`, and `const-wide/high16`, including minimum/maximum
values and asymmetric halfwords. A plain NOP must occupy its own line before the
following instruction. The independent expectations follow Android's
[DEX instruction formats](https://source.android.com/docs/core/runtime/instruction-formats)
and [Dalvik bytecode](https://source.android.com/docs/core/runtime/dalvik-bytecode).
The fixture exercises disassembly; it does not execute or verify register types.
Branch labels, exception metadata, and other opcodes require separate validation.

```sh
cmake -S . -B build -DGARLIC_SMALI_DECODE_TEST=ON
cmake --build build
ctest --test-dir build -R '^smali_decode_integration$' --output-on-failure
```

This option defaults to OFF. It requires only local Python and the built Garlic;
all DEX files are temporary, with no JDK, SDK, network, or device dependency.
