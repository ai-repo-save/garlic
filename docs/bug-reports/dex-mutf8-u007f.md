# [bug] Legal MUTF-8 U+007F causes an entire DEX to be rejected

## Environment

- Baseline: `138b5b5833b306557c281686851e36f6bac7ec75`.
- Ubuntu 24.04 x86_64, GCC 13.3, CMake 3.28.3, Python 3.12.13.
- Reproducer: temporary hand-built DEX035 from `tests/dex_mutf8_integration.py`;
  no APK, SDK, or external Python package required.

## Reproduction and actual behavior

```sh
cmake -S . -B build -DGARLIC_DEX_MUTF8_TEST=ON
cmake --build build --target garlic -j 2
python3 tests/dex_mutf8_integration.py build/garlic
```

Before the fix, the `u007f` case (source name bytes `41 7f 5a 00`,
`utf16_size = 3`) fails: CLI smali exits 2 instead of returning class `Mutf8`.
The parser marks the whole DEX invalid with `structure outside the file`, even
though the string and its terminator are within the file. Other strings in a
DEX can therefore prevent reading an otherwise unrelated class.

## Expected behavior and cause

The official [DEX MUTF-8 specification](https://source.android.com/docs/core/runtime/dex-format#mutf-8)
uses ordinary UTF-8's one-byte encoding for U+0001 through U+007F inclusive.
U+0000 is instead `c0 80`, and raw `00` terminates the string.
[`string_data_item`](https://source.android.com/docs/core/runtime/dex-format#string-data-item)
counts UTF-16 code units, including isolated surrogates; supplementary characters
use two three-byte-encoded surrogate code units.

`dex_string_byte_size()` in `src/parser/dex/metadata.c` used `c > 0 && c < 127`.
Thus byte `7f` missed the one-byte branch and fell through to rejection.
The fix changes only that upper bound to `0x80`, without bypassing bounds,
length, or terminator checks.

## Verification and scope

- Regression passes: 17 valid cases (empty, encoded NUL, one-/two-/three-byte
  boundaries, surrogate boundaries, U+10000 and U+10FFFF), with sentinels to
  check complete consumption; five malformed strings still rejected (raw NUL,
  bare `80`/`bf`, short/long UTF-16 lengths).
- Real-world read-only smoke: CLI smali can now read `X.05iZ` from the supplied
  `classes3.dex`, exit 0, 101 lines / 2270 bytes, empty stderr; before fix exit 2.
  Neither sample nor generated DEX files are committed. The rebuilt binary also
  returns the same class through MCP.
- `dex_mutf8_integration`, `smali_decode_integration`,
  `dex_rendering_integration`, and `mcp_request_lifetime` pass.
- Reviewed neighboring MUTF-8 scanning and related `0x7f`/`127` comparisons:
  no second instance of this one-byte acceptance error found. Smali's printable
  ASCII upper bound intentionally escapes U+007F and is not an acceptance check.
  This change is not a complete malformed-MUTF-8 validator rewrite.
- Incremental `garlic` build succeeds with existing warnings about unchecked
  `fread`, compiler warning options, Rosemary length declaration, and serial LTO.
