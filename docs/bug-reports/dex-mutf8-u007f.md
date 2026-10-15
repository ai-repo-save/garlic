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
- At this stage, whole-APK MCP smali queries on TikTok 47.4.1 still returned
  `exit=-1`; the MUTF-8 fix did not resolve that separate process failure.
  The follow-up investigation and lookup lifetime fix are recorded below.
- `dex_mutf8_integration`, `smali_decode_integration`,
  `dex_rendering_integration`, and `mcp_request_lifetime` pass.
- Existing `smali_payload_integration` fails both with the original condition
  rebuilt from baseline and with the fix: its fixture uses return type index 2
  with only two type IDs (`proto return type outside type_ids`). Left unchanged.
- Reviewed neighboring MUTF-8 scanning and related `0x7f`/`127` comparisons:
  no second instance of this one-byte acceptance error found. Smali's printable
  ASCII upper bound intentionally escapes U+007F and is not an acceptance check.
  This change is not a complete malformed-MUTF-8 validator rewrite.
- Incremental `garlic` build succeeds with existing warnings about unchecked
  `fread`, compiler warning options, Rosemary length declaration, and serial LTO.

## Follow-up: whole-APK single-class smali lookup exhausts memory

### Reproduction and resource evidence

Follow-up baseline: `64f92a2` (including the U+007F fix), same platform as above.
The supplied read-only APK is about 477 MB, with 56 root DEX entries totaling
375,196,656 uncompressed bytes. No APK or extracted DEX is committed.

```sh
/usr/bin/time -v build/garlic /path/to/tiktok.apk -s -c X.04Gq
```

The baseline exits by **SIGKILL**, shell status 137, after 20.27 seconds, with
maximum RSS **19,658,320 KiB** and no smali output. The kernel journal confirms
`global_oom,task=garlic` and `Out of memory: Killed process ... (garlic)` with
`anon-rss:19657552kB`. This is not evidence of a segmentation fault. MCP's
`exec_process()` returns -1 when the child did not exit normally, explaining the
otherwise uninformative `exit=-1` error.

A diagnostic rerun under a 3 GiB virtual-address limit, stopped at `exit()` in
gdb, gives this allocation stack (the limit is diagnostic only):

```text
pool_malloc -> mem_pool_new_big_block -> mem_pool_alloc
 -> parse_dex_code_debug_item -> parse_dex_code_item
 -> parse_dex_class_data_items -> parse_dex_class_defs
 -> parse_dex_from_buffer -> write_from_zip
 -> dex_smali_write_class_from_path -> run_for_class_smali -> main
```

Before the second DEX, the first DEX's metadata pool alone contains
3,173,860,320 bytes (about 3 GiB), while the global scratch pool contains only
492,992 bytes. The first DEX is about 9.6 MB; eagerly expanded debug metadata is
large. That large per-DEX working set made the lifetime error especially costly.

### Cause and narrow fix

`write_from_zip()` parsed each DEX into a **separate** `meta->pool`, then freed
only the ZIP input buffer. The prior DEX's metadata became unreachable but was
never freed. `mem_free_pool()` at the end of the query frees only the global
scratch pool, not these metadata pools. The standalone DEX lookup also omitted
metadata release, but ends after one DEX, so it did not accumulate across entries.

The single-class lookup now destroys the parsed DEX's mutex and releases its
metadata pool after matching/rendering (including the not-found path). Each ZIP
DEX also has a scoped scratch pool, released before moving to the next entry.
Rendering finishes before either pool or the input buffer is released. No class
or APK exceptions, suppressed errors, product resource caps, cache, or parser
format changes are introduced.

### Regression and verification

`tests/e2e/dex_smali_lookup_lifetime.py` is an explicitly enabled Linux CLI error
regression. It creates a temporary multidex APK with 512 legal small DEXes whose
source-name strings are 256 KiB, then a final DEX defining the requested class.
A child-only 128 MiB `RLIMIT_AS` safely exposes accumulation. This is not a
throughput benchmark. The unchanged baseline fails at the APK lookup with
`out of memory: 262145 bytes refused`; the fixed binary returns the exact
expected smali for standalone DEX, APK, and nested APK, and the exact exit 1 /
class-not-found diagnostic for a missing class. The test defaults to OFF; see
`tests/README.md` for the explicit command.

Read-only real-input verification used a diagnostic 8 GiB virtual-address cap.
All six whole-APK CLI queries below exit 0 with empty stderr; each output is
byte-for-byte identical to a separate query against its defining DEX:

| Class | Defining DEX | Smali bytes | Peak RSS (KiB) | Wall time (s) |
| --- | --- | ---: | ---: | ---: |
| `X.04Gq` | `classes3.dex` | 77,767 | 3,335,040 | 43.68 |
| `com.bytedance.bdturing.ttnet.TTNetUtil` | `classes3.dex` | 4,699 | 3,335,200 | 41.97 |
| `X.08p8` | `classes5.dex` | 42,751 | 3,335,060 | 75.23 |
| `com.tts.oecverify.ttnet.TTNetUtil` | `classes5.dex` | 5,382 | 3,334,792 | 74.97 |
| `org.chromium.CronetClient` | `classes5.dex` | 169,772 | 3,335,320 | 74.86 |
| `X.0Bpn` | `classes6.dex` | 7,719 | 3,335,456 | 73.32 |

- `dex_smali_lookup_lifetime`, `dex_mutf8_integration`,
  `smali_decode_integration`, `dex_rendering_integration`, and
  `mcp_request_lifetime` pass with the rebuilt binary.
- `smali_payload_integration` still fails on both the saved baseline binary and
  the fixed binary; the known fixture failure above remains outside this fix.
- A separate Debug build with `-g -O1 -fno-lto -fsanitize=address
  -fno-omit-frame-pointer` also passes the same four fixture scenarios with
  `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1`, without the `RLIMIT_AS` cap
  (ASan reserves a large virtual address range). No ASan/LSan diagnostics occur.
- Incremental build succeeds with the existing warnings noted above.
- Installed Garlic and the running MCP server are unchanged; this verifies the
  rebuilt CLI lookup used by MCP, not a replacement of the installed service.

### Remaining scope

The large single-DEX metadata working set remains: this fix bounds retained
metadata by one scanned DEX, not by raw DEX size. Lookup still eagerly parses
successive entries, hence the 42–75 second runtime. An index, lazy debug parsing,
or debug metadata deduplication would be separate work requiring its own evidence
and tests, not a reason to retain exhausted DEX pools.

Full-APK Java decompilation uses `apk_run_dex_tasks()` and intentionally retains
metadata for pending worker tasks until `apk_release()`. That is a different
lifetime/batching problem. It was not rerun or claimed fixed here; changing it
requires validating task ownership and cross-task metadata dependencies. Malformed
DEX parser rejection cleanup is also unchanged. No large architecture change or
APK business-semantic analysis was performed.
