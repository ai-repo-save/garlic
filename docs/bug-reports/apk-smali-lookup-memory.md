# [bug] APK smali lookup retains scanned DEX metadata

## Reproduction and resource evidence

Baseline: `64f92a2` (including the U+007F fix), Ubuntu 24.04 x86_64, GCC 13.3.
The supplied read-only APK is about 477 MB, with 56 root DEX entries totaling
375,196,656 uncompressed bytes. No APK or extracted DEX is committed.

```sh
/usr/bin/time -v build/garlic /path/to/tiktok.apk -s -c X.04Gq
```

The baseline exits by SIGKILL, shell status 137, after 20.27 seconds, with
maximum RSS 19,658,320 KiB and no smali output. The kernel journal confirms
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

## Cause and narrow fix

`write_from_zip()` parsed each DEX into a separate `meta->pool`, then freed
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

## Regression and verification

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
  the fixed binary: its fixture has return type index 2 with only two type IDs
  (`proto return type outside type_ids`). That fixture is outside this fix.
- A separate Debug build with `-g -O1 -fno-lto -fsanitize=address
  -fno-omit-frame-pointer` also passes the same four fixture scenarios with
  `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1`, without the `RLIMIT_AS` cap
  (ASan reserves a large virtual address range). No ASan/LSan diagnostics occur.
- Incremental build succeeds with the existing warnings noted above.
- Installed Garlic and the running MCP server are unchanged; this verifies the
  rebuilt CLI lookup used by MCP, not a replacement of the installed service.

## Remaining scope

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
