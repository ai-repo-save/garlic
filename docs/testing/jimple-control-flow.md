# Jimple control-flow validation

`tests/e2e/jimple_control_flow.py` is one explicit end-to-end test, outside the default test set. Soot and the JDK are development-only consumers. Garlic uses its native analysis and the formal MCP `jimple` tool; this test adds no production JVM dependency.

## Independent inputs and expectations

`tests/fixtures/jimple-control-flow/BuildFixture.java` uses the dexlib2 builder bundled with Soot 4.6.0. The fixture follows Android's [Dalvik bytecode specification](https://source.android.com/docs/core/runtime/dalvik-bytecode), [instruction formats](https://source.android.com/docs/core/runtime/instruction-formats), and [DEX format](https://source.android.com/docs/core/runtime/dex-format). It contains branches, loop-carried values and register-type reuse, two throwing predecessors of one typed handler, ordered typed handlers with an ignored exception, nested exception paths and catch-all, exceptional pre-instruction destination state, integer/null uses of one zero definition, null/reference joins, float `const/high16`, register aliases, and overlapping wide moves across a conditional join.

`cases.json` records explicit inputs, exact results, and the covered properties. Float results use raw IEEE 754 bits. Integer overflow and exception behavior follow the [Java Language Specification](https://docs.oracle.com/javase/specs/jls/se21/html/jls-15.html). `ControlFlowOracle.java` independently implements the same algorithms. The test requires both the compiled Java oracle and the original DEX translated by Soot Dexpler to match every explicit result before comparing Garlic output. No Garlic type-inference logic supplies the fixture or its expected results.

`StrictConsumer.java` independently reads the original DEX method inventory using dexlib2. For the requested class it requires an exact match of all declarations and concrete bodies, retrieves and validates every concrete Jimple body, runs Soot's packs with validation enabled, and writes JVM bytecode. ASM then checks the complete emitted method inventory against the original DEX. Android/application dependencies may be phantom references; the requested class and its concrete bodies must resolve. Synthetic output additionally executes with `-Xverify:all` against the same complete case table.

The real-APK phase always requests `com.google.ccc.abuse.droidguard.DroidGuard`. Its APK must have SHA-256 `fffb44b653aede6007b15033cb457d044840bddd01d87e293ff58ee4305371ae`. This identifies the acquisition at `cache/device-acquisition/1f7d878f-b977-40f2-afc0-2970447bca43/dynamic/AAEF584C0030E52846AF790022AA2BF836A591DF/the.apk` in the `droidguard-vm` repository. The test checks all methods, including `init()` and `l(byte[])`; fixture failure does not suppress this phase. It validates and emits the real class but does not execute its Android-dependent methods.

## Execution

Build and execute only in the agreed build environment. Use existing JDK 21, `uv`, Soot 4.6.0, an actual Android SDK platform jar, and the frozen Garlic build. The following paths are present on `root@192.168.50.8`; Android 34 supplies consumer dependencies and does not change or deploy to a device.

```sh
cd /root/git/garlic
uv run tests/e2e/jimple_control_flow.py \
  --garlic build/jimple-fix/garlic \
  --soot-jar build/validation-tools/soot-4.6.0-jar-with-dependencies.jar \
  --android-jar /home/dev/Android/Sdk/platforms/android-34/android.jar \
  --apk build/validation-tools/droidguard.apk
```

`--list-cases` prints the explicit coverage and case inventory. `--check-fixture-source` runs only the independent Java/Dexpler input checks; its report is marked `fixture-source-only` and does not establish Garlic acceptance. `--help` describes all arguments. Subprocesses have a bounded timeout. Any failed assertion or consumer fails the run; expected results remain unchanged when Garlic fails.

Each run creates a new directory under `build/validation-tools/control-flow/`, or the new directory given by `--work-dir`. It snapshots Garlic into `tool/garlic` before execution and records its SHA-256, repository HEAD, and source-file hashes in `tool/identity.json`; `source-diff.stdout` retains the source diff. The current Linux build needs only system libc, with no project shared-library sidecar. It retains the generated DEX/APK/Jimple/classes, per-command stdout/stderr, structured `events.jsonl`, and `report.json`. Events share a run identifier. The report records coverage, exact case results, method inventories, commands, and failures. These are rebuildable test artifacts; remove individual run directories after reviewing their diagnostics. No automatic retention job runs.
