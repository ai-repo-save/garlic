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
