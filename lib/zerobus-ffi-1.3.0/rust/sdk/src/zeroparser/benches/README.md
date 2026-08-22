## Reproducing C++ numbers

The plot's C++ bars are pinned constants in `bench_plot.rs` (`cpp_baselines()`),
measured by an out-of-tree harness so this crate keeps no C++ source or build
dependency. To re-measure:

1. Dump the exact encoded bytes the Rust benches see:
   ```bash
   ZEROPARSER_CPP_DUMP_DIR=/tmp/zeroparser-cpp-bench/data \
     cargo bench --features zeroparser --bench zeroparser_bench_plot
   ```
   This writes one `<label>@<bytes>B.bin` per scenario plus a `scenarios.txt`
   manifest (`<label>,<record_bytes>` lines).

2. In a scratch directory outside this repo, drop the bench `.proto` files
   alongside a small driver that:
   - generates C++ stubs with the same `protoc` as the libprotobuf you link
     (`protoc --cpp_out=.`); confirm `protoc --version` matches the library,
     since a `protoc` on `PATH` often differs (with Homebrew the matching pair
     is under `$(brew --prefix protobuf)/bin`);
   - decodes each `<label>@<bytes>B.bin` in a loop into a single **reused**
     message (`ParseFromArray()` clears first), walking every field once via
     both `Reflection`/`Get*` (apples-to-apples with `prost-reflect` /
     Zeroparser) and generated accessors (apples-to-apples with `prost`); for
     repeated/map fields the reflection walk reads `FieldSize`, mirroring
     prost-reflect's `List`/`Map` `.len()`;
   - mirrors `measure_mbps()` in `bench_plot.rs`: 3 trials, each timing enough
     50k-record batches to run ~1 s, reporting
     `record_bytes * count * iters / 1024² / elapsed` (MiB, not decimal MB);
   - prints `<scenario>,cpp_reflect,<MB/s>` / `<scenario>,cpp_typed,<MB/s>`.

3. Average a few runs and update `cpp_baselines()` in `bench_plot.rs`, keyed
   `"<label>@<bytes>B"`, then re-run the bench.

Link the driver against libprotobuf and its abseil dependency (protobuf ≥ 22
needs abseil). With Homebrew on Apple Silicon and no `pkg-config`:

```bash
clang++ -std=c++17 -O3 -DNDEBUG \
  -I"$(brew --prefix protobuf)/include" -I"$(brew --prefix abseil)/include" \
  driver.cpp *.pb.cc \
  -L"$(brew --prefix protobuf)/lib" -lprotobuf -lutf8_range -lutf8_validity \
  "$(brew --prefix abseil)"/lib/libabsl_*.dylib \
  -Wl,-dead_strip_dylibs -o driver   # dead-strip drops unused absl libs
```
