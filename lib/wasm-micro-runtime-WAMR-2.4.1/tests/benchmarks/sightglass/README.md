# Introduction

[Sightglass](https://github.com/bytecodealliance/sightglass) is a benchmarking suite and tooling to test WebAssembly applications.

**Source**: https://github.com/bytecodealliance/sightglass

# Building

Please build iwasm and wamrc, refer to:
- [Build iwasm on Linux](../../../doc/build_wamr.md#linux), or [Build iwasm on MacOS](../../../doc/build_wamr.md#macos)
- [Build wamrc AOT compiler](../../../README.md#build-wamrc-aot-compiler)

And install WASI SDK, please download the [wasi-sdk release](https://github.com/WebAssembly/wasi-sdk/releases) and extract the archive to default path `/opt/wasi-sdk`.

And then run `./build.sh` to build the source code, the folder `out` will be created and files will be generated under it.

# Running

Run `./run_aot.sh` to test the benchmark, the native mode and iwasm aot mode will be tested for each workload, and the file `report.txt` will be generated.

Run `./run_interp.sh` to test the benchmark, the native mode and iwasm interpreter mode will be tested for each workload, and the file `report.txt` will be generated.

Run `./test_pgo.sh` to test the benchmark with AOT static PGO (Profile-Guided Optimization) enabled, please refer [here](../README.md#install-llvm-profdata) to install tool `llvm-profdata` and build `iwasm` with `cmake -DWAMR_BUILD_STATIC_PGO=1`.

- For Linux, build `iwasm` with `cmake -DWAMR_BUILD_STATIC_PGO=1`, then run `./test_pgo.sh` to test the benchmark with AOT static PGO (Profile-Guided Optimization) enabled.

- For Linux-sgx, similarly, build `iwasm` with `cmake -DWAMR_BUILD_STATIC_PGO=1`, then `make` in the directory `enclave-sample`. And run `./test_pgo.sh --sgx` to test the benchmark.
