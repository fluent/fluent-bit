# Introduction

[CoreMark's](https://www.eembc.org/coremark) primary goals are simplicity and providing a method for testing only a processor's core features.

**Source**: https://github.com/eembc/coremark

# Building

Please build iwasm and wamrc, refer to:
- [Build iwasm on Linux](../../../doc/build_wamr.md#linux), or [Build iwasm on MacOS](../../../doc/build_wamr.md#macos)
- [Build wamrc AOT compiler](../../../README.md#build-wamrc-aot-compiler)

And install WASI SDK, please download the [wasi-sdk release](https://github.com/WebAssembly/wasi-sdk/releases) and extract the archive to default path `/opt/wasi-sdk`.

And then run `./build.sh` to build the source code, file `coremark.exe`, `coremark.wasm` and `coremark.aot` will be generated.

# Running

Run `./run.sh` to test the benchmark, the native mode, iwasm aot mode and iwasm interpreter mode will be tested respectively.

Run `./test_pgo.sh` to test the benchmark with AOT static PGO (Profile-Guided Optimization) enabled, please refer [here](../README.md#install-llvm-profdata) to install tool `llvm-profdata` and build `iwasm` with `cmake -DWAMR_BUILD_STATIC_PGO=1`.

- For Linux, build `iwasm` with `cmake -DWAMR_BUILD_STATIC_PGO=1`, then run `./test_pgo.sh` to test the benchmark with AOT static PGO (Profile-Guided Optimization) enabled.

- For Linux-sgx, similarly, build `iwasm` with `cmake -DWAMR_BUILD_STATIC_PGO=1`, then `make` in the directory `enclave-sample`. And run `./test_pgo.sh --sgx` to test the benchmark.
