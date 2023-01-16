# Introduction

[CoreMark's](https://www.eembc.org/coremark) primary goals are simplicity and providing a method for testing only a processor's core features.

**Source**: https://github.com/eembc/coremark

# Building

Please build iwasm and wamrc, refer to:
- [Build iwasm on Linux](../../../doc/build_wamr.md#linux), or [Build iwasm on MacOS](../../../doc/build_wamr.md#macos)
- [build wamrc AOT compiler](../../../README.md#build-wamrc-aot-compiler)

And install WASI SDK, please download the [wasi-sdk release](https://github.com/CraneStation/wasi-sdk/releases) and extract the archive to default path `/opt/wasi-sdk`.

And then run `./build.sh` to build the source code, file `coremark.exe`, `coremark.wasm` and `coremark.aot` will be generated.

# Running

Run `./run.sh` to test the benchmark, the native mode, iwasm aot mode and iwasm interpreter mode will be tested respectively.
