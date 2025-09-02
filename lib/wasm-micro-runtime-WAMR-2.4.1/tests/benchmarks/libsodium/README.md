# Introduction

[libsodium](https://github.com/jedisct1/libsodium) is a new, easy-to-use software library for encryption, decryption, signatures, password hashing and more.

**Source**: https://github.com/jedisct1/libsodium

# Building

Please build iwasm and wamrc, refer to:
- [Build iwasm on Linux](../../../doc/build_wamr.md#linux), or [Build iwasm on MacOS](../../../doc/build_wamr.md#macos)
- [Build wamrc AOT compiler](../../../README.md#build-wamrc-aot-compiler)

And install [zig toolchain](https://ziglang.org/learn/getting-started), refer to [Install Zig from a Package Manager](https://github.com/ziglang/zig/wiki/Install-Zig-from-a-Package-Manager) for how to install it.

And then run `./build.sh` to build the source code, the libsodium source code will be cloned, and test benchmarks of native version, wasm files and AOT files will be generated under `libsodium/zig-out/bin`.

# Running

Run `./run_aot.sh` to test the benchmark, the native mode and iwasm aot mode will be tested respectively.

Run `./test_pgo.sh` to test the benchmark with AOT static PGO (Profile-Guided Optimization) enabled, please refer [here](../README.md#install-llvm-profdata) to install tool `llvm-profdata` and build `iwasm` with `cmake -DWAMR_BUILD_STATIC_PGO=1`.

- For Linux, build `iwasm` with `cmake -DWAMR_BUILD_STATIC_PGO=1`, then run `./test_pgo.sh` to test the benchmark with AOT static PGO (Profile-Guided Optimization) enabled.

- For Linux-sgx, similarly, build `iwasm` with `cmake -DWAMR_BUILD_STATIC_PGO=1`, then `make` in the directory `enclave-sample`. And run `./test_pgo.sh --sgx` to test the benchmark.

# Others

Refer to [Performance of WebAssembly runtimes in 2023](https://00f.net/2023/01/04/webassembly-benchmark-2023) for more about the performance comparison of wasm runtimes on running the libsodium benchmarks.
