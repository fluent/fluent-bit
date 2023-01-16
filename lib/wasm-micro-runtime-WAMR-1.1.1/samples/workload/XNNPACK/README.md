"XNNPACK" sample introduction
==============

This sample demonstrates how to build [XNNPACK](https://github.com/google/XNNPACK) benchmarks into WebAssembly with emsdk toolchain and run them with iwasm.

## Installation toolchains

please refer to [installation instructions](../README.md).

## Build XNNPACK

```bash
cd <wamr-dir>/samples/workload/XNNPACK
mkdir build
cd build
cmake ..
```
The wasm files are generated under folder samples/workload/XNNPACK/xnnpack/bazel-bin.

## Run benchmarks

Firstly please build iwasm with simd, libc-emcc and lib-pthread support:

``` bash
$ cd <wamr-dir>/product-mini/platforms/linux/
$ mkdir build && cd build
$ cmake .. -DWAMR_BUILD_SIMD=1 -DWAMR_BUILD_LIBC_EMCC=1 -DWAMR_BUILD_LIB_PTHREAD=1
$ make
```

And please build wamrc:

``` bash
cd <wamr-dir>/wamr-compiler
./build_llvm.sh
mkdir build && cd build
cmake ..
make
```

Then compile wasm file to aot file and run:

``` shell
$ cd <wamr-dir>/samples/workload/XNNPACK/xnnpack/bazel-bin
$ wamrc --enable-simd -o average_pooling_bench.aot average_pooling_bench.wasm  (or other wasm files)
$ iwasm average_pooling_bench.aot
```

