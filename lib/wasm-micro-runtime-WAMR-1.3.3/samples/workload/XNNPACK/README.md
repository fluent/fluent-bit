"XNNPACK" sample introduction
==============

This sample demonstrates how to build [XNNPACK](https://github.com/google/XNNPACK) benchmarks into WebAssembly with emsdk toolchain and run them with iwasm.

## Installation toolchains

please refer to [installation instructions](../README.md).

## Build XNNPACK

please build wamrc:

``` bash
cd <wamr-dir>/wamr-compiler
./build_llvm.sh
mkdir build && cd build
cmake ..
make
```

And then build xnnpack standalone wasm files

```bash
$ cd <wamr-dir>/samples/workload/XNNPACK
$ cmake -S . -B build
$ cmake --build build
```

Generated .wasm(and .aot) files are under *samples/workload/XNNPACK/build*.

## Run benchmarks

Firstly please build iwasm with simd, libc-emcc and lib-pthread supporting:

``` bash
$ cd <wamr-dir>/product-mini/platforms/linux/
$ mkdir build && cd build
$ cmake .. -DWAMR_BUILD_LIBC_EMCC=1 -DWAMR_BUILD_LIB_PTHREAD=1
$ make
```

Then run:

``` shell
$ cd <wamr-dir>/samples/workload/XNNPACK/build
$ iwasm average_pooling_bench.aot # (or other aot files)
```

