"wasm-av1" sample introduction
==============

This sample demonstrates how to build [wasm-av1](https://github.com/GoogleChromeLabs/wasm-av1) into
WebAssembly with simd support and run it with iwasm.

## Preparation

please refer to [installation instructions](../README.md).

## Build with wasi-sdk

``` shell
$ mkdir build && cd build
$ cmake ..
$ make
# to verify
$ ls testavx.wasm
```

## Or build with EMSDK

just run the convenience script:

```bash
./build.sh
```

the script builds wasm-av1 and runs it with iwasm, which basically contains the following steps:
- hack emcc to delete some objects in libc.a
- patch wasm-av1 and build it with emcc compiler
- build iwasm with simd and libc-emcc support
- run testav1.aot with iwasm

### Run workload

Firstly please build iwasm with simd support:

``` shell
$ cd <wamr dir>/product-mini/platforms/linux/
$ mkdir build && cd build
$ cmake .. -DWAMR_BUILD_LIBC_EMCC=1
$ make
```

Then compile wasm file to aot file and run:

``` shell
$ cd <dir of testavx.wasm>
$ <wamr dir>/wamr-compiler/build/wamrc -o testavx.aot testavx.wasm
# copy sample data like <wamr dir>/samples/workload/wasm-av1/av1/third_party/samples/elephants_dream_480p24.ivf
# make sure you declare the access priority of the directory in which the sample data is
$ <wamr dir>/product-mini/platforms/linux/build/iwasm --dir=. testavx.aot elephants_dream_480p24.ivf
```
