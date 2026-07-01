# "WASI threads" sample introduction

To run the sample, `wasi-sdk` >= 20 is required.

## Build and run the samples

```shell
$ mkdir build
$ cd build
$ cmake ..
$ make
...
$ ./iwasm wasm-apps/no_pthread.wasm
```

## Run samples in AOT mode
```shell
$ ../../../wamr-compiler/build/wamrc \
    --enable-multi-thread \
    -o wasm-apps/no_pthread.aot wasm-apps/no_pthread.wasm
$ ./iwasm wasm-apps/no_pthread.aot
```
