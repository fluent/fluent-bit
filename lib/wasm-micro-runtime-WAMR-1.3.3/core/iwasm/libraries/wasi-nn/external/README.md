# wasi-nn as shared library

Example on how to create libwasi-nn (external library) instead of embedding wasi-nn inside iwasm

From folder `core/iwasm/libraries/wasi-nn/test`, build the test and run

```sh
../external/build/iwasm \
    --dir=. \
    --env="TARGET=cpu" \
    --native-lib=../external/build/libwasi-nn.so \
    test_tensorflow.wasm 
```
