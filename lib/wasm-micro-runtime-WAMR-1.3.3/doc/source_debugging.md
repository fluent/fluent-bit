# WAMR source debugging

## Build wasm application with debug information
To debug your application, you need to compile them with debug information. You can use `-g` option when compiling the source code if you are using wasi-sdk (also work for emcc and rustc):
``` bash
/opt/wasi-sdk/bin/clang -g test.c -o test.wasm
```

Then you will get `test.wasm` which is a WebAssembly module with embedded DWARF sections. Further, you can use `llvm-dwarfdump` to check if the generated wasm file contains DWARF information:
``` bash
llvm-dwarfdump-12 test.wasm
```

## Debugging with interpreter

See [Debuggging with interpreter](source_debugging_interpreter.md).

## Debugging with AOT

See [Debuggging with AOT](source_debugging_aot.md).
