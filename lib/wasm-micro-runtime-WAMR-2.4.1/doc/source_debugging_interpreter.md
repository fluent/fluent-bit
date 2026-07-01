# WAMR source debugging (interpreter)

References:
- [Blog: WAMR source debugging basic](https://bytecodealliance.github.io/wamr.dev/blog/wamr-source-debugging-basic/)  
- [Blog: Debugging wasm with VSCode](https://bytecodealliance.github.io/wamr.dev/blog/debugging-wasm-with-vscode/)

WAMR supports source level debugging based on DWARF (normally used in C/C++/Rust), source map (normally used in AssemblyScript) is not supported.

**The lldb's ability to debug wasm application is based on the patch [Add class WasmProcess for WebAssembly debugging](https://reviews.llvm.org/D78801). Thanks very much to the author @paolosev for such a great work!**

## Debugging with interpreter

1. Install dependent libraries
``` bash
apt update && apt install cmake make g++ libxml2-dev -y
```

2. Build iwasm with source debugging feature
``` bash
cd ${WAMR_ROOT}/product-mini/platforms/linux
mkdir build && cd build
cmake .. -DWAMR_BUILD_DEBUG_INTERP=1
make
```
> Note: On MacOS M1 environment, pass the additional `-DWAMR_DISABLE_HW_BOUND_CHECK=1` cmake configuration.

3. Execute iwasm with debug engine enabled
``` bash
iwasm -g=127.0.0.1:1234 test.wasm
# Use port = 0 to allow a random assigned debug port
```

4. Build customized lldb
``` bash
git clone --branch release/13.x --depth=1 https://github.com/llvm/llvm-project
cd llvm-project
git apply ${WAMR_ROOT}/build-scripts/lldb_wasm.patch
mkdir build-lldb
cmake -S ./llvm -B build-lldb \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_PROJECTS="clang;lldb" \
    -DLLVM_TARGETS_TO_BUILD:STRING="X86;WebAssembly" \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DLLVM_BUILD_BENCHMARKS:BOOL=OFF \
    -DLLVM_BUILD_DOCS:BOOL=OFF  -DLLVM_BUILD_EXAMPLES:BOOL=OFF  \
    -DLLVM_BUILD_LLVM_DYLIB:BOOL=OFF  -DLLVM_BUILD_TESTS:BOOL=OFF  \
    -DLLVM_ENABLE_BINDINGS:BOOL=OFF  -DLLVM_INCLUDE_BENCHMARKS:BOOL=OFF  \
    -DLLVM_INCLUDE_DOCS:BOOL=OFF  -DLLVM_INCLUDE_EXAMPLES:BOOL=OFF  \
    -DLLVM_INCLUDE_TESTS:BOOL=OFF -DLLVM_ENABLE_LIBXML2:BOOL=ON
cmake --build build-lldb --target lldb --parallel $(nproc)
# The lldb is generated under build-lldb/bin/lldb
```
> Note: If using `CommandLineTools` on MacOS, make sure only one SDK is present in `/Library/Developer/CommandLineTools/SDKs`.

> You can download pre-built `wamr-lldb` binaries from [here](https://github.com/bytecodealliance/wasm-micro-runtime/releases).

5. Launch customized lldb and connect to iwasm
``` bash
lldb
(lldb) process connect -p wasm connect://127.0.0.1:1234
```
Then you can use lldb commands to debug your applications. Please refer to [lldb document](https://lldb.llvm.org/use/tutorial.html) for command usage.

## Enable debugging in embedders (for interpreter)

There are three steps to enable debugging in embedders

1. Set the debug parameters when initializing the runtime environment:
    ``` c
    RuntimeInitArgs init_args;
    memset(&init_args, 0, sizeof(RuntimeInitArgs));

    /* ... */
    strcpy(init_args.ip_addr, "127.0.0.1");
    init_args.instance_port = 1234;
    /*
    * Or set port to 0 to use a port assigned by os
    * init_args.instance_port = 0;
    */

    if (!wasm_runtime_full_init(&init_args)) {
        return false;
    }
    ```

2. Use `wasm_runtime_start_debug_instance` to create the debug instance:
    ``` c
    /*
        initialization, loading and instantiating
        ...
    */
    exec_env = wasm_runtime_create_exec_env(module_inst, stack_size);
    uint32_t debug_port = wasm_runtime_start_debug_instance(exec_env);
    ```

3. Enable source debugging features during building

    You can use `-DWAMR_BUILD_DEBUG_INTERP=1` during cmake configuration

    Or you can set it directly in `cmake` files:
    ``` cmake
    set (WAMR_BUILD_DEBUG_INTERP 1)
    ```

### Attentions
- Debugging `multi-thread wasm module` is not supported, if your wasm module use pthread APIs (see [pthread_library.md](./pthread_library.md)), or the embedder use `wasm_runtime_spawn_thread` to create new wasm threads, then there may be **unexpected behaviour** during debugging.

    > Note: This attention is about "wasm thread" rather than native threads. Executing wasm functions in several different native threads will **not** affect the normal behaviour of debugging feature.

- When using source debugging features, **don't** create multiple `wasm_instance` from the same `wasm_module`, because the debugger may change the bytecode (set/unset breakpoints) of the `wasm_module`. If you do need several instance from the same bytecode, you need to copy the bytecode to a new butter, then load a new `wasm_module`, and then instantiate the new wasm module to get the new instance.

- If you are running `lldb` on non-linux platforms, please use `platform select remote-linux` command in lldb before connecting to the runtime:
    ```
    (lldb) platform select remote-linux
    (lldb) process connect -p wasm connect://127.0.0.1:1234
    ```
