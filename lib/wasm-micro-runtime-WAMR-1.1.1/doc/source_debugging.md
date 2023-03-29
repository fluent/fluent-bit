# WAMR source debugging

WAMR supports source level debugging based on DWARF (normally used in C/C++/Rust), source map (normally used in AssemblyScript) is not supported.

**The lldb's ability to debug wasm application is based on the patch [Add class WasmProcess for WebAssembly debugging](https://reviews.llvm.org/D78801). Thanks very much to the author @paolosev for such a great work!**

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

3. Execute iwasm with debug engine enabled
``` bash
iwasm -g=127.0.0.1:1234 test.wasm
# Use port = 0 to allow a random assigned debug port
```

4. Build customized lldb (assume you have already cloned llvm)
``` bash
cd ${WAMR_ROOT}/core/deps/llvm
git apply ../../../build-scripts/lldb-wasm.patch
mkdir build-lldb && cd build-lldb
cmake -DCMAKE_BUILD_TYPE:STRING="Release" -DLLVM_ENABLE_PROJECTS="clang;lldb" -DLLVM_TARGETS_TO_BUILD:STRING="X86;WebAssembly" -DLLVM_ENABLE_LIBXML2:BOOL=ON ../llvm
make -j $(nproc)
```

5. Launch customized lldb and connect to iwasm
``` bash
lldb
(lldb) process connect -p wasm connect://127.0.0.1:1234
```
Then you can use lldb commands to debug your applications. Please refer to [lldb document](https://lldb.llvm.org/use/tutorial.html) for command usage.

> Known issue: `step over` on some function may be treated as `step in`, it will be fixed later.

## Debugging with AOT

> Note: AOT debugging is experimental and only a few debugging capabilities are supported.

1. Build lldb (assume you have already built llvm)
``` bash
cd ${WAMR_ROOT}/core/deps/llvm/build
cmake ../llvm -DLLVM_ENABLE_PROJECTS="clang;lldb" -DLLDB_INCLUDE_TESTS=OFF
make -j $(nproc)
```

2. Build wamrc with debugging feature
``` bash
cd ${WAMR_ROOT}/wamr-compiler
mkdir build && cd build
cmake .. -DWAMR_BUILD_DEBUG_AOT=1
make -j $(nproc)
```

3. Build iwasm with debugging feature
``` bash
cd ${WAMR_ROOT}/product-mini/platforms/linux
mkdir build && cd build
cmake .. -DWAMR_BUILD_DEBUG_AOT=1
make
```

4. Compile wasm module to AOT module
``` bash
wamrc -o test.aot test.wasm
```

5. Execute iwasm using lldb

   Then you can use lldb commands to debug both wamr runtime and your wasm application in ***current terminal***.

   ``` bash
   % lldb iwasm -- test.aot
   (lldb) target create "iwasm"
   Current executable set to 'iwasm' (x86_64).
   (lldb) settings set -- target.run-args  "test.aot"
   (lldb) settings set plugin.jit-loader.gdb.enable on
   (lldb) b main
   Breakpoint 1: where = iwasm`main + 48 at main.c:294:11, address = 0x0000000100001020
   (lldb) run
   Process 27954 launched: '/tmp/bin/iwasm' (x86_64)
   Process 27954 stopped
   * thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
       frame #0: 0x0000000100001020 iwasm`main(argc=2, argv=0x00007ff7bfeff678) at main.c:294:11
      291  int
      292  main(int argc, char *argv[])
      293  {
   -> 294      int32 ret = -1;
      295      char *wasm_file = NULL;
      296      const char *func_name = NULL;
      297      uint8 *wasm_file_buf = NULL;
   Target 0: (iwasm) stopped.
   (lldb) c
   Process 27954 resuming
   1 location added to breakpoint 1
   error: need to add support for DW_TAG_base_type 'void' encoded with DW_ATE = 0x0, bit_size = 0
   Process 27954 stopped
   * thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.2
       frame #0: 0x00000001002980a0 JIT(0x100298004)`main(exenv=0x0000000301808200) at hello.c:6:9
      3    int
      4    main(void)
      5    {
   -> 6            printf("hello\n");
      7
      8            return 0;
      9    }
   Target 0: (iwasm) stopped.
   (lldb) br l
   Current breakpoints:
   1: name = 'main', locations = 2, resolved = 2, hit count = 2
     1.1: where = iwasm`main + 48 at main.c:294:11, address = 0x0000000100001020, resolved, hit count = 1
     1.2: where = JIT(0x100298004)`main + 12 at hello.c:6:9, address = 0x00000001002980a0, resolved, hit count = 1

   (lldb)
   ```

   * In the above example,

     * The first `main` function, which is in `main.c`, is the main
       function of the iwasm command.

     * The second `main` function, which is in `hello.c`, is the main
       function of the AOT-compiled wasm module.

   * WAMR AOT debugging uses the GDB JIT loader mechanism to load
     the debug info of the debugee module.
     On some platforms including macOS, you need to enable it explicitly.
     (`settings set plugin.jit-loader.gdb.enable on`)

     References:

     * https://github.com/llvm/llvm-project/blob/main/llvm/docs/DebuggingJITedCode.rst
     * https://sourceware.org/gdb/current/onlinedocs/gdb/JIT-Interface.html

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
