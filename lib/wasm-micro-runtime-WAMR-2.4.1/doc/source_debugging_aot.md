# WAMR source debugging (AOT)

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
     the debug info of the debuggee module.
     On some platforms including macOS, you need to enable it explicitly.
     (`settings set plugin.jit-loader.gdb.enable on`)

     References:

     * https://github.com/llvm/llvm-project/blob/main/llvm/docs/DebuggingJITedCode.rst
     * https://sourceware.org/gdb/current/onlinedocs/gdb/JIT-Interface.html
