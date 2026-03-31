
# Build WAMR vmcore

WAMR vmcore is a set of runtime libraries for loading and running Wasm modules. This document introduces how to build the WAMR vmcore.

References:
- [how to build iwasm](../product-mini/README.md): building different target platforms such as Linux, Windows, Mac etc
- [Blog: Introduction to WAMR running modes](https://bytecodealliance.github.io/wamr.dev/blog/introduction-to-wamr-running-modes/)


## WAMR vmcore cmake building configurations

By including the script `runtime_lib.cmake` under folder [build-scripts](../build-scripts) in CMakeList.txt, it is easy to use vmcore to build host software with cmake.

```cmake
# add this into your CMakeList.txt
include (${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)
add_library(vmlib ${WAMR_RUNTIME_LIB_SOURCE})
```

The script `runtime_lib.cmake` defines a number of variables for configuring the WAMR runtime features. You can set these variables in your CMakeList.txt or pass the configurations from cmake command line.

### **Configure platform and architecture**

- **WAMR_BUILD_PLATFORM**:  set the target platform. It can be set to any platform name (folder name) under folder [core/shared/platform](../core/shared/platform).

- **WAMR_BUILD_TARGET**: set the target CPU architecture. Current supported targets are:  X86_64, X86_32, AARCH64, ARM, THUMB, XTENSA, ARC, RISCV32, RISCV64 and MIPS.
  - For ARM and THUMB, the format is \<arch>\[\<sub-arch>]\[_VFP], where \<sub-arch> is the ARM sub-architecture and the "_VFP" suffix means using VFP coprocessor registers s0-s15 (d0-d7) for passing arguments or returning results in standard procedure-call. Both \<sub-arch> and "_VFP" are optional, e.g. ARMV7, ARMV7_VFP, THUMBV7, THUMBV7_VFP and so on.
  - For AARCH64, the format is\<arch>[\<sub-arch>], VFP is enabled by default. \<sub-arch> is optional, e.g. AARCH64, AARCH64V8, AARCH64V8.1 and so on.
  - For RISCV64, the format is \<arch\>[_abi], where "_abi" is optional, currently the supported formats are RISCV64, RISCV64_LP64D and RISCV64_LP64: RISCV64 and RISCV64_LP64D are identical, using [LP64D](https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/master/riscv-cc.adoc#named-abis) as abi (LP64 with hardware floating-point calling convention for FLEN=64). And RISCV64_LP64 uses [LP64](https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/master/riscv-cc.adoc#named-abis) as abi (Integer calling-convention only, and hardware floating-point calling convention is not used).
  - For RISCV32, the format is \<arch\>[_abi], where "_abi" is optional, currently the supported formats are RISCV32, RISCV32_ILP32D, RISCV32_ILP32F and RISCV32_ILP32: RISCV32 and RISCV32_ILP32D are identical, using [ILP32D](https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/master/riscv-cc.adoc#named-abis) as abi (ILP32 with hardware floating-point calling convention for FLEN=64). RISCV32_ILP32F uses [ILP32F](https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/master/riscv-cc.adoc#named-abis) as abi (ILP32 with hardware floating-point calling convention for FLEN=32). And RISCV32_ILP32 uses [ILP32](https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/master/riscv-cc.adoc#named-abis) as abi (Integer calling-convention only, and hardware floating-point calling convention is not used).

```bash
cmake -DWAMR_BUILD_PLATFORM=linux -DWAMR_BUILD_TARGET=ARM
```

### **Configure interpreters**

- **WAMR_BUILD_INTERP**=1/0: enable or disable WASM interpreter

- **WAMR_BUILD_FAST_INTERP**=1/0: build fast (default) or classic WASM interpreter.

  NOTE: the fast interpreter runs ~2X faster than classic interpreter, but consumes about 2X memory to hold the pre-compiled code.

### **Configure AOT and JITs**

- **WAMR_BUILD_AOT**=1/0, enable AOT or not, default to enable if not set
- **WAMR_BUILD_JIT**=1/0, enable LLVM JIT or not, default to disable if not set
- **WAMR_BUILD_FAST_JIT**=1/0, enable Fast JIT or not, default to disable if not set
- **WAMR_BUILD_FAST_JIT**=1 and **WAMR_BUILD_JIT**=1, enable Multi-tier JIT, default to disable if not set

### **Configure LIBC**

- **WAMR_BUILD_LIBC_BUILTIN**=1/0, build the built-in libc subset for WASM app, default to enable if not set

- **WAMR_BUILD_LIBC_WASI**=1/0, build the [WASI](https://github.com/WebAssembly/WASI) libc subset for WASM app, default to enable if not set

- **WAMR_BUILD_LIBC_UVWASI**=1/0 (Experiment), build the [WASI](https://github.com/WebAssembly/WASI) libc subset for WASM app based on [uvwasi](https://github.com/nodejs/uvwasi) implementation, default to disable if not set

> Note: for platform which doesn't support **WAMR_BUILD_LIBC_WASI**, e.g. Windows, developer can try using **WAMR_BUILD_LIBC_UVWASI**.

### **Enable Multi-Module feature**

- **WAMR_BUILD_MULTI_MODULE**=1/0, default to disable if not set
> Note: See [Multiple Modules as Dependencies](./multi_module.md) for more details.

### **Enable WASM mini loader**

- **WAMR_BUILD_MINI_LOADER**=1/0, default to disable if not set

> Note: the mini loader doesn't check the integrity of the WASM binary file, developer must ensure that the WASM file is well-formed.

### **Enable shared memory feature**
- **WAMR_BUILD_SHARED_MEMORY**=1/0, default to disable if not set

### **Enable bulk memory feature**
- **WAMR_BUILD_BULK_MEMORY**=1/0, default to disable if not set

### **Enable memory64 feature**
- **WAMR_BUILD_MEMORY64**=1/0, default to disable if not set

> Note: Currently, the memory64 feature is only supported in classic interpreter running mode and AOT mode.

### **Enable thread manager**
- **WAMR_BUILD_THREAD_MGR**=1/0, default to disable if not set

### **Enable lib-pthread**
- **WAMR_BUILD_LIB_PTHREAD**=1/0, default to disable if not set
> Note: The dependent feature of lib pthread such as the `shared memory` and `thread manager` will be enabled automatically.

> See [WAMR pthread library](./pthread_library.md) for more details.

### **Enable lib-pthread-semaphore**
- **WAMR_BUILD_LIB_PTHREAD_SEMAPHORE**=1/0, default to disable if not set
> Note: This feature depends on `lib-pthread`, it will be enabled automatically if this feature is enabled.

### **Enable lib wasi-threads**
- **WAMR_BUILD_LIB_WASI_THREADS**=1/0, default to disable if not set
> Note: The dependent feature of lib wasi-threads such as the `shared memory` and `thread manager` will be enabled automatically.

> See [wasi-threads](./pthread_impls.md#wasi-threads-new) and [Introduction to WAMR WASI threads](https://bytecodealliance.github.io/wamr.dev/blog/introduction-to-wamr-wasi-threads) for more details.

### **Enable lib wasi-nn**
- **WAMR_BUILD_WASI_NN**=1/0, default to disable if not set
> Note: WAMR_BUILD_WASI_NN without WAMR_BUILD_WASI_EPHEMERAL_NN is deprecated and will likely be removed in future versions of WAMR. Please consider to enable WAMR_BUILD_WASI_EPHEMERAL_NN as well.
> Note: See [WASI-NN](../core/iwasm/libraries/wasi-nn) for more details.

### **Enable lib wasi-nn GPU mode**
- **WAMR_BUILD_WASI_NN_ENABLE_GPU**=1/0, default to disable if not set

### **Enable lib wasi-nn external delegate mode**
- **WAMR_BUILD_WASI_NN_ENABLE_EXTERNAL_DELEGATE**=1/0, default to disable if not set

- **WAMR_BUILD_WASI_NN_EXTERNAL_DELEGATE_PATH**=Path to the external delegate shared library (e.g. `libedgetpu.so.1.0` for Coral USB)

### **Enable lib wasi-nn with `wasi_ephemeral_nn` module support**
- **WAMR_BUILD_WASI_EPHEMERAL_NN**=1/0, default to enable if not set

### **Disable boundary check with hardware trap**
- **WAMR_DISABLE_HW_BOUND_CHECK**=1/0, default to enable if not set and supported by platform
> Note: by default only platform [linux/darwin/android/windows/vxworks 64-bit](https://github.com/bytecodealliance/wasm-micro-runtime/blob/5fb5119239220b0803e7045ca49b0a29fe65e70e/core/shared/platform/linux/platform_internal.h#L81) will enable the boundary check with hardware trap feature, for 32-bit platforms it's automatically disabled even when the flag is set to 0, and the wamrc tool will generate AOT code without boundary check instructions in all 64-bit targets except SGX to improve performance. The boundary check includes linear memory access boundary and native stack access boundary, if `WAMR_DISABLE_STACK_HW_BOUND_CHECK` below isn't set.

### **Disable native stack boundary check with hardware trap**
- **WAMR_DISABLE_STACK_HW_BOUND_CHECK**=1/0, default to enable if not set and supported by platform, same as `WAMR_DISABLE_HW_BOUND_CHECK`.
> Note: When boundary check with hardware trap is disabled, or `WAMR_DISABLE_HW_BOUND_CHECK` is set to 1, the native stack boundary check with hardware trap will be disabled too, no matter what value is set to `WAMR_DISABLE_STACK_HW_BOUND_CHECK`. And when boundary check with hardware trap is enabled, the status of this feature is set according to the value of `WAMR_DISABLE_STACK_HW_BOUND_CHECK`.

### **Disable async wakeup of blocking operation**
- **WAMR_DISABLE_WAKEUP_BLOCKING_OP**=1/0, default to enable if supported by the platform
> Note: The feature helps async termination of blocking threads. If you disable it, the runtime can wait for termination of blocking threads possibly forever.

### **Enable tail call feature**
- **WAMR_BUILD_TAIL_CALL**=1/0, default to disable if not set

### **Enable 128-bit SIMD feature**
- **WAMR_BUILD_SIMD**=1/0, default to enable if not set
> Note: supported in AOT mode, JIT mode, and fast-interpreter mode with SIMDe library.

### **Enable SIMDe library for SIMD in fast interpreter**
- **WAMR_BUILD_LIB_SIMDE**=1/0, default to disable if not set
> Note: If enabled, SIMDe (SIMD Everywhere) library will be used to implement SIMD operations in fast interpreter mode.

### **Enable Exception Handling**
- **WAMR_BUILD_EXCE_HANDLING**=1/0, default to disable if not set

> Note: Currently, the exception handling feature is only supported in classic interpreter running mode.

### **Enable Garbage Collection**
- **WAMR_BUILD_GC**=1/0, default to disable if not set

### **Set the Garbage Collection heap size**
- **WAMR_BUILD_GC_HEAP_SIZE_DEFAULT**=n, default to 128 kB (131072) if not set

### **Configure Debug**

- **WAMR_BUILD_CUSTOM_NAME_SECTION**=1/0, load the function name from custom name section, default to disable if not set

### **Enable AOT stack frame feature**
- **WAMR_BUILD_AOT_STACK_FRAME**=1/0, default to disable if not set
> Note: if it is enabled, the AOT or JIT stack frames (like stack frame of classic interpreter but only necessary data is committed) will be created for AOT or JIT mode in function calls. And please add `--enable-dump-call-stack` option to wamrc during compiling AOT module.

### **Enable dump call stack feature**
- **WAMR_BUILD_DUMP_CALL_STACK**=1/0, default to disable if not set

> Note: if it is enabled, the call stack will be dumped when exception occurs.

> - For interpreter mode, the function names are firstly extracted from *custom name section*, if this section doesn't exist or the feature is not enabled, then the name will be extracted from the import/export sections
> - For AOT/JIT mode, the function names are extracted from import/export section, please export as many functions as possible (for `wasi-sdk` you can use `-Wl,--export-all`) when compiling wasm module, and add `--enable-dump-call-stack --emit-custom-sections=name` option to wamrc during compiling AOT module.

### **Enable memory profiling (Experiment)**
- **WAMR_BUILD_MEMORY_PROFILING**=1/0, default to disable if not set
> Note: if it is enabled, developer can use API `void wasm_runtime_dump_mem_consumption(wasm_exec_env_t exec_env)` to dump the memory consumption info.
Currently we only profile the memory consumption of module, module_instance and exec_env, the memory consumed by other components such as `wasi-ctx`, `multi-module` and `thread-manager` are not included.

> Also refer to [Memory usage estimation for a module](./memory_usage.md).

### **Enable performance profiling (Experiment)**
- **WAMR_BUILD_PERF_PROFILING**=1/0, default to disable if not set
> Note: if it is enabled, developer can use API `void wasm_runtime_dump_perf_profiling(wasm_module_inst_t module_inst)` to dump the performance consumption info. Currently we only profile the performance consumption of each WASM function.

> The function name searching sequence is the same with dump call stack feature.

> Also refer to [Tune the performance of running wasm/aot file](./perf_tune.md).

### **Enable the global heap**
- **WAMR_BUILD_GLOBAL_HEAP_POOL**=1/0, default to disable if not set for all *iwasm* applications, except for the platforms Alios and Zephyr.

> **WAMR_BUILD_GLOBAL_HEAP_POOL** is used in the *iwasm* applications provided in the directory `product-mini`. When writing your own host application using WAMR, if you want to use a global heap and allocate memory from it, you must set the initialization argument `mem_alloc_type` to `Alloc_With_Pool`.
> The global heap is defined in the documentation [Memory model and memory usage tunning](memory_tune.md).

### **Set the global heap size**
- **WAMR_BUILD_GLOBAL_HEAP_SIZE**=n, default to 10 MB (10485760) if not set for all *iwasm* applications, except for the platforms Alios (256 kB), Riot (256 kB) and Zephyr (128 kB).

> **WAMR_BUILD_GLOBAL_HEAP_SIZE** is used in the *iwasm* applications provided in the directory `product-mini`. When writing your own host application using WAMR, if you want to set the amount of memory dedicated to the global heap pool, you must set the initialization argument `mem_alloc_option.pool` with the appropriate values.
> The global heap is defined in the documentation [Memory model and memory usage tunning](memory_tune.md).
> Note: if `WAMR_BUILD_GLOBAL_HEAP_SIZE` is not set and the flag `WAMR_BUILD_SPEC_TEST` is set, the global heap size is equal to 300 MB (314572800), or 100 MB (104857600) when compiled for Intel SGX (Linux).

### **Set maximum app thread stack size**
- **WAMR_APP_THREAD_STACK_SIZE_MAX**=n, default to 8 MB (8388608) if not set
> Note: the AOT boundary check with hardware trap mechanism might consume large stack since the OS may lazily grow the stack mapping as a guard page is hit, we may use this configuration to reduce the total stack usage, e.g. -DWAMR_APP_THREAD_STACK_SIZE_MAX=131072 (128 KB).

### **Set vprintf callback**
- **WAMR_BH_VPRINTF**=<vprintf_callback>, default to disable if not set
> Note: if the vprintf_callback function is provided by developer, the os_printf() and os_vprintf() in Linux, Darwin, Windows, VxWorks, Android and esp-idf platforms, besides WASI Libc output will call the callback function instead of libc vprintf() function to redirect the stdout output. For example, developer can define the callback function like below outside runtime lib:
>
> ```C
> int my_vprintf(const char *format, va_list ap)
> {
>     /* output to pre-opened file stream */
>     FILE *my_file = ...;
>     return vfprintf(my_file, format, ap);
>     /* or output to pre-opened file descriptor */
>     int my_fd = ...;
>     return vdprintf(my_fd, format, ap);
>     /* or output to string buffer and print the string */
>     char buf[128];
>     vsnprintf(buf, sizeof(buf), format, ap);
>     return my_printf("%s", buf);
> }
> ```
>
> and then use `cmake -DWAMR_BH_VPRINTF=my_vprintf ..` to pass the callback function, or add `BH_VPRINTF=my_vprintf` macro for the compiler, e.g. add line `add_definitions(-DBH_VPRINTF=my_vprintf)` in CMakeLists.txt. See [basic sample](../samples/basic/src/main.c) for a usage example.

### **WAMR_BH_LOG**=<log_callback>, default to disable if not set
> Note: if the log_callback function is provided by the developer, WAMR logs are redirected to such callback. For example:
> ```C
> void my_log(uint32 log_level, const char *file, int line, const char *fmt, ...)
> {
>     /* Usage of custom logger */
> }
> ```
> See [basic sample](../samples/basic/src/main.c) for a usage example.

### **Enable reference types feature**
- **WAMR_BUILD_REF_TYPES**=1/0, default to enable if not set

### **Exclude WAMR application entry functions**
- **WAMR_DISABLE_APP_ENTRY**=1/0, default to disable if not set

> Note: The WAMR application entry (`core/iwasm/common/wasm_application.c`) encapsulate some common process to instantiate, execute the wasm functions and print the results. Some platform related APIs are used in these functions, so you can enable this flag to exclude this file if your platform doesn't support those APIs.
> *Don't enable this flag if you are building `product-mini`*

### **Enable source debugging features**
- **WAMR_BUILD_DEBUG_INTERP**=1/0, default to 0 if not set
> Note: There are some other setup required by source debugging, please refer to [source_debugging.md](./source_debugging.md) and [WAMR source debugging basic](https://bytecodealliance.github.io/wamr.dev/blog/wamr-source-debugging-basic) for more details.

### **Enable load wasm custom sections**
- **WAMR_BUILD_LOAD_CUSTOM_SECTION**=1/0, default to disable if not set

> Note: By default, the custom sections are ignored. If the embedder wants to get custom sections from `wasm_module_t`, then `WAMR_BUILD_LOAD_CUSTOM_SECTION` should be enabled, and then `wasm_runtime_get_custom_section` can be used to get a custom section by name.

> Note: If `WAMR_BUILD_CUSTOM_NAME_SECTION` is enabled, then the `custom name section` will be treated as a special section and consumed by the runtime, not available to the embedder.

> For AoT file, must use `--emit-custom-sections` to specify which sections need to be emitted into AoT file, otherwise all custom sections will be ignored.

### **Stack guard size**
- **WAMR_BUILD_STACK_GUARD_SIZE**=n, default to N/A if not set.
> Note: By default, the stack guard size is 1K (1024) or 24K (if uvwasi enabled).

### **Disable writing the linear memory base address to x86 GS segment register**
- **WAMR_DISABLE_WRITE_GS_BASE**=1/0, default to enable if not set and supported by platform
> Note: by default only platform [linux x86-64](https://github.com/bytecodealliance/wasm-micro-runtime/blob/5fb5119239220b0803e7045ca49b0a29fe65e70e/core/shared/platform/linux/platform_internal.h#L67) will enable this feature, for 32-bit platforms it's automatically disabled even when the flag is set to 0. In linux x86-64, writing the linear memory base address to x86 GS segment register may be used to speedup the linear memory access for LLVM AOT/JIT, when `--enable-segue=[<flags>]` option is added for `wamrc` or `iwasm`.

> See [Enable segue optimization for wamrc when generating the aot file](./perf_tune.md#3-enable-segue-optimization-for-wamrc-when-generating-the-aot-file) for more details.

### **User defined linear memory allocator**
- **WAMR_BUILD_ALLOC_WITH_USAGE**=1/0, default to disable if not set
> Notes: by default, the linear memory is allocated by system. when it's set to 1 and Alloc_With_Allocator is selected, it will be allocated by customer.

### **Enable running PGO(Profile-Guided Optimization) instrumented AOT file**
- **WAMR_BUILD_STATIC_PGO**=1/0, default to disable if not set
> Note: See [Use the AOT static PGO method](./perf_tune.md#5-use-the-aot-static-pgo-method) for more details.

### **Enable linux perf support**
- **WAMR_BUILD_LINUX_PERF**=1/0, enable linux perf support to generate the flamegraph to analyze the performance of a wasm application, default to disable if not set
> Note: See [Use linux-perf](./perf_tune.md#7-use-linux-perf) for more details.

### **Enable module instance context APIs**
- **WAMR_BUILD_MODULE_INST_CONTEXT**=1/0, enable module instance context APIs which can set one or more contexts created by the embedder for a wasm module instance, default to enable if not set:
```C
    wasm_runtime_create_context_key
    wasm_runtime_destroy_context_key
    wasm_runtime_set_context
    wasm_runtime_set_context_spread
    wasm_runtime_get_context
```
> Note: See [wasm_export.h](../core/iwasm/include/wasm_export.h) for more details.

### **Enable quick AOT/JTI entries**
- **WAMR_BUILD_QUICK_AOT_ENTRY**=1/0, enable registering quick call entries to speedup the aot/jit func call process, default to enable if not set
> Note: See [Refine callings to AOT/JIT functions from host native](./perf_tune.md#83-refine-callings-to-aotjit-functions-from-host-native) for more details.

### **Enable AOT intrinsics**
- **WAMR_BUILD_AOT_INTRINSICS**=1/0, enable the AOT intrinsic functions, default to enable if not set. These functions can be called from the AOT code when `--disable-llvm-intrinsics` flag or `--enable-builtin-intrinsics=<intr1,intr2,...>` flag is used by wamrc to generate the AOT file.
> Note: See [Tuning the XIP intrinsic functions](./xip.md#tuning-the-xip-intrinsic-functions) for more details.

### **Enable extended constant expression**
- **WAMR_BUILD_EXTENDED_CONST_EXPR**=1/0, default to disable if not set.
> Note: See [Extended Constant Expressions](https://github.com/WebAssembly/extended-const/blob/main/proposals/extended-const/Overview.md) for more details.

### **Configurable memory access boundary check**
- **WAMR_CONFIGURABLE_BOUNDS_CHECKS**=1/0, default to disable if not set
> Note: If it is enabled, allow to run `iwasm --disable-bounds-checks` to disable the memory access boundary checks for interpreter mode.

### **Module instance context APIs**
- **WAMR_BUILD_MODULE_INST_CONTEXT**=1/0, default to disable if not set
> Note: If it is enabled, allow to set one or more contexts created by embedder for a module instance, the below APIs are provided:
```C
    wasm_runtime_create_context_key
    wasm_runtime_destroy_context_key
    wasm_runtime_set_context
    wasm_runtime_set_context_spread
    wasm_runtime_get_context
```

### **Shared heap among wasm apps and host native**
- **WAMR_BUILD_SHARED_HEAP**=1/0, default to disable if not set
> Note: If it is enabled, allow to create one or more shared heaps, and attach one to a module instance, the belows APIs ared provided:
```C
   wasm_runtime_create_shared_heap
   wasm_runtime_attach_shared_heap
   wasm_runtime_detach_shared_heap
   wasm_runtime_shared_heap_malloc
   wasm_runtime_shared_heap_free
```
And the wasm app can calls below APIs to allocate/free memory from/to the shared heap if it is attached to the app's module instance:
```C
   void *shared_heap_malloc();
   void shared_heap_free(void *ptr);
```

### **Shrunk the memory usage**
- **WAMR_BUILD_SHRUNK_MEMORY**=1/0, default to enable if not set
> Note: When enabled, this feature will reduce memory usage by decreasing the size of the linear memory, particularly when the `memory.grow` opcode is not used and memory usage is somewhat predictable.

## **Instruction metering**
- **WAMR_BUILD_INSTRUCTION_METERING**=1/0, default to disable if not set
> Note: Enabling this feature allows limiting the number of instructions a wasm module instance can execute. Use the `wasm_runtime_set_instruction_count_limit(...)` API before calling `wasm_runtime_call_*(...)` APIs to enforce this limit.

## **Combination of configurations:**

We can combine the configurations. For example, if we want to disable interpreter, enable AOT and WASI, we can run command:

``` Bash
cmake .. -DWAMR_BUILD_INTERP=0 -DWAMR_BUILD_AOT=1 -DWAMR_BUILD_LIBC_WASI=0 -DWAMR_BUILD_PLATFORM=linux
```

Or if we want to enable interpreter, disable AOT and WASI, and build as X86_32, we can run command:

``` Bash
cmake .. -DWAMR_BUILD_INTERP=1 -DWAMR_BUILD_AOT=0 -DWAMR_BUILD_LIBC_WASI=0 -DWAMR_BUILD_TARGET=X86_32
```

When enabling SIMD for fast interpreter mode, you'll need to enable both SIMD and the SIMDe library:

``` Bash

cmake .. -DWAMR_BUILD_INTERP=1 -DWAMR_BUILD_FAST_INTERP=1 -DWAMR_BUILD_SIMD=1 -DWAMR_BUILD_LIB_SIMDE=1
```

For Valgrind, begin with the following configurations and add additional ones as needed:

``` Bash
  #...
  -DCMAKE_BUILD_TYPE=Debug \
  -DWAMR_DISABLE_HW_BOUND_CHECK=0 \
  -DWAMR_DISABLE_WRITE_GS_BASE=0
  #...
```
