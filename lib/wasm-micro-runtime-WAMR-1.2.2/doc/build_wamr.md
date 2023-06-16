
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

#### **Configure platform and architecture**

- **WAMR_BUILD_PLATFORM**:  set the target platform. It can be set to any platform name (folder name) under folder [core/shared/platform](../core/shared/platform).

- **WAMR_BUILD_TARGET**: set the target CPU architecture. Current supported targets are:  X86_64, X86_32, AARCH64, ARM, THUMB, XTENSA, ARC, RISCV32, RISCV64 and MIPS.
  - For ARM and THUMB, the format is \<arch>\[\<sub-arch>]\[_VFP], where \<sub-arch> is the ARM sub-architecture and the "_VFP" suffix means using VFP coprocessor registers s0-s15 (d0-d7) for passing arguments or returning results in standard procedure-call. Both \<sub-arch> and "_VFP" are optional, e.g. ARMV7, ARMV7_VFP, THUMBV7, THUMBV7_VFP and so on.
  - For AARCH64, the format is\<arch>[\<sub-arch>], VFP is enabled by default. \<sub-arch> is optional, e.g. AARCH64, AARCH64V8, AARCH64V8.1 and so on.
  - For RISCV64, the format is \<arch\>[_abi], where "_abi" is optional, currently the supported formats are RISCV64, RISCV64_LP64D and RISCV64_LP64: RISCV64 and RISCV64_LP64D are identical, using [LP64D](https://github.com/riscv/riscv-elf-psabi-doc/blob/master/riscv-elf.md#-named-abis) as abi (LP64 with hardware floating-point calling convention for FLEN=64). And RISCV64_LP64 uses [LP64](https://github.com/riscv/riscv-elf-psabi-doc/blob/master/riscv-elf.md#-named-abis) as abi (Integer calling-convention only, and hardware floating-point calling convention is not used).
  - For RISCV32, the format is \<arch\>[_abi], where "_abi" is optional, currently the supported formats are RISCV32, RISCV32_ILP32D and RISCV32_ILP32: RISCV32 and RISCV32_ILP32D are identical, using [ILP32D](https://github.com/riscv/riscv-elf-psabi-doc/blob/master/riscv-elf.md#-named-abis) as abi (ILP32 with hardware floating-point calling convention for FLEN=64). And RISCV32_ILP32 uses [ILP32](https://github.com/riscv/riscv-elf-psabi-doc/blob/master/riscv-elf.md#-named-abis) as abi (Integer calling-convention only, and hardware floating-point calling convention is not used).

```bash
cmake -DWAMR_BUILD_PLATFORM=linux -DWAMR_BUILD_TARGET=ARM
```

#### **Configure interpreters**

- **WAMR_BUILD_INTERP**=1/0: enable or disable WASM interpreter

- **WAMR_BUILD_FAST_INTERP**=1/0: build fast (default) or classic WASM interpreter.

  NOTE: the fast interpreter runs ~2X faster than classic interpreter, but consumes about 2X memory to hold the pre-compiled code.

#### **Configure AOT and JITs**

- **WAMR_BUILD_AOT**=1/0, enable AOT or not, default to enable if not set
- **WAMR_BUILD_JIT**=1/0, enable LLVM JIT or not, default to disable if not set
- **WAMR_BUILD_FAST_JIT**=1/0, enable Fast JIT or not, default to disable if not set
- **WAMR_BUILD_FAST_JIT**=1 and **WAMR_BUILD_JIT**=1, enable Multi-tier JIT, default to disable if not set

#### **Configure LIBC**

- **WAMR_BUILD_LIBC_BUILTIN**=1/0, build the built-in libc subset for WASM app, default to enable if not set

- **WAMR_BUILD_LIBC_WASI**=1/0, build the [WASI](https://github.com/WebAssembly/WASI) libc subset for WASM app, default to enable if not set

- **WAMR_BUILD_LIBC_UVWASI**=1/0 (Experiment), build the [WASI](https://github.com/WebAssembly/WASI) libc subset for WASM app based on [uvwasi](https://github.com/nodejs/uvwasi) implementation, default to disable if not set

> Note: for platform which doesn't support **WAMR_BUILD_LIBC_WASI**, e.g. Windows, developer can try using **WAMR_BUILD_LIBC_UVWASI**.

#### **Enable Multi-Module feature**

- **WAMR_BUILD_MULTI_MODULE**=1/0, default to disable if not set

#### **Enable WASM mini loader**

- **WAMR_BUILD_MINI_LOADER**=1/0, default to disable if not set

> Note: the mini loader doesn't check the integrity of the WASM binary file, developer must ensure that the WASM file is well-formed.

#### **Enable shared memory feature**
- **WAMR_BUILD_SHARED_MEMORY**=1/0, default to disable if not set

#### **Enable bulk memory feature**
- **WAMR_BUILD_BULK_MEMORY**=1/0, default to disable if not set

#### **Enable thread manager**
- **WAMR_BUILD_THREAD_MGR**=1/0, default to disable if not set

#### **Enable lib-pthread**
- **WAMR_BUILD_LIB_PTHREAD**=1/0, default to disable if not set
> Note: The dependent feature of lib pthread such as the `shared memory` and `thread manager` will be enabled automatically.

#### **Enable lib-pthread-semaphore**
- **WAMR_BUILD_LIB_PTHREAD_SEMAPHORE**=1/0, default to disable if not set
> Note: This feature depends on `lib-pthread`, it will be enabled automatically if this feature is enabled.

#### **Enable lib wasi-threads**
- **WAMR_BUILD_LIB_WASI_THREADS**=1/0, default to disable if not set
> Note: The dependent feature of lib wasi-threads such as the `shared memory` and `thread manager` will be enabled automatically.

#### **Enable lib wasi-nn**
- **WAMR_BUILD_WASI_NN**=1/0, default to disable if not set

#### **Enable lib wasi-nn GPU mode**
- **WASI_NN_ENABLE_GPU**=1/0, default to disable if not set

#### **Disable boundary check with hardware trap**
- **WAMR_DISABLE_HW_BOUND_CHECK**=1/0, default to enable if not set and supported by platform
> Note: by default only platform linux/darwin/android/windows/vxworks 64-bit will enable the boundary check with hardware trap feature, and the wamrc tool will generate AOT code without boundary check instructions in all 64-bit targets except SGX to improve performance. The boundary check includes linear memory access boundary and native stack access boundary, if `WAMR_DISABLE_STACK_HW_BOUND_CHECK` below isn't set.

#### **Disable native stack boundary check with hardware trap**
- **WAMR_DISABLE_STACK_HW_BOUND_CHECK**=1/0, default to enable if not set and supported by platform, same as `WAMR_DISABLE_HW_BOUND_CHECK`.
> Note: When boundary check with hardware trap is disabled, or `WAMR_DISABLE_HW_BOUND_CHECK` is set to 1, the native stack boundary check with hardware trap will be disabled too, no matter what value is set to `WAMR_DISABLE_STACK_HW_BOUND_CHECK`. And when boundary check with hardware trap is enabled, the status of this feature is set according to the value of `WAMR_DISABLE_STACK_HW_BOUND_CHECK`.

#### **Enable tail call feature**
- **WAMR_BUILD_TAIL_CALL**=1/0, default to disable if not set

#### **Enable 128-bit SIMD feature**
- **WAMR_BUILD_SIMD**=1/0, default to enable if not set
> Note: only supported in AOT mode x86-64 target.

#### **Configure Debug**

- **WAMR_BUILD_CUSTOM_NAME_SECTION**=1/0, load the function name from custom name section, default to disable if not set

#### **Enable dump call stack feature**
- **WAMR_BUILD_DUMP_CALL_STACK**=1/0, default to disable if not set

> Note: if it is enabled, the call stack will be dumped when exception occurs.

> - For interpreter mode, the function names are firstly extracted from *custom name section*, if this section doesn't exist or the feature is not enabled, then the name will be extracted from the import/export sections
> - For AOT/JIT mode, the function names are extracted from import/export section, please export as many functions as possible (for `wasi-sdk` you can use `-Wl,--export-all`) when compiling wasm module, and add `--enable-dump-call-stack` option to wamrc during compiling AOT module.

#### **Enable memory profiling (Experiment)**
- **WAMR_BUILD_MEMORY_PROFILING**=1/0, default to disable if not set
> Note: if it is enabled, developer can use API `void wasm_runtime_dump_mem_consumption(wasm_exec_env_t exec_env)` to dump the memory consumption info.
Currently we only profile the memory consumption of module, module_instance and exec_env, the memory consumed by other components such as `wasi-ctx`, `multi-module` and `thread-manager` are not included.

#### **Enable performance profiling (Experiment)**
- **WAMR_BUILD_PERF_PROFILING**=1/0, default to disable if not set
> Note: if it is enabled, developer can use API `void wasm_runtime_dump_perf_profiling(wasm_module_inst_t module_inst)` to dump the performance consumption info. Currently we only profile the performance consumption of each WASM function.

> The function name searching sequence is the same with dump call stack feature.

#### **Enable the global heap**
- **WAMR_BUILD_GLOBAL_HEAP_POOL**=1/0, default to disable if not set for all *iwasm* applications, except for the platforms Alios and Zephyr.

> **WAMR_BUILD_GLOBAL_HEAP_POOL** is used in the *iwasm* applications provided in the directory `product-mini`. When writing your own host application using WAMR, if you want to use a global heap and allocate memory from it, you must set the initialization argument `mem_alloc_type` to `Alloc_With_Pool`.
> The global heap is defined in the documentation [Memory model and memory usage tunning](memory_tune.md).

#### **Set the global heap size**
- **WAMR_BUILD_GLOBAL_HEAP_SIZE**=n, default to 10 MB (10485760) if not set for all *iwasm* applications, except for the platforms Alios (256 kB), Riot (256 kB) and Zephyr (128 kB).

> **WAMR_BUILD_GLOBAL_HEAP_SIZE** is used in the *iwasm* applications provided in the directory `product-mini`. When writing your own host application using WAMR, if you want to set the amount of memory dedicated to the global heap pool, you must set the initialization argument `mem_alloc_option.pool` with the appropriate values.
> The global heap is defined in the documentation [Memory model and memory usage tunning](memory_tune.md).
> Note: if `WAMR_BUILD_GLOBAL_HEAP_SIZE` is not set and the flag `WAMR_BUILD_SPEC_TEST` is set, the global heap size is equal to 300 MB (314572800), or 100 MB (104857600) when compiled for Intel SGX (Linux).

#### **Set maximum app thread stack size**
- **WAMR_APP_THREAD_STACK_SIZE_MAX**=n, default to 8 MB (8388608) if not set
> Note: the AOT boundary check with hardware trap mechanism might consume large stack since the OS may lazily grow the stack mapping as a guard page is hit, we may use this configuration to reduce the total stack usage, e.g. -DWAMR_APP_THREAD_STACK_SIZE_MAX=131072 (128 KB).

#### **WAMR_BH_VPRINTF**=<vprintf_callback>, default to disable if not set
> Note: if the vprintf_callback function is provided by developer, the os_printf() and os_vprintf() in Linux, Darwin, Windows and VxWorks platforms, besides WASI Libc output will call the callback function instead of libc vprintf() function to redirect the stdout output. For example, developer can define the callback function like below outside runtime lib:
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
> and then use `cmake -DWAMR_BH_VPRINTF=my_vprintf ..` to pass the callback function, or add `BH_VPRINTF=my_vprintf` macro for the compiler, e.g. add line `add_defintions(-DBH_VPRINTF=my_vprintf)` in CMakeListst.txt.

#### **Enable reference types feature**
- **WAMR_BUILD_REF_TYPES**=1/0, default to disable if not set

#### **Exclude WAMR application entry functions**
- **WAMR_DISABLE_APP_ENTRY**=1/0, default to disable if not set

> Note: The WAMR application entry (`core/iwasm/common/wasm_application.c`) encapsulate some common process to instantiate, execute the wasm functions and print the results. Some platform related APIs are used in these functions, so you can enable this flag to exclude this file if your platform doesn't support those APIs.
> *Don't enable this flag if you are building `product-mini`*

#### **Enable source debugging features**
- **WAMR_BUILD_DEBUG_INTERP**=1/0, default to 0 if not set
> Note: There are some other setup required by source debugging, please refer to [source_debugging.md](./source_debugging.md) for more details.

#### **Enable load wasm custom sections**
- **WAMR_BUILD_LOAD_CUSTOM_SECTION**=1/0, default to disable if not set

> Note: By default, the custom sections are ignored. If the embedder wants to get custom sections from `wasm_module_t`, then `WAMR_BUILD_LOAD_CUSTOM_SECTION` should be enabled, and then `wasm_runtime_get_custom_section` can be used to get a custom section by name.

> Note: If `WAMR_BUILD_CUSTOM_NAME_SECTION` is enabled, then the `custom name section` will be treated as a special section and consumed by the runtime, not available to the embedder.

> For AoT file, must use `--emit-custom-sections` to specify which sections need to be emitted into AoT file, otherwise all custom sections (except custom name section) will be ignored.

### **Stack guard size**
- **WAMR_BUILD_STACK_GUARD_SIZE**=n, default to N/A if not set.
> Note: By default, the stack guard size is 1K (1024) or 24K (if uvwasi enabled).

**Combination of configurations:**

We can combine the configurations. For example, if we want to disable interpreter, enable AOT and WASI, we can run command:

``` Bash
cmake .. -DWAMR_BUILD_INTERP=0 -DWAMR_BUILD_AOT=1 -DWAMR_BUILD_LIBC_WASI=0 -DWAMR_BUILD_PLATFORM=linux
```

Or if we want to enable interpreter, disable AOT and WASI, and build as X86_32, we can run command:

``` Bash
cmake .. -DWAMR_BUILD_INTERP=1 -DWAMR_BUILD_AOT=0 -DWAMR_BUILD_LIBC_WASI=0 -DWAMR_BUILD_TARGET=X86_32
```
