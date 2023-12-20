## WAMR-1.3.0

### Breaking Changes
- Abstract POSIX filesystem functions (#2585)
  - Change API wasm_runtime_set_wasi_args_ex's arguments
    `int stdinfd/stdoutfd/stderrfd` to `int64_t stdinfd/stdoutfd/stderrfd`
- core/iwasm: Support mapped file system access on non-libuv WASI (#2628)
  - Enable mapping host directories to guest directories by parsing
    the `map_dir_list` argument in API `wasm_runtime_init_wasi` for libc-wasi
- Support muti-module for AOT mode (#2482)
  - Add argument `package_type_t module_type` for module_reader callback
- Generate jitdump to support linux perf for LLVM JIT (#2788)
  - Add a field `bool linux_perf_support` in RuntimeInitArgs
- Remove provision of unnecessary fd rights (#2579)
- libc-wasi: Conditionally support SYNC flags (#2581)

### New Features
- Support muti-module for AOT mode (#2482)
- Implement libc-wasi for Windows platform (#2740)
- Implement module instance context APIs (#2436)
- Implement async termination of blocking thread (#2516)
- Generate jitdump to support linux perf for LLVM JIT (#2788)
- Add Cosmopolitan Libc Platform (#2598)

### Bug Fixes
- sgx-ra: Disable the building of samples (#2507)
- Handle a return from wasi _start function correctly (#2529)
- fd_object_release: Preserve errno (#2535)
- Fix build error with ancient GCC (4.8) (#2553)
- Fix compiling error for RT-Thread (#2569)
- Fix potential unaligned store issue when extra return value is v128 (#2583)
- Fix loader push_pop_frame_ref_offset (#2590)
- Fix compilation error on Android platform (#2594)
- Ignore handling SIG_DFL/SIG_IGN for previous sig action (#2589)
- Fix nightly run sanitizer error in Fast JIT (#2601)
- Check ValueKind before extracting a constant int value (#2595)
- Patch implementations of vfbinop(min,max,pmin,pax) (#2584)
- Improve stack trace dump and fix coding guideline CI (#2599)
- aot_resolve_stack_sizes: Disable the size check for now (#2608)
- Remove module instance from hashmap in wasi_nn_destroy (#2613)
- Fix label index out-of-range references in op_br_table_cache (#2615)
- Fix compilation of shift opcodes on x86_64 and i386 architectures (#2619)
- Fix potential issue in aot compiler when translating block opcodes (#2622)
- Use another default pipeline when opt-level is 0 (#2624)
- Fix AOT shift operations for indirect constants (#2627)
- Fix fast-interp "pre-compiled label offset out of range" issue (#2659)
- Revert "Strip static and shared libraries of iwasm to reduce the binary size (#2431)" (#2669)
- Fix windows compilation on C++20 (#2670)
- Fix fast-jit f32/f64 truncate to i32/i64 (#2671)
- Fix use getrandom on cosmopolitan libc (#2674)
- Fix repeatedly initialize shared memory data and protect the memory's fields (#2673)
- Minor fixes for Go bindings (#2676)
- Fix issues reported by Coverity (#2681)
- Add more buffer boundary checks in wasm loader (#2734)
- Grab cluster->lock when modifying exec_env->module_inst (#2685)
- Fix CMSIS import with Zephyr 3.4+ (#2744)
- Fix log messages in Zephyr example (#2761)
- Fix fast-jit callnative translation (#2765)
- aot compiler: Disable musttail for thumb (#2771)
- Fix data/elem drop (#2747)
- Fix formatting in aot_dump_perf_profiling (#2796)
- Fix formatting in wasm_dump_perf_profiling (#2799)
- Fix memory.init opcode issue in fast-interp (#2798)
- aot compiler: Fix handle next reachable if block (#2793)
- Fix configurable bounds checks typo (#2809)
- Attestation: Free JSON from the Wasm module heap (#2803)
- Update Zephyr support to v3.5.0 and make instructions generic to boards (#2805)
- Return error when shutdown() fails (#2801)
- iwasm: Print help when meeting unknown cmd options (#2824)
- Fix fast-jit accessing shared memory's fields issue (#2841)
- Fix wasm loader handle op_br_table and op_drop (#2864)
- Fix block with type issue in fast interp (#2866)
- Fix float argument handling for riscv32 ilp32d (#2871)
- Portably handle fd_advise on directory fd (#2875)
- Fix sample basic intToStr was called with wrong length (#2876)

### Enhancements
- Implement strict validation of thread IDs according to the specification (#2521)
- Stop abusing shared memory lock to protect exception (#2509)
- Implement os_usleep for posix (#2517)
- set_exception_visitor: Remove the special case for wasi proc exit (#2525)
- Revert "Return error when exception was raised after main thread finishes" (#2524)
- libc-wasi: Remove unused code (#2528)
- Add callback to handle memory.grow failures (#2522)
- Add context to enlarge memory error callback (#2546)
- Add ARM aeabi symbol for clearing memory content in a specific range (#2531)
- Unifdef -U WASMTIME_SSP_STATIC_CURFDS (#2533)
- Fix typo for IP address buffer (#2532)
- Add an API to terminate instance (#2538)
- Add user to enlarge memory error callback (#2546)
- runtest.py: Show accurate case amount in summary (#2549)
- Allow using custom signal handler from non-main thread (#2551)
- Return __WASI_EINVAL from fd_prestat_dir_name (#2580)
- Support AOT compiler with LLVM 17 (#2567)
- Add support for closing/renumbering preopen fds (#2578)
- Enable AOT usage on M1 mac (#2618)
- core/iwasm: Support mapped file system access on non-libuv WASI (#2628)
- Enable MASM automatically in runtime_lib.cmake (#2634)
- Abstract POSIX filesystem functions (#2585)
- Implement wasi clock_time/clock_res get (#2637)
- Fix several typo/warning/unused-code issues (#2655)
- Partial windows filesystem implementation (#2657)
- Apply no_sanitize_address for clang compiler in several places (#2663)
- Refactor clock functions to use WASI types (#2666)
- Refine lock/unlock shared memory (#2682)
- Fix several AOT compiler issues (#2697)
- Fix AOT compiler simd shift opcodes (#2715)
- Fix invalid use of jit_reg_is_const_val in fast-jit (#2718)
- Use user defined malloc/free functions for user defined memory allocator (#2717)
- Move WASI types into separate header (#2724)
- Provide default vprintf on UWP (#2725)
- Fix typo in Zephyr simple example (#2738)
- Fix switch-case fallthrough compilation warning (#2753)
- Add eabihf ABI support and set vendor-sys of bare-metal targets (#2745)
- Return uint32 from WASI functions (#2749)
- Add compilation flag to enable/disable heap corruption check (#2766)
- Extend os_mmap to support map file from fd (#2763)
- Fix printing ref.extern addresses in wasm_application.c (#2774)
- Remove unused JitBitmap (#2775)
- Use next generation crypto API on Windows (#2769)
- More precise help info of enabled targets for wamrc (#2783)
- Refine atomic operation flags in bh_atomic.h (#2780)
- Fix comment in WAMR_MEM_DUAL_BUS_MIRROR (#2791)
- Fix return type in wasm_loader_get_custom_section (#2794)
- Add support for custom sections in nuttx (#2795)
- Change is_shared_memory type from bool to uint8 (#2800)
- Fix typos in zephyr platform struct descriptions (#2818)
- Access linear memory size atomically (#2834)
- Output warning and quit if import/export name contains '\00' (#2806)
- Use wasm_config_t to pass private configuration to wasm_engine_new (#2837)
- core/iwasm/interpreter/wasm_loader.c: remove an extra validation (#2845)
- Don't add "+d" to riscv cpu features if already given (#2855)
- Fix compilation warnings on Windows (#2868)

### Others
- Add mutex stress test (#2472)
- Add unit tests for the tid allocator (#2519)
- Add support for running tests on apple M1 macs (#2554)
- export_native_api.md: Add a note about thread termination (#2572)
- test_wamr.sh: Print a bit more meaningful message (#2574)
- run_wasi_tests.sh: Provide stdin by ourselves (#2576)
- Fix a few issues in "run_wasi_tests.sh: provide stdin by ourselves" (#2582)
- Fix compile error of tsf benchmark (#2588)
- test_wamr.sh: Bump wasi-testsuite version (#2568)
- samples/inst-context-threads: Add a brief explanation (#2592)
- doc/memory_tune.md: "remove malloc" hack is not relevant to wasi-threads (#2603)
- Refactor stress tests to make them runnable in reactor mode (#2614)
- Run rust tests from wasi-testsuite (#2484)
- spec-test-script: Fix NaN comparision between v128 values (#2605)
- CI: Enable testing AOT multi-module feature (#2621)
- Vote for nomination of Woods, Chris and Trenner, Thomas as TSC members (#2638)
- Add tsan for fast interp and aot (#2679)
- Enable WASI tests on Windows CI (#2699)
- docs: Fix typo in export native APIs doc (#2750)
- Update RISC-V compilers in Nuttx compilation CI and spec test CI (#2756)
- Enable more LLVM backends for the release wamrc binary (#2778)
- Disable FPU in NuttX spec test (#2781)
- Fix broken links in app-mgr README.md (#2786)
- Fix build error of libsodium benchmark (#2792)
- Fix wamr-test-suites script for macos (#2819)
- Run spec test for classic/fast-interp in NuttX CI (#2817)
- test_wamr.sh: Don't bother to build shared library (#2844)
- doc/build_wamr.md: Fix links to RISC-V named ABIs (#2852)
- Fix typos of CIDR in docs and help text (#2851)
- Enable spectest on riscv64 (#2843)
- Update FPU configuration in spec_test_on_nuttx.yml (#2856)

---

## WAMR-1.2.3

### Breaking Changes
- Increase default native stack size (#2332)

### New Features
- Implement the segue optimization for LLVM AOT/JIT (#2230)
- Implement AOT static PGO (#2243)
- Enable static PGO for Linux SGX (#2270)
- Add Rust Formatters to Debugger (Vector, Map etc.) (#2219)

### Bug Fixes
- The Python language-binding needs python>=3.9 (#2228)
- aot_compile_op_call: Remove a wrong optimization (#2233)
- Fix typo in samples/ref-types (#2236)
- Update thread proposal ignore cases (#2246)
- Disable writting GS register on linux-sgx platform (#2255)
- Fix compile error of wamrc with llvm-13/llvm-14 (#2261)
- aot/jit: Set module layout (#2260)
- Fix build error with LLVM 16 (#2259)
- spec-test-script: Disable conversions.wast on i386 (#2269)
- Fix a heap corruption bug in ems realloc (#2279)
- Fix fast-interp issue of LAST_OP_OUTPUT_I32/64 check (#2295)
- Fix wamrc build issues with LLVM 13 and LLVM 16 (#2313)
- aot: Move stack_sizes table to a dedicated section (#2317)
- product-mini/platforms/linux: Mark vmlib POSITION_INDEPENDENT_CODE (#2323)
- aot: Avoid possible relocations around "stack_sizes" for XIP mode (#2322)
- Avoid switch lowering to lookup tables for XIP (#2339)
- Fix typo in zephyr's Dockerfile.old (#2354)
- Fix typo (dwarf) in the codebase (#2367)
- Implement suspend flags as atomic variable (#2361)
- Fix llvm jit failed to lookup aot_stack_sizes symbol issue (#2384)
- Fix some check issues on table operations (#2392)
- Fix ExpandMemoryOpPass doesn't work properly (#2399)
- Fix non-builtin BH_ATOMIC_32_FETCH_OR and BH_ATOMIC_32_FETCH_AND (#2400)
- Fix wasi-sockets tests (#2389)
- Fix result arity check on select_t opcode (#2406)
- Re-organize intrinsics in aot_reloc_riscv.c to fix some FPU issues (#2414)
- Fix lib-pthread issues (#2410)
- Fix typo in test_wamr.sh (#2421)
- Fix memory sharing (#2415)
- wasm_export.h: Fix struct wasm_val_t (#2435)
- Fix typos in wamrc print_help() (#2442)
- iwasm: Fix native lib cleanup after error occurs (#2443)
- Correct --heap-size option in messages (#2458)
- wasm_instantiate: Fix a potential integer overflow issue (#2459)
- Fix windows link error and clear windows warnings (#2463)
- aot: Disable musttail for mips (#2457)
- Fix opcode overwrite issue in fast interp (#2476)
- wamrc: Fix windows relocation to `aot_func_internal#n` (#2474)
- Fix windows AOT hw bound check (#2475)
- Fix typo in aot_emit_aot_file.c (#2478)

### Enhancements
- A few changes related to WAMRC_LLC_COMPILER (#2218)
- Enhance linux-sgx CI (#2102)
- Add asan and ubsan to WAMR CI (#2161)
- Update doc on WAMR_DISABLE_HW_BOUND_CHECK 32-bit (#2262)
- wamrc: Add an incompatibility note in the help message (#2276)
- Add cmake variable to disable writing gs register (#2284)
- Make hmu_tree_node 4 byte aligned to reduce compiler warning (#2268)
- Appease unused warning on min_uint64 (#2277)
- Fix format warning by PRIu32 in [wasm|aot] dump call stack  (#2251)
- Fix a compile warning due to missing include (#2293)
- Fix dockerfile linter warnings (#2291)
- Enable windows x86-32 AOT relocations (#2285)
- wamr-ide: Add vscode extension tests (#2292)
- AOT/JIT native stack bound check improvement (#2244)
- Add retries to flaky step in nightly run CI (#2306)
- Use system libuv if available (#1861)
- wasi-nn: Simplify cmake and headers' location (#2308)
- wasi-nn: Improve tests paths for local dev (#2309)
- aot: Implement a few more relocation types for riscv (#2318)
- wasi-nn: Add support of wasi-nn as shared lib (#2310)
- Add a few more assertions on structures to which aot abi is sensitive (#2326)
- Fix sanitizer errors in posix socket  (#2331)
- Add "--xip" option for wamrc (#2336)
- Add "--enable-llvm-passes=<passes>" option to wamrc (#2335)
- Make memory access boundary check behavior configurable (#2289)
- Migrate ExpandMemoryOpPass to llvm new pass manager (#2334)
- Allow defining hints without exact socket type or address family (#2337)
- wamrc: Warn on text relocations for XIP (#2340)
- Add scripts to validate lldb source debugger (#2150)
- Add docker file to fix Zephy ESP32 linking issue (#2314)
- Add "--native-lib=<lib>" option to wamrc (#2342)
- Fix unused warnings on disable_bounds_checks (#2347)
- Add "--enable-builtin-intrinsics=<flags>" option to wamrc (#2341)
- nuttx: Add a kconfig for wasi-threads (#2343)
- iwasm: Disable app heap by default if wasi is enabled (#2346)
- Fix some static scan issues (#2362)
- Bring up WAMR on esp32-s3 device (#2348)
- ESP-IDF platform supports to load AOT to PSRAM and run it (#2385)
- Add hadolint CI for Dockerfile linting (#2387)
- Move generic parts of wasm_suspend_flags.h to bh_atomic.h (#2393)
- bh_atomic.h: Add comments (#2398)
- bh_atomic.h: Add BH_ATOMIC_32_FETCH_ADD/BH_ATOMIC_32_FETCH_SUB (#2408)
- Update libuv version to v1.46.0 (#2405)
- Remove a few unused functions (#2409)
- Add initial stress test (#2364)
- Move wasm_runtime_destroy_wasi and wasi_nn_destroy calls together (#2418)
- embed_wamr.md: Improvements about threads (#2420)
- Add runtime inited checks in Enclave command handlings to improve security (#2416)
- Add some relocation symbols for xtensa target (#2422)
- Remove unnecessary and extra zero length check in mem functions' macro (#2428)
- Introduce WASMModuleInstanceExtraCommon (#2429)
- Strip static and shared libraries of iwasm to reduce the binary size (#2431)
- Auto-check wrgsbase in cmake script (#2437)
- iwasm: call native lib init/deinit if exists (#2439)
- wasi-nn: Support uint8 quantized networks (#2433)
- Implement `wasm_externref_objdel` and `wasm_externref_set_cleanup` (#2455)
- wasi-nn: Improve TPU support (#2447)
- wamr-python: Enable debugging WASM and grant dir access (#2449)
- Build wasi-libc from source in WAMR CI (#2465)
- wamrc: More friendly to print help info (#2451)
- Add another wamr test (#2411)
- Fix issues reported by Coverity and clear windows warnings (#2467)
- Clone the input binary during wasm_module_validate (#2483)

### Others
- Nuttx CI: Ignore the expired certificate for riscv gcc toolchain (#2222)
- core/iwasm/compilation: constify a bit (#2223)
- Bump requests from 2.28.2 to 2.31.0 in /build-scripts (#2229)
- dwarf_extractor: Constify a bit (#2278)
- AOTFuncContext: Remove a stale comment (#2283)
- Add performance tunning document (#2286)
- Reduce CI jobs number (#2296)
- CI: Update used node version to 16 (#2303)
- Update Docker image for latest version of external libraries & tools (#2374)
- Upgrade cJSON version to v1.7.16 (#2404)
- Upgrade XNNPACK workload (#2394)
- Build more benchmarks in workload XNNPACK (#2417)
- Upgrade SGX-RA integration for 0.1.2 and Ubuntu 20.04 (#2454)
- Add sample pre-commit hook (#2470)

---

## WAMR-1.2.2

### Breaking Changes

### New Features
- Implement Fast JIT multi-threading feature (#2134)

### Bug Fixes
- Update request.ts wasm_response_send signature (#2122)
- Fix ems allocator unaligned memory access on riscv64 (#2140)
- libc_wasi_wrapper.c: Fix min func issue for size_t < 8 bytes on some platforms (#2152)
- Fix three multi-threading and wasm-c-api-imports issues (#2173)
- Fix build polybench benchmark error with wasi-sdk-19.0 (#2187)
- Fix wamr-ide debugger ignoring launch config (#2155)

### Enhancements
- Add test for validating linear memory size updates (#2078)
- Update Zephyr docs to remove unsupported west subcommand (#2128)
- Update messages/comments to refer the new place of the version definition (#2133)
- build_wamr_lldb.yml: sync lldb build options between ubuntu and macos (#2132)
- build_wamr_vscode_ext.yml: vsce publish only on the official repo (#2130)
- VSCode-Extension: Download lldb built for ubuntu 20.04 (#2139)
- Avoid re-installing if Tensorflow is already installed for WASI-NN (#2148)
- wamrc: Add --stack-usage option (#2158)
- Fix URL in language-bindings/python/README.md (#2166)
- Fix URL in embed_wamr.md (#2165)
- Fix URL in README.md (#2168)
- Return error when exception was raised after main thread finishes (#2169)
- wasi-nn: Add external delegation to support several NPU/GPU (#2162)
- Update document for iwasm/wamrc dependent packages (#2183)
- Use a manual flag to disable clock_nanosleep on the unsupported platforms (#2176)
- Fix compile warnings on windows platform (#2208)

### Others
- CI: Add ubsan checks to samples/wasm-c-api (#2147)
- CI: More precise trigger paths for github actions (#2157)

---

## WAMR-1.2.1

### Breaking Changes

### New Features

### Bug Fixes
- libc-wasi/posix.c: Fix POLL{RD,WR}NORM in uClibc (#2069)
- Fix bh_assert for 64-bit platforms (#2071)
- wamr-ide: Modify Dockerfile to update base image version and fix build issue (#2068)
- Fix module_malloc/module_free issues (#2072)
- Fix use after free when dumping call stack (#2084)
- Fix compilation errors of workload xnnpack and meshoptimizer (#2081)
- Fix typo in Fast JIT's BUILD_COND_BR Macro (#2092)
- Fix sanitizer pointer overflow warning when perform pointer arithmetic (#2098)
- Update sample workload tensorflow (#2101)
- Fix ref.func forward-declared function check (#2099)
- Fix interpreter read linear memory size for multi-threading (#2088)

### Enhancements
- Limit the minimal size of bh_hashmap (#2073)
- Bump tensorflow to 2.11.1 in /core/iwasm/libraries/wasi-nn/test (#2061)
- Bump tensorflow to 2.11.1 in install_tensorflow.sh (#2076)
- Add support for universal binaries on OSX (#2060)
- Update documents (#2100)

### Others
- spectest/nuttx: Increase stack size of iwasm task (#2082)
- ci: Refactor windows build definition (#2087)
- ci: Enable WASI threads in CI (#2086)
- Use wasi-sdk-20 to build wasi-threads cases in CI (#2095)

---

## WAMR-1.2.0

### Breaking Changes


### New Features
- Implement two-level Multi-tier JIT engine: tier-up from Fast JIT to LLVM JIT to get quick cold startup and better performance
- Enable running mode control for runtime, wasm module instance and iwasm
- Implement wasi-threads feature
- Upgrade toolkits: upgrade to llvm-15.0, wasi-sdk-19.0, emsdk-3.1.28 and so on
- Port WAMR to the FreeBSD platform
- Refactor wasi-nn to simplify the support for multiple frameworks
- wasi-nn: Enable GPU support
- wasi-nn: Support multiple TFLite models
- Add WAMR API bindings in Python
- Add libsodium benchmark

### Bug Fixes
- Fix wasm-c-api import func link issue in wasm_instance_new
- Fix watchpoint segfault when using debug interp without server
- libc-wasi: Fix spurious poll timeout
- Fix typo verify_module in aot_compiler.c
- Fix failure about preopen of reactor modules
- Fix equal check in AOT XIP float cmp intrinsic
- Fix issue of resolving func name in custom name section
- Fix go language binding build on macos arm64
- Prevent undefined behavior from c_api_func_imports == NULL
- Fix potential block issue in source debugger
- SGX IPFS: Fix a segfault and support seeking beyond the end of files while using SEEK_CUR/SEEK_END
- Fix undef error about WAMR_BUILD_MEMORY_PROFILING
- Fix jit memory overwritten after instance deinstantiate
- Fix stack alignment issue on ia32
- Fix explicit casts and types in espidf_socket.c
- Fix potential integer overflow issue in wasm-c-api
- Fix libc-wasi build failure when using clang
- Fix wamrapi python binding for darwin
- Fix getting port issue in posix os_socket_bind
- Fix key error in build_llvm.py
- nuttx: Add missing pthread.h header
- Fix os_socket_addr_resolve() for IPv6
- Enhance/Fix sample socket-api and workload
- Fix fast-jit build error
- Fix dead lock in source debugger
- fix debugger: Set termination flags also when in debug mode

### Enhancements
- Add WAMR-IDE vscode extension to the Visual Studio Marketplace
- Refine Windows thread waiting list operations
- Improve wasm-c-api instantiation-time linking
- Enable platform support for esp-idf v5.0.1
- Readme refactoring
- Add architecture diagram for wasm function
- Add architecture document for wasm export
- Add architecture diagram for wasm globals and classic-interp stack frame
- Use boringssl instead of openssl to implement wasm cache loading
- Implement i32.rem_s and i32.rem_u intrinsic
- Perfect the codebase for wamr-ide
- Remove unnecessary ret value control when spec test is enabled
- Use float version library routine for XIP aot_intrinsic_xxx APIs
- Register missing symbols for f32 to 64 bit integer conversion
- Report error in instantiation when meeting unlinked import globals
- Add more types and APIs for attr_container
- Simplify fcmp intrinsic logic for AOT/XIP
- Add some missing macros for int literals in wamr-sdk libc-builtin-sysroot stdint.h
- nuttx: Mock socket APIs if NET is disabled
- Main thread spread exception when thread-mgr is enabled
- Implement opcode atomic.wait and atomic.notify for Fast JIT
- Add docker images auto check and setup support for WAMR-IDE
- Make memory profiling show native stack usage
- Enable gcc-4.8 compilation
- Enable specifying out-of-source platform configuration cmake file
- Add gh api call for fetching llvm version (#1942) Fixes
- Don't terminate other threads when create thread failed
- Modify poll_oneoff in libc-wasi to make it interruptible
- Expose wasm_runtime_call_indirect
- Make a workaround for EGO when fstat returns NOT_SUPPORT
- Re-org calling post instantiation functions
- Enable custom llvm build flags
- support SSH for git clone llvm
- Support dump call stack on exception and dump call stack on nuttx
- Update document for source debugging
- Document some info about estimating memory usage
- Document the summary of two pthread implementations
- Refine aot compiler check suspend_flags and fix issue of multi-tier jit

### Others
- Enable XIP in CI daily test
- Integrate wasi test suite to wamr-test-suites and CI
- Add CI for wasi-threads tests
- Update CIs and documents to make naming of generated binaries consist
- Enable CI wasi test suite for x86-32 classic/fast interpreter
- CI: Enable libc-wasi compilation test on NuttX
- CI: Enable Multi-tier JIT by default for released iwasm binary
- Enable CI build for gcc 4.8 on linux

---

## WAMR-1.1.2

### Breaking Changes
- Remove the LLVM MCJIT mode, replace it with LLVM ORC JIT eager mode
- Add option to pass user data to the allocator functions of RuntimeInitArgs
- Change how iwasm returns:
  - return 1 if an exception was thrown, else
  - return the wasi exit code if the wasm app is a wasi app, else
  - keep the same behavior as before
- Enable bulk memory by default

### New Features
- Add control for the native stack check with hardware trap
- Add memory watchpoint support to debugger
- Add wasm_module_obtain() to clone wasm_module_t
- Implement Fast JIT dump call stack and perf profiling
- esp-idf: Add socket support for esp-idf platform

### Bug Fixes
- Fix XIP issue caused by rem_s on RISC-V
- Fix XIP issues of fp to int cast and int rem/div
- Fix missing float cmp for XIP
- Correct the arch name for armv7a on NuttX
- Fix issue of restoring wasm operand stack
- Fix issue of thumb relocation R_ARM_THM_MOVT_ABS
- Fix fast jit issue of translating opcode i32.rem_s/i64.rem_s
- Fix interp/fast-jit float min/max issues
- Fix missing intrinsics for risc-v which were reported by spec test
- wasm-c-api: Fix init/destroy thread env multiple times issue
- Fix wasm-c-api import func link issue in wasm_instance_new
- Fix sample ref-types/wasm-c-api build error with wat2wasm low version
- Fix zephyr sample build errors
- Fix source debugger error handling: continue executing when detached
- Fix scenario where the timeout for atomic wait is set to negative number
- Fix link cxx object file error when building wamrc for docker image
- Fix XIP issue of handling 64-bit const in 32-bit target

### Enhancements
- Refactor the layout of interpreter and AOT module instance
- Refactor LLVM JIT: remove mcjit and legacy pass manager, upgrade to ORCv2 JIT
- Refine Fast JIT call indirect and call native process
- Refine Fast JIT accessing memory/table instance and global data
- Refine AOT exception check when function return
- Enable source debugger reconnection
- Add wasm_runtime_get_wasi_exit_code
- linux-sgx: Use non-destructive modes for opening files using SGX IPFS
- Add wasm_runtime_unregister_natives
- Implement invokeNative asm code for MinGW
- Add wamr Blog link and Gitbook link to readme
- Remove unnecessary app heap memory clean operations to reduce process RSS
- Normalize how the global heap pool is configured across iwasm apps
- Refine the stack frame size check in interpreter
- Enlarge the default wasm operand stack size to 64KB
- Use cmake POSITION_INDEPENDENT_CODE instead of hardcoding -pie -fPIE
- Implement R_ARM_THM_MOVT_[ABS|REPL] for thumb
- Suppress the warnings when building with GCC11
- samples/native-lib: Add a bit more complicated example
- Add mutex initializer for wasm-c-api engine operations
- XIP adaptation for xtensa platform
- Update libuv version number
- Remove an improper assumption when creating wasm_trap
- Avoid initialize LLVM repeatedly
- linux-sgx: Improve the remote attestation
- linux-sgx: Improve the documentation of SGX-RA sample
- linux-sgx: Allow to open files with arbitrary paths in the sandbox using IPFS
- Avoid raising exception when debugging with VSCode
- wamr-test-suites: Update runtest.py to support python3
- Enable Nuttx spec test option and register aot symbols
- Use wabt binary instead of building from source in spec test
- nuttx: Enable ref types by Kconfig
- Update xtensa LLVM version to 15.x
- Add bh_print_proc_mem() to dump memory info of current process
- Create trap for error message when wasm_instance_new fails
- wamr-test-suites: Add support for ARM/RISCV by QEMU
- Enable to compile WAMR on platforms that don't support IPV6
- Fix warnings in the posix socket implementation
- Update document for MacOS compilation
- Install patched LLDB on vscode extension activation
- Add ARM aeabi memcpy/memmove/memset symbols for AOT bulk memory ops
- Enable wasm cache loading in wasm-c-api

### Others
- Add CIs to release new version and publish binary files
- Add more compilation groups of fast jit into CI
- Enable spec test on nuttx and daily run it

---

## WAMR-1.1.1

- Implement Linux SGX socket API getpeername, recvfrom and sendto
- Implement Linux SGX POSIX calls based on getsockname and set/getbool
- Integrate WASI-NN into WAMR: support TensorFlow/CPU/F32 in the first stage
- Add timeout send/recv and multicast client/server socket examples
- Support cross building and linking LLVM shared libs for wamrc
- Add darwin support for app_framework
- Add ios support for product-mini
- Update export_native_api.md: Relax the "ground rule"
- wasm_export.h: Add comments on wasm_runtime_register_natives
- Remove unused wasm_runtime_is_module_registered
- samples/multi-module: Examine module registration a bit
- samples/native-lib: Fix exec_env type
- Fix Linux SGX directional OCALL parameter for getsockname
- Fix threads issue to enable running threads spec proposal test cases
- Fix the "register native with iwasm" stuff for macOS
- Fix issues in assemblyscript lib
- Wrap wasi_socket_ext api with extern "C" to fix link failure with cxx project
- Fix invalid size of memory allocated in wasi init
- posix_thread.c: Avoid sem_getvalue deprecation warning on macOS

---

## WAMR-1.1.0

- Extend support for Socket API:
  - Implement IPv6 (along with IPv4) for all the socket-related operations
  - Enable resolving host name IP address by adding a host call to WASI
  - Implement a security feature for controlling what domains are allowed to be resolved
  - Allow configuring socket options by adding host calls to WASI for setting and reading the options
  - Enable connection-less communication between hosts by adding host calls to WASI for sending
  - data directly to a given address and receiving messages from a specific address
  - Fix verification of the address in the address pool
  - Add more samples and update the documents
  - Implement SGX IPFS as POSIX backend for file interaction for linux-sgx
- Integrates the Intel SGX feature called Intel Protection File System Library (IPFS) into the runtime
  to create, operate and delete files inside the enclave, while guaranteeing the confidentiality and
  integrity of the data persisted
- Make libc-builtin buffered printf be a common feature
- Enable passing through arguments for build_llvm.sh
- Update \_\_wasi_sock_accept signature to match wasi_snapshot_preview1
- Enable build wasi_socket_ext.c with both clang and clang++
- Add check for code section size, fix interpreter float operations
- Prevent an already detached thread from being detached again for thread manager
- Fix several issues related to AOT debug and update source_debugging.md
- Fix Windows/MSVC build issues and compile warnings
- Fix wasm loader: function sub local count can be 0
- Fix crash in dumping call stack when the AOT file doesn't contain custom name section
- Fix Dockerfile lint errors and suppress hadolint warnings for pinning versions part
- Fix Fast JIT issues reported by instrument test
- Fix link error for ESP-IDF 4.4.2
- Fix syntax errors and undefined names in Python code
- Fix issues reported by Coverity
- Fix Go binding build error
- Fix a wrongly named parameter and enhance the docs in bh_hashmap.h

---

## WAMR-1.0.0

- Implement Python language binding
- Implement Go language binding
- Implement Fast JIT engine
- Implement hw bound check for interpreter and Fast JIT
- Enable the semantic version mechanism for WAMR
- Implement POSIX semaphore support for linux platform
- Implement SGX getrandom/getentropy without ocall
- Enable remote attestation by librats in SGX mode
- Upgrade WAMR-IDE and source debugging
- Support print exception info in source debugger
- Support emit specified custom sections into AoT file
- Refactor spec test script and CI workflows
- Support integrate 3rd-party toolchains into wamrc
- Enable dump call stack to a buffer
- Enable aot compiler with llvm-14/15
- Don't suppress prev signal handler in hw bound check
- Remove unnecessary memset after mmap
- Refine wasm\*runtime_call_wasm_a/v
- Enable app management and thread support for esp32 arch
- Enable libc-wasi support for esp-idf arch
- Implement xtensa XIP
- Enable memory leak check
- Introduce basic CI for nuttx
- Update documents
- Fix module_realloc with NULL ptr issue
- Fix a typo of macro in wasm_application.c
- nuttx: add CONFIG_INTERPRETERS_WAMR_PERF_PROFILING
- aot_reloc_xtensa.c: define \_\_packed if not available
- Fix bh_vector extend_vector not locked issue
- Enable build libc-wasi for nuttx
- Fix typo in embed_wamr.md
- Fix drop opcode issue in fast interpreter
- Fix typos in wasm_mini_loader.c
- Fix issues reported by Coverity and Klocwork
- Add missing aot relocation symbols for xtensa target
- Add arc compiler-rt functions and reloc type for mwdt
- Fix get invokeNative float ret value issue with clang compiler
- Make robust on choosing target assumption for X86_32 support
- Fix an issue of wasm_cluster_spread_custom_data when called before exec
- Fix socket api verification of addresses in the address pool
- Add API wasm_runtime_set_module_inst
- Set noexecstack CXX link flags for wamrc
- Add import subtyping validation
- Fix libc-wasi/uvwasi poll/environ_get issues
- Add missing symbol for aot_reloc_arc.c
- Add a dev docker container for WAMR repo
- Fix dump call stack issue in interpreter
- Fix windows thread data issue and enhance windows os_mmap
- Support custom stack guard size
- Implement i64.div and i64.rem intrinsics
- Let iwasm return non-zero value when running failed
- Reserve one pointer size for fast-interp code_compiled_size
- Enable libc-wasi support for esp-idf
- Expose wasm_runtime_get_exec_env_singleton to the API users
- Normalize wasm types to refine interpreter call_indirect
- Remove unused wasm_runtime_create_exec_env_and_call_wasm
- Fix linear memory page count issues
- debug: Retire wasm_debug\*(get|set)\_engine_active mechanism
- wasm_application.c: Do not start debug instance automatically
- Fix typo in simd_conversions.c
- nuttx: Add CONFIG_INTERPRETERS_WAMR_DEBUG_INTERP
- Add a new API to get free memory in memory pool
- Fix multi-module and some other issues
- Fix build issue of the meshoptimizer workload
- Fix build error on alios platform

---

## WAMR-X.Y.Z

### Breaking Changes

### New Features

### Bug Fixes

### Enhancements

### Others

---


