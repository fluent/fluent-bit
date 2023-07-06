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


