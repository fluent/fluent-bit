## WAMR-2.4.1

### Breaking Changes

- wasi_socket_ext.c: fix error reporting (#4476)
- lib-socket: make getaddrinfo return EAI\_ values (#4498)
- bump AOT_CURRENT_VERSION for extended-const (#4511)

### New Features

### Bug Fixes

- modify macro related to simde when WASM_OP_SELECT_128 (#4461)
- posix os_socket_accept: stop assuming socklen_t is unsigned int (#4488)
- wasi_socket_ext.c: fix the number of getaddrinfo results (#4466)
- Fix typos (#4472)
- fix regression running_config.json (#4477)
- posix os_socket_addr_resolve: relax compatibility check (#4469)
- Add validation for recursive type count in loader (#4440)

### Enhancements

- Add CI on Zephyr (#4336)
- introduce wasm_runtime_instantiate_ex2 (#4444)
- Add a CLI option to specify shared heap size on Windows platform (#4503)
- wasi-nn: add a comment on load_by_name_with_config (#4492)
- nn-cli: add an option to use load_by_name (#4490)
- wamr-wasi-extensions: document (#4493)
- doc/socket_api.md: some historical notes (#4494)
- lib-socket: implement getsockopt(SOL_SOCKET,SO_TYPE) (#4458)

### Others

- build(deps): Bump github/codeql-action from 3.29.2 to 3.29.3 (#4507)

## WAMR-2.4.0

### Breaking Changes

- Refactor copy callstack feature (#4401)
- Enable WAMR_BUILD_WASI_EPHEMERAL_NN by default (#4381)
- Enable aot memory64 sw bounds checks by default (#4350)

### New Features

- Support extended constant expressions (#4432)
- Shared heap enhancements for Interpreter and AOT (#4400)

### Bug Fixes

- posix os_socket_addr_resolve: return the consistent max_info_size (#4467)
- fix a wamrc debug mode compile issue (#4470)
- wasi-nn: do not pretend to support legacy abi in openvino and llamacpp (#4468)
- appease a few compiler warnings (-Wstrict-prototypes) (#4465)
- enable aux stack frame for aot compiler fuzz test (#4462)
- improve logic of `heap_type` validation when `ref.null` (#4372)
- wasi_nn_llamacpp.c: explicitly reject unimplemented input index (#4446)
- wasi: avoid user-triggerable 0-sized allocations (#4452)
- Fix socket shutdown (#12) (#4449)
- wasi_nn_llamacpp.c: validate input tensor type/dimensions (#4442)
- wasi_nn_llamacpp.c: reject invalid graph and execution context (#4422)
- wasi_nn_openvino.c: avoid self-assignment warning (#4434)
- Fix potential integer overflow issues (#4429)
- Improve run.py of regression (#4417)
- wasi-nn: reduce code duplication a bit (#4433)
- Refactor AOTObjectData definition to use a forward declaration (#4428)
- CI: revert SGX retry attempts (#4421)
- loader: fix a potential overflow issue (#4427)
- wasi_nn_openvino.c: fix a debug build (#4416)
- Fix few shadow warnings (#4409)
- wasi_nn_llamacpp.c: remove an unused variable (#4415)
- wasi_nn_llamacpp.c: fix buffer overruns in set_input (#4420)
- wasi-nn: make the host use the wasi_ephemeral_nn version of tensor_data (#4411)
- Collective fix (#4413)
- fix bug in bh_vector when extending (#4414)
- wasi_nn_llamacpp.c: make this compilable (#4403)
- Fix handling of non-nullable global_type during global import (#4408)
- loader: add type index checking (#4402)
- wasi_nn_tensorflowlite.cpp: fix get_output return size (#4390)
- wasi-nn: fix context lifetime issues (#4396)
- CI: fix the description of upload_url (#4407)
- wamr-wasi-extensions/socket: disable reference-types (#4392)
- wasi_nn_openvino.c: implement multiple models per instance (#4380)
- Improve spec test execution by adding retry logic for transient errors (#4393)
- wasi-nn: add minimum serialization on WASINNContext (#4387)
- deprecate legacy WAMR-specific "wasi_nn" module (#4382)
- wasi-nn: fix tensor_data abi for wasi_ephemeral_nn (#4379)
- core/iwasm/libraries/wasi-nn/test: use the correct version of keras (#4383)
- Fix several issues related to night-run CI and test scripts. (#4385)
- wasi_nn_tensorflowlite.cpp: reject non-fp32 input earlier (#4388)
- core/iwasm/libraries/wasi-nn/test/build.sh: add a tip for intel mac (#4389)
- wasi-nn: don't try to deinit uninitialized backend (#4375)
- wasi-nn: apply the shared library hack to darwin as well (#4374)
- add nn-cli example (#4373)
- wasi_nn_openvino.c: remove pre/postprocessing and layout assumptions (#4361)
- send an empty/error reply from server (#4362)
- wasi_nn_openvino.c: add a missing buffer overflow check in get_output (#4353)
- wasi_ephemeral_nn.h: prefix identfiers to avoid too generic names (#4358)
- wamr-wasi-extensions: add lib-socket things (#4360)
- wasi_nn_openvino.c: remove broken xml check (#4365)
- add validation for array type in load_init_expr(GC only) (#4370)
- wasi-nn: fix backend leak on multiple loads (#4366)
- Collective fix for typos and minor bugs (#4369)
- Modify AOT static PGO to conform to llvm-18 and add a CI job to test static PGO on the coremark benchmark (#4345)
- Update WABT downloads URL (#4357)
- clean up incompatible running mode checks in test script and ci (#4342)
- Follow #4268 to deprecate wamr_ide-related components (#4341)
- Update type validation in load_table_import() and load_table() (#4296)
- wasi_nn_openvino.c: remove the tensor layout adjustment logic (#4308)
- add heap-type check for GC when ref.null (#4300)
- wasi_nn_types.h: remove a seemingly stale comment (#4348)
- wasi_socket_ext.c: avoid tls to make this library-friendly (#4338)
- wasi-nn: do not assign wasi_nn_ctx->backend multiple times (#4329)
- wasi_nn.h: make this compatible with wasi_ephemeral_nn (#4330)
- remove temporary wasi-libc build steps from CI workflows (#4343)
- wasi-nn: fix the size of tensor->type (#4333)
- wasi-nn: move some host-only things out of wasi_nn_types.h (#4334)
- Collective fix: fix some typos (#4337)
- Update binary compression steps to follow symlinks for actual files (#4321)
- Add wamrc compilation into Windows CI workflow (#4327)
- wasi-nn: remove unused wasi_nn_dump_tensor_dimension prototype (#4325)
- wasi_nn.h: add import_name attribute (#4328)
- wasi-nn: protect the backend lookup table with a lock (#4319)
- handle nullable heap reference types in import section (#4302)
- wasi_nn_openvino.c: make this buildable (#4305)
- wasi-nn: fix shared library filenames for macOS (#4306)
- fix wasi-nn abi definitions (#4307)
- wasi-nn: remove "backends" argument from detect_and_load_backend() (#4309)
- wasi_nn_openvino.c: fix a few printf formats (#4310)
- Bump uvwasi to latest commit #392e1f1 (#4312)

### Enhancements

- Add readme for extended const (#4471)
- Add security issue runbook (#4450)
- docs: fix cmake variable typo (#4441)
- CI: add wamr_wasi_extensions to the release assets (#4425)
- CI: build wamr-wasi-extensions (#4394)
- improve installation steps for wasi-sdk and wabt on Windows (#4359)
- wamr-wasi-extensions: add a cmake package to provide our wasi extension (#4344)
- Update Dockerfile for Zephyr SDK and Zephyr-project versioning (#4335)
- add load_by_name in wasi-nn (#4298)

### Others

- build(deps): Bump ossf/scorecard-action from 2.4.1 to 2.4.2 (#4315)
- build(deps): Bump github/codeql-action from 3.29.1 to 3.29.2 (#4459)
- build(deps): Bump github/codeql-action from 3.29.0 to 3.29.1 (#4436)
- build(deps): Bump github/codeql-action from 3.28.19 to 3.29.0 (#4371)
- build(deps): Bump github/codeql-action from 3.28.18 to 3.28.19 (#4346)
- build(deps): Bump requests from 2.32.3 to 2.32.4 in /build-scripts (#4349)

---

## WAMR-2.3.1

### Breaking Changes

- Revert the location to install public headers (#4295). This restores compatibility (of installed headers) with WAMR-2.2.0 and earlier.

### New Features

- feat: Add instruction metering for interpreter (#4122)

### Bug Fixes

- updating WASI stdio handle initialization and build options for UVWASI (#4260)
- Fix SIMD load lane to avoid incompatible pointer types (#4278)
- Fixed unit tests on X86_32 (#4279)
- Improve Embedding WAMR guideline (#4284)
- Fix Compiler Error C2491 (#4286)
- Enhance type checking for function types in loader and improve error handling (#4294)
- Dockerfile.vx-delegate build error fix (#4273)
- Enable runtime API exposure for MSVC builds (#4287)

### Enhancements

- feat(yml): Add ESP32-P4 and ESP32-C5 support (#4270)
- add a sample to use cmake package (#4291)

### Others

- build(deps): Bump github/codeql-action from 3.28.17 to 3.28.18 (#4285)

---

## WAMR-2.3.0

### Breaking changes

### New features

- simd for fast-interp (#4131)
- copy call-stack (#4033)

### Bug fixes

- fix(ios): Remove `float-abi` flag (#3889)
- Fix out of bounds issues after memory.grow on non-aot non-threads builds (#3872)
- Fix out of bounds issue in is_native_addr_in_shared_heap function (#3886)
- Fix mmap flags for AOT loader on non-Linux SGX platforms (#3890)
- fix(uwp): Gate NTSTATUS definition behind WINAPI_PARTITION_DESKTOP for UWP builds (#3897)
- Fix linked global initialization in multimodule (#3905)
- Correct the table index calculation in aot_instantiation (#3903)
- Fix a leak in wasm_loader_emit_br_info (#3900)
- Check possible integer overflow in aot memory boundary check (#3920)
- Fix CI wamr-ide error (#3913)
- Fix WASI Path Mapping Processing (#3923)
- Use plain assignment rather than bh_memcpy_s (#3924)
- Fix loader small bug (#3928)
- don't return an uninitialized trap if argv_to_results fails (#3935)
- support WASM_FUNCREF return type in argv_to_results (#3936)
- Fix incorrect assignment in win_file.c (#3939)
- Fix aot table instantiate (#3946)
- set alignment 4 when loading multi return value (#3955)
- Only access Zephyr thread stats info when it's available (#3962)
- top-level cmakefile: fix macOS build (#3968)
- Handle a new scenario where an item is both exported and imported. (#3984)
- platform/nuttx: Flush icache/dcache properly (#4147)
- fix(runtest.py): A workaround to bypass errors that occur when deleting temporary files (#4093)
- Fix build issues when compiling WAMRC as a cross-compiler (#4112)
- include bh_platform.h (#4135)
- Fix iwasm build error when WAMR_BUILD_WASI_NN enabled (#4138)
- avoid Windows perform newline translation (#4128)
- fix: correct typos and improve comments across multiple files by codespell (#4116)
- fix: fix load aarch64 aot failed (#4114)
- wasm_loader allocates more spaces for elements (#4099)
- fix: add dispose of the debug information builder when destroying compilation context (#4105)
- prevent mmap size overflow on 32 bit platform for memory.grow (#4071)
- fix: when load aot init expr,no type_idx set. (#4094)
- fix(aot_emit_aot_file): prevent buffer emission for zero byte_count (#4095)
- fix(build_llvm_libraries.yml): Correct script path for build_llvm.py (#4089)
- fix(unit-test): libc_builtin_test issues (#4073)
- [gc] Subtyping fix (#4075)
- fix(build_llvm.py): clean up whitespace and formatting in build script (#4087)
- Unit test:type matching issue and code redundancy (#4079)
- fix(aot): ensure value_cmp does not exceed br_count in branch table compilation (#4065)
- In wasm32, fix potential conversion overflow when enlarging 65536 pages (#4064)
- Use wasm32-wasip1 instead of wasm32-wasi target for rust code (#4057)
- Update Rust target from 'wasm32-wasi' to 'wasm32-wasip1' in CI (#4050)
- Fix wasm loader check data segment count (#4039)
- Fix table index calculations in wasm_loader and wasm_mini_loader (#4004)
- Ensure **heap_base and **data_end global indices are validated against import count (#3996)
- fix format specifier warning on 32bit builds (#4177)
- Remove indirect-load for constants on Xtensa Target to improve performance (#4162)
- cmake: Enhance target selection for ARM architectures with FPU (#4185)
- Add import memory/table flag assert check for miniloader (#4179)
- Fix few integer overflowing (#4161)
- prevent frame_offset underflow in wasm_loader (#4165)
- fix: Remove unused variables in SIMD_v128_const case (#4197)
- fix false native stack overflow detections with HW_BOUND_CHECK (#4196)
- Keep fix the CMake compatibility issue (#4180)
- Fix the error of AOT mode on the "i386-windows-msvc" platform (#4183)
- debug-engine: fix a few type mismatches (#4189)
- Replace CMAKE_CURRENT_FUNCTION_LIST_DIR (#4200)
- fix potential memory leak (#4205)
- Add missing V128 handling in WASM_OP_BR (#4203)
- fix print_help when libc wasi is enabled (#4218)
- LLVM: don't verify instcombine fixpoint (#4219)
- LLVMCreateTargetMachineWithOpts: disable large data (#4220)
- set default value of `WAMR_BUILD_REF_TYPES` to 1 in standalone cases (#4227)
- platform/nuttx: Fix dcache operation in os_dcache_flush (#4225)
- fix return types of our 64-bit clz/ctz/popcount intrinsics (#4238)
- riscv: avoid llvm.cttz.i32/i64 for xip (#4248)
- Add overflow check for preserved local offset in preserve_referenced_local (#4211)
- aot_resolve_object_relocation_group: adapt to LLVM 16 (#4250)
- initialize WASI stdio handles to invalid for better error handling (#4092)
- Modifying build flags to ensure libiwasm.so is built (#4255)
- Stop pretending to support extended-const proposal (#4258)
- Improve readlinkat_dup() to handle symlink size correctly (#4229)
- fix: improve error handling of snprintf() in send_thread_stop_status() (#4234)
- Don't call os_thread_get_stack_boundary unless we actually use it (#4264)
- avoid access null pointer (#4262)
- disable compiler to prevent get_current_target() crash (#4251)
- product-mini/platforms/windows: set C++17 explicitly (#4269)
- fix buf checking in load_table_section (#4276)
- Set CMAKE_OSX_SYSROOT when building lldb (#4274)
- Add select 128 (#4236)

### Enhancements

- Refine looking up aot function with index (#3882)
- Wasm loader enhancement: check code size in code entry (#3892)
- Refactor AOT loader to support compatible versions (#3891)
- GlobalValueSet was moved to IRPartitionLayer recently, but we have a local definition anyway (#3899)
- Support external toolchain on Windows for aot compiler (#3911)
- Drop declarative elements on module instantiation (#3922)
- add testcases for shared heap and fix POP_MEM_OFFSET of memory64 (#3916)
- Enable ref types by default (#3894)
- Update README.md to clarify Windows toolchain support and ESP-IDF reference (#3917)
- add thread cpu time for zephyr (#3937)
- Improvements for platform thread APIs on Windows and Zephyr (#3941)
- Refactor SConscript and add file checks in iwasm.c (#3945)
- Consume the placeholders that were put when emitting table info (#3940)
- wasm_export.h: Use "default" visibility for gcc and clang (#3957)
- [fuzzing] Enable instantiation (#3958)
- use a random secret key (#3971)
- CMakeLists.txt: Do not require C++ (#3956)
- add reference type support by default for darwin to support WASI-SDK-25 (#3978)
- top-level cmake: link llvm libraries to our shared library (#3973)
- Set thread information earlier in exec_env creation (#3967)
- Break aot_create_comp_data into small functions (#3987)
- Optimize memory initialization handling in AOT loader (#3983)
- nuttx: remove the up_x API for kernel build (#4154)
- Expose WAMR_BUILD_GC_HEAP_SIZE_DEFAULT as a CMake option (#4124)
- Use log instead of using assertion in aot loader (#4119)
- feat: use C linkage in aot_comp_option.h for C++ embeding (#4106)
- Cmake improvements (#4076)
- feat: add support for EXTERNREF value type and enable AOT validator in fuzz tests (#4083)
- build_llvm.py: Allow to build xtensa target on non-xtensa host (#4086)
- Add a conditional check for the macro **STDC_VERSION** (#4080)
- [fuzzing] execute every exported function (#3959)
- Update memory allocation functions to use allocator user data (#4043)
- Add versioning support and update CMake configuration (#3933)
- Show wasm proposals status during compilation and execution (#3989)
- add a validator for aot module (#3995)
- Synchronize the GC spec tests to the commit from December 9. 2024. (#4022)
- Refine getting const offsets in wasm loader of fast-interp (#4012)
- fixes for compiling on windows (#4026)
- .github: Add shared lib builds (#3975)
- Error message improvement (#4000)
- Refine read leb int wasm loader of fast interpreter (#4017)
- Enable shrunk memory by default and add related configurations (#4008)
- Add documentation regarding security issues and the status of Wasm proposals (#3972)
- Improve stack consistency by ensuring sufficient space for dummy offsets (#4011)
- Check whether related table has funcref elem in opcode call_indirect (#3999)
- [fuzzing] Use software bound-check during fuzzing (#4003)
- Add an example of how to embed WAMR in Zephyr user mode (#3998)
- Update cmake min to 3.14 (#4175)
- aot: add new u64 intrinsics (#4168)
- Refactor Dockerfile and update .dockerignore for wasi-nn tests; adjust map-dir parameters in smoke test script (#4158)
- improve variable naming and code clarity in SIMD operations (#4157)
- Raise CI runner to ubuntu 22.04 (#4191)
- Remove the dlen to optimize it. (#4193)
- Add missing casts and improve error handling in performance map functions (#4202)
- Raise wasi-sdk to 25 and wabt to 1.0.37 (#4187)
- wamrc: add --disable-llvm-jump-tables option (#4224)
- feat(fuzz): add a new fuzzing target about aot compiler (#4121)
- bypass vptr santizier (#4231)
- use a selected llvm libs list to replace the full list (#4232)
- teach aot emitter/loader about .srodata and .srodata.cst\* sections (#4240)
- run_clang_format_diff: mention homebrew for clang-format installation (#4237)
- Use --target to pass a triple in wamrc (#4199)
- samples/wasm-c-api: skip aot compilation unless necessary (#4239)
- samples/wasm-c-api: remove unused valgrind detection (#4249)
- More detail to python setup, and fixed small typo (#4247)
- JIT: don't join worker threads twice (#4252)
- aot_resolve_object_relocation_group: adapt to LLVM 19 (#4254)
- build-scripts/build_llvm.py: bump to llvm 18 (#4259)
- CI: make macos' build_samples_wasm_c_api similar to ubuntu (#4253)
- Refactor fast-interpreter SIMD compilation flags (#4261)
- Bypass wamr_ide-related components from the release process. (#4268)
- Check for WASM_ENABLE_SIMDE in a couple more places (#4266)
- Add error handling for sgx ci (#4222)

### Security Issues

- Add validation for old_path in wasi_path_symlink (# CVE-2025-43853)

### Others

- Exclude fuzz test python and npm packages in scoreboard scan (#3871)
- Bump AOT_CURRENT_VERSION for WAMR 2.x (gc, memory64) (#3880)
- Add Tianlong into code owners (#3970)
- build(deps): Bump actions/upload-artifact from 4.4.3 to 4.5.0 (#3981)
- docs: Update build instructions suggestions for using Valgrind (#4164)
- test: temporarily skip 'skip-stack-guard-page' test case (#4163)
- build(deps): Bump actions/upload-artifact from 4.6.1 to 4.6.2 (#4159)
- Update NuttX and NuttX Apps references to releases/12.9 in workflow files (#4148)
- build(deps): Bump esbuild, @vitejs/plugin-react and vite (#4149)
- build(deps): Bump ossf/scorecard-action from 2.4.0 to 2.4.1 (#4109)
- build(deps): bump github/codeql-action from 3.26.13 to 3.28.1 (#3888) (#3902)
- build(deps): Bump github/codeql-action from 3.28.10 to 3.28.11 (#4132)
- build(deps): Bump github/codeql-action from 3.28.9 to 3.28.10 (#4108)
- build(deps): Bump actions/upload-artifact from 4.6.0 to 4.6.1 (#4107)

---

## WAMR-2.2.0

### Breaking changes

### New features

- Add support for multi-memory proposal in classic interpreter (#3742)
- wasi-nn: Add a new target for llama.cpp as a wasi-nn backend (#3709)
- Add memory instance support apis (#3786)
- Implement a first version of shared heap feature (#3789)
- Support dynamic aot debug (#3788)
- Implement shared heap for AOT (#3815)
- Support table64 extension in classic-interp and AOT running modes (#3811)

### Bug fixes

- Enable merged os_mmap for aot data sections (#3681)
- Fix arm64 issues on mac (#3688)
- aot loader: Call os_mmap with MMAP_MAP_32BIT only when target is x86-64 or riscv64 (#3755)
- Fix building iwasm_shared and iwasm_static libs on win32 (#3762)
- Fix compile error when multi-module and tags are enabled (#3781)
- Fix aot multi export memory support (#3791)
- Fix Windows compile error when uvwasi is enabled (#3810)
- Fix missing symbols when using aot mode on riscv platforms (#3812)
- Fix mac build of libc_emcc_wrapper.c (#3836)
- aot_comp_option.h: Add missing stdint.h header (#3834)
- Fix compilation error found in tflite test (#3820)
- Fix exec_env_tls assertion in module instantiation (#3844)
- Fix issues of destroy_shared_heaps (#3847)

### Enhancements

- aot loader: Refine os_mmap related code (#3711)
- Enable merged os_mmap for aot data sections and aot text (#3743)
- Improve posix mmap retry logic (#3714)
- Remove unnecessary code duplication in aot runtime (#3767)
- Add wamrc parameter to configure stack frame features (#3763)
- refactoring: Re-use commit IP functionality between exception handling and other cases (#3768)
- AOT call stack optimizations (#3773)
- Appease GCC strict prototypes warning (#3775)
- Appease GCC -Wformat (#3783)
- Fix compiler warnings (#3784)
- Implement option for skipping function index in the callstack (#3785)
- Fix a compile warning in aot_emit_function.c (#3793)
- Restore cmake hidden compile symbol visibility (#3796)
- Refactor shared heap feature for interpreter mode (#3794)
- Add no_resolve to LoadArgs and wasm_runtime_resolve_symbols (#3790)
- shared heap: Fix some issues and add basic unit test case (#3801)
- Add shared heap sample (#3806)
- Fix unused param warning when GC is enabled (#3814)
- Add scoreboard CI for supply-chain security (#3819)
- Emit load_addr and load_size if WAMR_ENABLE_COMPILER is set (#3835)
- libc-emcc: Use alternate method to check getrandom support (#3848)
- Enable libc-wasi for windows msvc build (#3852)
- Remove unused folder samples/gui and samples/littlevgl (#3853)
- Fix some compile warnings and typos (#3854)
- Allow to set native stack boundary to exec_env (#3862)
- Refine wasm/aot function instance lookup (#3865)
- Fix quadratic runtime for duplicate export name detection (#3861)

### Others

- Add a comment on AOT_SECTION_TYPE_SIGNATURE (#3746)
- CI: Freeze version of bloaty for NuttX compilation (#3756)
- aot compiler: Allow to control stack boundary check when boundary check is enabled (#3754)
- Update ref to the multi-memory tests (#3764)
- compilation_on_nuttx.yml: Update checkout action to suppress warnings (#3765)
- CI: Disable parallel test in spectest for NuttX (#3780)
- spec_test_on_nuttx.yml: Disable riscv32_ilp32f for now (#3777)
- Ignore temporary file from aider (#3787)
- Add CODEOWNERS (#3822)
- build(deps): bump github/codeql-action from 2.2.4 to 3.26.9 (#3826)
- build(deps): bump actions/upload-artifact from 3.1.0 to 4.4.0 (#3827)
- build(deps): bump ossf/scorecard-action from 2.3.1 to 2.4.0 (#3828)
- build(deps): bump github/codeql-action from 3.26.9 to 3.26.11 (#3843)
- build(deps): bump actions/upload-artifact from 4.4.0 to 4.4.3 (#3855)
- build(deps): bump github/codeql-action from 3.26.11 to 3.26.12 (#3856)
- Add Windows wamrc and iwasm build in release CI (#3857)
- Fix syntax error in codeql_buildscript.sh (#3864)
- release CI: Add another iwasm binary that supports Garbage Collection and Exception Handling (#3866)
- Fix lookup function issue reported in nightly run (#3868)

---

## WAMR-2.1.2

### Breaking Changes

- wasi-nn: Apply new architecture (#3692)

### New Features

- [wasi-nn] Add a new wasi-nn backend openvino (#3603)
- Add APIs into wasm_c_api.h to summary wasm function execution duration (#3639)
- Add support for RISCV32 ILP32F (#3708)

### Bug Fixes

- libc-builtin: Fix function prototype for wasm_runtime_module_realloc (#3702)
- Fix potential memory leak in insert_native_symbol (#3712)
- aot compiler: Fix NaN handling for opcode f32/f64.const in XIP mode (#3721)
- Fix table idx resolving in op call_indirect/return_call_indirect (#3726)

### Enhancements

- Remove a few hardcoded spec test knowledge from the core library (#3648)
- Change log of import function to be consistent (#3656)
- libc-builtin: Fix a printf format (#3652)
- Set compile symbol visibility to hidden in cmake (#3655)
- wamrc: Add --mllvm= option (#3658)
- wamr-compiler: Avoid size-level tweak if target is specified (#3659)
- aot runtime: Add missing arm/thumb relocations (#3660)
- aot compiler: Enlarge AOTNativeSymbol->symbol (#3662)
- aot compiler: Bail out on too long native symbol names (#3663)
- Support more features for rt-thread (#3661)
- Zephyr User Mode Support (#3650)
- Set posix thread name for debug build (#3657)
- Add emscripten_sleep() wrapper to libc-emcc (#3669)
- Fix a compilation warning (#3682)
- wamrc: Add some help text for --size-level (#3689)
- Restore linux iwasm default visibility (#3691)
- posix_thread.c: Restore old signal alternate stack before thread exit (#3693)
- libc-wasi: Make rights of STDIN/STDOUT/STDERR fixed and overlook their access modes (#3694)
- [refactoring] Extract read leb to a separate file, share the code between loader and mini loader (#3701)
- debug-interp: Only add lock when signal_flag is SIG_SINGSTEP (#3704)
- Fix compilation warnings (#3707)
- Add missing headers in bh_atomic.h and aot_llvm_extra.cpp (#3715)
- Update std atomic check and simd compatibility check for arc compiler (#3716)
- aot compiler: Track non-0x00 tableindex as ref types use (#3695)
- compilation: Use the dedicated stack-sizes section only for AOT (#3732)
- riscv: Add missing relocation intrinsics for **fixdfsi/**ltdf2 (#3733)

### Others

- Fix night run CI (#3640)
- spec-test-script/runtest.py: Don't assume the tmp dir path (#3632)
- wamr-test-suites: Remove dead code (wasi_test) (#3634)
- wamr-test-suites/test_wamr.sh: Add an option to specify wamrc binary (#3635)
- CI: Build llvm for xtensa (#3637)
- spec-test-script/runtest.py: Avoid specifying -v=0 unnecessarily (#3642)
- spec-test-script: Add xtensa case (#3643)
- spec-test-script/runtest.py: Move "--size-level=1" to common place for RISCV64 (#3644)
- spec-test-script/runtest.py: Use a shorter timeout when expected to fail (#3647)
- spec-test-script: Make case_last_words larger (#3651)
- spec-test-script/runtest.py: Reduce stack size for aot w/o gc (#3653)
- spec-test-script: Skip a few tests for xtensa qemu (#3664)
- spec-test-script: Use -mtext-section-literals for xtensa xip (#3666)
- spec_test_on_nuttx.yml: Add xtensa (#3665)
- spec_test_on_nuttx.yml: Enable xip (#3671)
- spec_test_on_nuttx.yml: Record more logs (#3670)
- spec_test_on_nuttx.yml: Replace sed with kconfig-tweak (#3672)
- spec_test_on_nuttx.yml: Retire CONFIG_EOL_IS_LF (#3676)
- spec-test-script/runtest.py: Use wamrc --xip option for xip (#3683)
- CI: Bump NuttX version to 12.6 (#3684)
- wamr-test-suites: Clean up generated tmp files after spec test (#3700)
- test_wamr.sh: Fix build wabt tool (#3703)
- NuttX: Retire CONFIG_ARCH_RV32IM and CONFIG_ARCH_RV64GC (#3717)
- runtest.py: Normallize option handling for XIP mode (#3722)
- CI: Enable XIP spectest for RISCV32 ILP32F (#3727)
- CI: Unify configuration stage for NuttX (#3725)

---

## WAMR-2.1.1

### Breaking Changes

- Sync up with latest wasi-nn spec (#3530)

### New Features

- Add APIs to get package version (#3601)
- Export API wasm_runtime_enlarge_memory (#3569)
- Add table type API support (#3515)
- Add wasm_runtime_get_module_package_type() and wasm_runtime_get_file_package_type() (#3600)

### Bug Fixes

- wasm_application.c: Avoid null pointer dereference (#3620)
- EH: Use the consistent type for EH handlers (#3619)
- wasm loader: Fix several issues in GC and exception handling (#3586)
- wasm loader: Fix push_frame_offset when pushing v128 type (#3588)
- Add integer overflow check for some indices in wasm/aot loader (#3579)
- aot-analyzer: Fix a few printf formats (#3590)
- aot-analyzer: Fix macos build (#3589)
- Fix compilation errors in aot-analyzer tool (#3584)
- interp debugger: Fix setting invalid value to step_count (#3583)
- aot loader: Check import global value type before using (#3571)
- Fix missing stack frame alloc/free in AOT multi-module invoke (#3562)
- aot loader: Verify global value type (#3560)
- aot loader: Add more checks in load_native_symbol_section() (#3559)
- core/shared/platform: Zero memory returned by os_mmap in some platforms (#3551)
- dwarf_extractor.cpp: Fix buffer overruns (#3541)
- aot loader: Prevent loading multiple native symbol sections (#3538)
- Validate func type in aot loader (#3535)
- wamrc: Fix truncated DW_AT_producer (#3537)
- wasm loader: Fix pop invalid offset count when stack top is ANY (#3516)
- Fix two fuzz issues (#3529)
- Fix several issues reported by oss-fuzz (#3526)

### Enhancements

- Fix compile warnings/error reported in Windows (#3616)
- wasm loader: Reject v128 for interpreters (#3611)
- Fix typos in wamrc and wasm_export.h (#3609)
- Bump ocaml/setup-ocaml from 2 to 3 (#3604)
- CMakeLists.txt: Fix Android pthread linkage (#3591)
- Add more arm AOT reloc entries (#3587)
- wasi-nn: Use numpy v1 in wasi-nn test requirements.txt (#3582)
- Optimize for multi-module support in AOT mode (#3563)
- aot compiler: Propagate const-ness by ourselves (#3567)
- aot_resolve_target_info: Avoid in-place modification of e_type (#3564)
- Allow missing imports in wasm loader and report error in wasm instantiation instead (#3539)
- aot compiler: Use larger alignment for load/store when possible (#3552)
- Consistent const keyword position in wasm_export.h (#3558)
- wasm_memory.c: Fix typo: hasn't been initialize -> `hasn't been initialized` (#3547)
- dwarf_extractor.cpp: Try to preserve link name (#3542)
- dwarf_extractor.cpp: Enable limited support for C++ (#3540)
- Sync up with latest wasi-nn spec (#3530)
- Expose more functions related to emitting AOT files (#3520)
- Make wasi-nn backends as separated shared libraries (#3509)
- build_llvm.py: Speed up llvm build with multi procs on windows (#3512)
- Fix compilation warnings of wasi-nn (#3497)
- Add missing functions to make RIOT work with the 2.x.x version (#3508)

### Others

- Update devcontainer.md (#3628)
- Fix compile errors on workload bwa and benchmark jetstream (#3617)
- wasm-mutator-fuzz: Set compilers earlier (#3585)
- wasm-mutator-fuzz: Make compilers overridable (#3578)
- wasi-nn: Add wasmedge-wasinn-example as smoke test (#3554)
- Add standalone cases (#3536)
- wasm-mutator-fuzz: Fix build errors and warnings for macOS (#3519)
- wasm-mutator-fuzz: Use another variable to check if in oss-fuzz environment (#3518)
- Add wasi-nn example as smoke test case (#3501)

---

## WAMR-2.1.0

### Breaking Changes

### New Features

- Add wasm_export.h APIs to expose memory type (#3496)
- Add api to get export global instance (#3452)
- Add wasm-mutator-fuzz test (#3420)
- Implement Memory64 support for AOT (#3362)
- Add wasm module global type information APIs (#3406)
- Add aot binary analysis tool aot-analyzer (#3379)
- Expose API to get import/export function's param/result valkind (#3363)
- Add WASI support for esp-idf platform (#3348)

### Bug Fixes

- Fix posix build when libc wasi is disabled and debug interp is enabled (#3503)
- Fix wasm_mini_loader.c build when jit or multi-module is enabled (#3502)
- Fix wasm loader check data segment count (#3492)
- Fix loader parse block type and calculate dynamic offset for loop args (#3482)
- Fix memory64 handling find_block_addr and execute_main (#3480)
- Fix two issues to make fuzzing test quit earlier (#3471)
- Fix test-wamr-ide CI failure (#3485)
- NuttX: Fix a dbus-related crash on esp32s3 (#3470)
- Clone data segments when specified with load args (#3463)
- Fix codeql compilation error (#3461)
- Fix several typos and fix bh_log calculate mills (#3441)
- ssp_config.h: Fix ifdef for android random api (#3444)
- libc-wasi: Fix a locking botch (#3437)
- Fix fast interp RECOVER_BR_INFO and local set/tee (#3434)
- aot compiler: Fix a type mismatch in compile_op_float_min_max (#3423)
- Correct Exception Handling tag type when GC is enabled (#3413)
- wasm loader: Fix handling if block without op else (#3404)
- ref-types: Correct default value for function local variables (#3397)
- aot compiler: Fix the length type passed to aot_memmove/aot_memset (#3378)
- Fix loader and mini-loader select potential error (#3374)
- Fix aot debugger compilation error on windows (#3370)
- A few native stack detection fixes for macOS/arm64 (#3368)
- Fix ESP32-S3 compiling error (#3359)
- Fix a few native stack address calculations (#3351)

### Enhancements

- Modify logging for windows exception handler and remove unused function (#3489)
- posix iwasm: Make the timeout logic a bit more robust (#3478)
- libc-builtin: Enhance buffered print for printf_wrapper (#3460)
- Enhance GC const initializer expression to support nested struct/array new (#3447)
- wasi: Tweak the configuration for nuttx and explain why (#3451)
- NuttX: Replace esp32s3 bits with the OS-provided APIs (#3439)
- Allow not copying the wasm binary in wasm-c-api and not referring to the binary in wasm/aot loader (#3389)
- aot: Make precheck functions use short-call for xtensa (#3418)
- Add wasm_runtime_detect_native_stack_overflow_size (#3355)
- Enhance wasm loader checks for opcode br_table (#3352)

### Others

- Bump requests from 2.32.2 to 2.32.3 in /build-scripts (#3494)
- Enable building static library on Android platform (#3488)
- wasm-mutator-fuzz: Generate more kinds of corpus (#3487)
- Correct nuttx repo names (#3484)
- Bump requests from 2.31.0 to 2.32.2 in /build-scripts (#3474)
- wasm-mutator-fuzz: Adapt to oss-fuzz compilation (#3464)
- Add regression tests of BA issue cases (#3462)
- Add malformed test cases (#3459)
- NuttX: Rename a few recently-added nuttx options (#3449)
- wamr-test-suites: Enable AOT multi-module spec tests (#3450)
- Remove install_wasi_sdk from workload preparation script (#3445)
- Add cmake static/shared library build settings (#3443)
- Update spec test to latest commit (#3293)
- Fix typo of WAMR_CONFIGUABLE_BOUNDS_CHECKS (#3424)
- ci/coding_guidelines_check.py: Allow some well-known file names to contain '-' (#3428)
- product-mini/platforms/posix/main.c: Adapt to WASM_MEM_DUAL_BUS_MIRROR (#3427)
- Add comments to global type function declarations (#3431)
- nuttx/esp32s3: Apply ibus/dbus adjustment to internal ram 1 as well (#3421)
- Change WASM_ANYREF to WASM_EXTERNREF (#3426)
- Remove unused macros which were moved to wamr-app-framework (#3425)
- Add WASM_V128 in wasm_valkind_enum (#3412)
- Fix basic example, parameter missmatch between host and wasm (#3415)
- Fix workspaces path in build_wamr.sh (#3414)
- core/iwasm/compilation: Remove stale function prototypes (#3408)
- Add test cases for the requirements of "gc-aot" feature (#3399)
- append_aot_to_wasm.py: Add --ver-str option to emit more info in custom section name (#3398)
- Fix clang compile warnings (#3396)
- Fix some more spelling issues (#3393)
- Fix some spelling issues (#3385)
- samples/native-stack-overflow: Examine native functions with signature (#3382)
- Add some more comments on WASM_STACK_GUARD_SIZE (#3380)
- Fix typo for 'native' in wasm_export.h (#3376)
- CI: Use macos-13 instead of macos-latest (#3366)
- Test more samples in nightly-run CI (#3358)
- Random improvements to samples/native-stack-overflow (#3353)
- Reduce WASM_STACK_GUARD_SIZE a bit for posix-like platforms (#3350)
- doc: Add ADOPTERS.md (#3324)
- Update binary size info in README.md (#3030)
- core/config.h: Bump the default WASM_STACK_GUARD_SIZE (#3344)
- Add unit test suites (#3490)
- Fix internal global getter types (#3495)
- Fix CI build and run unit tests (#3499)

---

## WAMR-2.0.0

### Breaking Changes

- The AOT ABI was changed after GC and memory64 features were introduced:
  - Implement GC feature for interpreter, AOT and LLVM-JIT (#3125)
  - Implement memory64 for classic interpreter (#3266)
  - Always allocate linear memory using mmap (#3052)
  - Refactor APIs and data structures as preliminary work for Memory64 (#3209)
- Remove unused argument in wasm_runtime_lookup_function (#3218)
- Separate app-manager and app-framework from WAMR (#3129)

### New Features

- Implement GC feature for interpreter, AOT and LLVM-JIT (#3125)
- Implement memory64 for classic interpreter (#3266)
- Add wasi_ephemeral_nn module support (#3241)

### Bug Fixes

- EH: Fix broken stack usage calculation (#3121)
- Fix loader check_wasi_abi_compatibility (#3126)
- Fix possible integer overflow in loader target block check (#3133)
- Fix locel.set in polymorphic stack (#3135)
- Fix threads opcodes' boundary check in classic-interp and fast-interp (#3136)
- fast-interp: Fix copy_stack_top_i64 overlap issue (#3146)
- Fix a ubsan complaint "applying zero offset to null pointer" (#3160)
- fast-interp: Fix GC opcode ref.as_non_null (#3156)
- Fix llvm jit push funcref/externref result type issue (#3169)
- Fix wasm loader handling opcode br_table (#3176)
- Fix ref.func opcode check when GC is enabled (#3181)
- lldb_function_to_function_dbi: Fix a null dereference (#3189)
- Fix compilation errors on MinGW (#3217)
- Fix compilation errors on esp-idf platform (#3224)
- Fix aot relocation symbols not found on windows 32-bit (#3231)
- posix_file.c: Correct the dirfd argument that passes to fstatat (#3244)
- Fix compilation errors on zephyr platform (#3255)
- Fix dynamic offset not updated in op_br for block with ret type (#3269)
- aot debug: Fix a NULL dereference (#3274)
- thread mgr: Free aux stack only when it was allocated (#3282)
- interp: Restore context from prev_frame after tail calling a native function (#3283)
- Sync simd opcode definitions spec (#3290)
- Fix posix_fadvise error handling (#3323)
- Fix windows relocation string parsing issue (#3333)

### Enhancements

- Zero the memory mapped from os_mmap in NuttX (#3132)
- Use logger for runtime error/debug prints (#3097)
- aot_compile_op_call: Stop setting calling convention explicitly (#3140)
- aot compiler: Place precheck wrapper before the corresponding wrapped function (#3141)
- Fix null pointer access in fast-interp when configurable soft bound check is enabled (#3150)
- Clarify how to verify SGX evidence without an Intel SGX-enabled platform (#3158)
- zephyr: Use zephyr sys_cache instead of CMSIS (#3162)
- VSCode IDE enhancement and readme update (#3172)
- Add vprintf override for android and esp-idf (#3174)
- zephyr: Include math only with minimal libc (#3177)
- zephyr: Implement Alloc_With_System_Allocator (#3179)
- Use indirect call in pre-checker function to avoid relocation in XIP mode (#3142)
- Implement the remaining Windows filesystem functions (#3166)
- Fix LLVM assertion failure and update CONTRIBUTING.md (#3197)
- Allow overriding max memory on module instantiation (#3198)
- Get location info from function indexes in addr2line script (#3206)
- Demangle function names in stack trace when using addr2line script (#3211)
- Refactor APIs and data structures as preliminary work for Memory64 (#3209)
- Allow converting the zero wasm address to native (#3215)
- Small refactor on WASMModuleInstance and fix Go/Python language bindings (#3227)
- Add esp32c6 support (#3234)
- Make android platform's cmake flags configurable (#3239)
- Go binding: Change C.long to C.int64_t when call wasm_runtime_set_wasi_args_ex (#3235)
- Implement apis to set and get the name of a wasm module (#3254)
- Append '\0' to every name string in aot name section (#3249)
- Add cmake flag to control aot intrinsics (#3261)
- Add lock and ref_count for runtime init (#3263)
- nuttx: Migrate NuttX CMake build for WAMR (#3256)
- LLVM 19: Switch to debug records (#3272)
- aot debug: Process lldb_function_to_function_dbi only for C (#3278)
- Fix warnings/issues reported in Windows and by CodeQL/Coverity (#3275)
- Enhance wasm loading with LoadArgs and support module names (#3265)
- Add wamr to esp-idf components registry (#3287)
- zephyr: Add missing pthread library functions (#3291)
- Add more checks in wasm loader (#3300)
- Log warning if growing table failed (#3310)
- Enhance GC subtyping checks (#3317)
- User defined memory allocator for different purposes (#3316)
- Add a comment on WASM_STACK_GUARD_SIZE (#3332)
- Allow executing malloc/free from native in memory64 mode (#3315)
- Add functions to expose module import/export info (#3330)

### Others

- Add ARM MacOS to the CI (#3120)
- Download jetstream src from github instead of browserbench.org (#3196)
- Update document to add wamr-rust-sdk introduction (#3204)
- Fix nightly run tsan ASLR issue (#3233)
- Add CodeQL Workflow for Code Security Analysis (#2812)
- Add issue templates (#3248)
- Fix CI error when install packages for macos-14 (#3270)
- Update document for GC, exception handling and memory64 features (#3284)
- Update release CI (#3295)
- Add native-stack-overflow sample (#3321)

---

## WAMR-1.3.2

### Breaking Changes

### New Features

- Implement Exception Handling for classic interpreter (#3096)
  - Use `cmake -DWAMR_BUILD_EXCE_HANDLING=1/0` option to enable/disable
    the feature, and by default it is disabled
  - It is still in highly experimental stage

### Bug Fixes

- Fix build errors when initializing wasm_val_t values with macros (#3007)
- fix(wasm-c-api): Do not clone stack frames if there's no trap (#3008)
- classic-interp: Handle SIMD opcode when JIT is enabled (#3046)
- fast-interp: Fix dynamic offset error issue in else branch (#3058)
- wasm_cluster_destroy_spawned_exec_env: Avoid "invalid exec env" trap (#3068)
- thread-mgr: Fix locking problems around aux stack allocation (#3073)
- cosmopolitan: Update compiler and update platform_internal.h (#3079)
- wasi: Apply wasm_runtime_begin_blocking_op to poll as well (#3080)
- Fix memory/table segment checks in memory.init/table.init (#3081)
- perf profiling: Adjust the calculation of execution time (#3089)
- aot: Fix LLVMSetTailCallKind check (#3099)
- fast-interp: Fix stack recovery for else branch (#3100)
- fast-interp: Fix frame_offset pop order (#3101)
- Fix AOT compilation on MacOS (#3102)
- fast-interp: Fix block with parameter in polymorphic stack issue (#3112)
- Fix read and validation of misc/simd/atomic sub opcodes (#3115)

### Enhancements

- Clear compilation warning and dead code (#3002)
- aot debug: Try to use a bit more appropriate file names (#3000)
- Increase default app thread stack size (#3010)
- Rename rwlock_init to avoid conflict (#3016)
- nuttx: Use larger alignment for os_mmap and comment why (#3017)
- Allow using mmap for shared memory if hw bound check is disabled (#3029)
- Don't redefine D_INO if already defined (#3036)
- Enhancements on wasm function execution time statistic (#2985)
- wamr-compiler: Fix non-x86{\_64} host builds (#3037)
- Disable quick aot entry for interp and fast-jit (#3039)
- nuttx: Add option to enable quick aot entry (#3040)
- Set CONFIG_HAS_CAP_ENTER to support posix file api for freertos (#3041)
- Revert "Enable MAP_32BIT for macOS (#2992)" (#3032)
- Enable quick aot entry when hw bound check is disabled (#3044)
- Do not inherit WASM_SUSPEND_FLAG_BLOCKING from the parent thread (#3051)
- wasm_runtime_begin_blocking_op: A comment about usage expectation (#3056)
- Check arguments before calling bh_hash_map_find (#3055)
- Fix aot large model (--size-level=0) with LLVM 18 (#3057)
- Add flag to control Winsocket initialization (#3060)
- nuttx: If STACK_GUARD_SIZE is not set, leave it to config.h (#2927)
- Enhance setting write gs base with cmake variable (#3066)
- aot_reloc_x86_64.c: Suggest to try --size-level=0 as well (#3067)
- Fix some issues reported by CodeQL (#3064)
- Remove a lot of "unused parameter" warnings (#3075)
- Forward log and log level to custom bh_log callback (#3070)
- Fix inconsistent code style in aot_loader.c (#3082)
- freertos: Thread exit more common (#3094)
- Fix windows build error and compilation warnings (#3095)

### Others

- Fix nightly-run CI failure (#3014)
- Build samples in debug mode (#3019)
- Remove deprecated tests in language-bindings python (#3018)
- Avoid unused thread_id warning and recompile multi-module sample (#3033)
- samples/terminate: Add a sample to demonstrate wasm_runtime_terminate (#3043)
- Bump NuttX version to 12.4.x in CI (#3047)
- perf_tune.md: Add refine the calling processes between host and wasm (#3065)
- build_wamr.md: Update the document (#3074)
- Fix download link for wasi-sdk (#3077)
- README.md: Fix typo tunning to tuning (#3078)
- Update outdated reference link in multi_module.md (#3092)
- Add comments to suppress warning from clang-tidy (#3088)
- CI: Update version of checkout to suppress warnings (#3093)
- test_wamr.sh: Allow using test script on different platforms (#3098)

---

## WAMR-1.3.1

### Breaking Changes

- In multi-threading, when an exception was thrown in wasm_func_call(),
  the trap returned contains the stack frames of the thread where the
  exception occurs, but not the stack frames of the main thread.
- Disable emitting custom name section to AOT file with
  `wamrc --enable-dump-call-stack` option, instead, use
  `wamrc --emit-custom-sections=name` to emit it and make it clear.

### New Features

- Enable AOT linux perf support (#2930)

### Bug Fixes

- Corrects Zephyr include files for current versions of Zephyr (#2881)
- Fix possible dead lock in wasm_cluster_spawn_exec_env (#2882)
- Handle ambiguous fstflags on fd_filestat_set_times (#2892)
- Fix memory size not updating after growing in interpreter (#2898)
- fixed(freertos): Fix crash when wasm app call pthread_exit(NULL) (#2970)
- fast-jit: Fix const shift and const i64 compare issues (#2969)
- Fix ref.is_null processing in fast-interp loader (#2971)
- simd-128: The input lanes of integer-to-integer narrowing ops should be interpreted as signed (#2850)
- Fix ref.func function declared check in wasm loader (#2972)
- Fix fast-interp polymorphic stack processing (#2974)
- Fix potential recursive lock in pthread_create_wrapper (#2980)
- Fix build failure on esp-idf platform (#2991)
- Return stack frames of crashed thread when using wasm-c-api (#2908)
- Fix compilation error on iOS due to macOS-specific API (#2995)
- Fix a bug when emit the custom name section to aot file (#2987)
- Fix linux-sgx build error when libc-wasi is disabled (#2997)

### Enhancements

- fix command-reactor: Look for \_initialize only if \_start not found (#2891)
- Refactor reloc symbols for riscv (#2894)
- Avoid memory import failure when wasi-threads is enabled (#2893)
- interpreter: Simplify memory.grow a bit (#2899)
- Avoid reporting timestamp if custom logger is used (#2905)
- Expose API to set log level in embedder (#2907)
- Add a script to translate jitted function names in flamegraph (#2906)
- Refine wasm-c-api wasm_func_call (#2922)
- Add VectorCombine pass for JIT and AOT (#2923)
- Enable wasm_runtime_terminate for single-threading (#2924)
- nuttx: Add CONFIG_INTERPRETERS_WAMR_DEBUG_AOT (#2929)
- Allow to control built-in libraries for wamrc from command line options (#2928)
- Fix a bug that appends '\_precheck' to aot_func (#2936)
- freertos: Add os_cond_broadcast for pthread wrapper (#2937)
- Append .aot to .wasm as a custom section named "aot" (#2933)
- fix(sgx-ra): Fix building when enclave is built without librats ahead (#2968)
- Refine LLVM JIT function call process (#2925)
- Refine AOT function call process (#2940)
- Allow to set segue flags for wasm-c-api JIT (#2926)
- freertos: Minor changes for freertos libc_wasi build adaption (#2973)
- freertos: Change ssp_config.h due to clock_nanosleep() not supported in freertos (#2979)
- aot compiler: Some updates for LLVM 18 (#2981)
- Enable MAP_32BIT for macOS (#2992)
- Register quick call entries to speedup the aot/jit func call process (#2978)
- Refine AOT/JIT code call wasm-c-api import process (#2982)

### Others

- compilation_on_nuttx.yml: Use docker image to simplify env setup (#2878)
- samples/spawn-thread: Disable libc and pthread (#2883)
- Add arm64 to nuttx compilation test (#2886)
- samples/spawn-thread: Tweak to expose a bug (#2888)
- Fix typo in CI config and suppress STORE_U8 in TSAN (#2802)
- Using docker image for nuttx spectest (#2887)
- doc: Separate source_debugging.md into two files (#2932)
- doc/build_wasm_app.md: Add a note about aot abi compatibility (#2993)

---

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
- Handle a return from wasi \_start function correctly (#2529)
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
- Return \_\_WASI_EINVAL from fd_prestat_dir_name (#2580)
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
- Fix format warning by PRIu32 in [wasm|aot] dump call stack (#2251)
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
- Fix sanitizer errors in posix socket (#2331)
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
- Implement R*ARM_THM_MOVT*[ABS|REPL] for thumb
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
