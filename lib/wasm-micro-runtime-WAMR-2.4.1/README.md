# WebAssembly Micro Runtime


**A [Bytecode Alliance][BA] project**

[BA]: https://bytecodealliance.org/

**[Guide](https://wamr.gitbook.io/)**&emsp;&emsp;**[Website](https://bytecodealliance.github.io/wamr.dev)**&emsp;&emsp;**[Chat](https://bytecodealliance.zulipchat.com/#narrow/stream/290350-wamr)**

[Build WAMR](./doc/build_wamr.md) | [Build AOT Compiler](./wamr-compiler/README.md) | [Embed WAMR](./doc/embed_wamr.md) | [Export Native API](./doc/export_native_api.md) | [Build Wasm Apps](./doc/build_wasm_app.md) | [Samples](./samples/README.md)

WebAssembly Micro Runtime (WAMR) is a lightweight standalone WebAssembly (Wasm) runtime with small footprint, high performance and highly configurable features for applications cross from embedded, IoT, edge to Trusted Execution Environment (TEE), smart contract, cloud native and so on. It includes a few parts as below:
- [**VMcore**](./core/iwasm/): A set of runtime libraries for loading and running Wasm modules. It supports rich running modes including interpreter, Ahead-of-Time compilation(AoT) and Just-in-Time compilation (JIT). WAMR supports two JIT tiers - Fast JIT, LLVM JIT, and dynamic tier-up from Fast JIT to LLVM JIT.
- [**iwasm**](./product-mini/): The executable binary built with WAMR VMcore which supports WASI and command line interface.
- [**wamrc**](./wamr-compiler/): The AOT compiler to compile Wasm file into AOT file
- Useful components and tools for building real solutions with WAMR vmcore:
  - [App-framework](https://github.com/bytecodealliance/wamr-app-framework/blob/main/app-framework/README.md): A framework for supporting APIs for the Wasm applications
  - [App-manager](https://github.com/bytecodealliance/wamr-app-framework/blob/main/app-mgr/README.md): A framework for dynamical loading the Wasm module remotely
  - [WAMR-IDE](./test-tools/wamr-ide): An experimental VSCode extension for developping WebAssembly applications with C/C++


### Key features
- Full compliant to the W3C Wasm MVP
- Small runtime binary size (core vmlib on cortex-m4f with tail-call/bulk memory/shared memory support, text size from bloaty)
  * ~58.9K for fast interpreter
  * ~56.3K for classic interpreter
  * ~29.4K for aot runtime
  * ~21.4K for libc-wasi library
  * ~3.7K for libc-builtin library
- Near to native speed by AOT and JIT
- Self-implemented AOT module loader to enable AOT working on Linux, Windows, MacOS, Android, SGX and MCU systems
- Choices of Wasm application libc support: the built-in libc subset for the embedded environment or [WASI](https://github.com/WebAssembly/WASI) for the standard libc
- [The simple C APIs to embed WAMR into host environment](./doc/embed_wamr.md), see [how to integrate WAMR](./doc/embed_wamr.md) and the [API list](./core/iwasm/include/wasm_export.h)
- [The mechanism to export native APIs to Wasm applications](./doc/export_native_api.md), see [how to register native APIs](./doc/export_native_api.md)
- [Multiple modules as dependencies](./doc/multi_module.md), ref to [document](./doc/multi_module.md) and [sample](samples/multi-module)
- [Multi-thread, pthread APIs and thread management](./doc/pthread_library.md), ref to [document](./doc/pthread_library.md) and [sample](samples/multi-thread)
- [wasi-threads](./doc/pthread_impls.md#wasi-threads-new), ref to [document](./doc/pthread_impls.md#wasi-threads-new) and [sample](samples/wasi-threads)
- [Linux SGX (Intel Software Guard Extension) support](./doc/linux_sgx.md), ref to [document](./doc/linux_sgx.md)
- [Source debugging support](./doc/source_debugging.md), ref to [document](./doc/source_debugging.md)
- [XIP (Execution In Place) support](./doc/xip.md), ref to [document](./doc/xip.md)
- [Berkeley/Posix Socket support](./doc/socket_api.md), ref to [document](./doc/socket_api.md) and [sample](./samples/socket-api)
- [Multi-tier JIT](./product-mini#linux) and [Running mode control](https://bytecodealliance.github.io/wamr.dev/blog/introduction-to-wamr-running-modes/)
- Language bindings: [Go](./language-bindings/go/README.md), [Python](./language-bindings/python/README.md), [Rust](./language-bindings/rust/README.md)

### Wasm post-MVP features
- [wasm-c-api](https://github.com/WebAssembly/wasm-c-api), ref to [document](doc/wasm_c_api.md) and [sample](samples/wasm-c-api)
- [128-bit SIMD](https://github.com/WebAssembly/simd), ref to [samples/workload](samples/workload)
- [Reference Types](https://github.com/WebAssembly/reference-types), ref to [document](doc/ref_types.md) and [sample](samples/ref-types)
- [Bulk memory operations](https://github.com/WebAssembly/bulk-memory-operations), [Shared memory](https://github.com/WebAssembly/threads/blob/main/proposals/threads/Overview.md#shared-linear-memory), [Memory64](https://github.com/WebAssembly/memory64)
- [Tail-call](https://github.com/WebAssembly/tail-call), [Garbage Collection](https://github.com/WebAssembly/gc), [Exception Handling](https://github.com/WebAssembly/exception-handling)
- [Extended Constant Expressions](https://github.com/WebAssembly/extended-const)

### Supported architectures and platforms
The WAMR VMcore supports the following architectures:
- X86-64, X86-32
- ARM, THUMB (ARMV7 Cortex-M7 and Cortex-A15 are tested)
- AArch64 (Cortex-A57 and Cortex-A53 are tested)
- RISCV64, RISCV32 (RISC-V LP64 and RISC-V LP64D are tested)
- XTENSA, MIPS, ARC

The following platforms are supported, click each link below for how to build iwasm on that platform. Refer to [WAMR porting guide](./doc/port_wamr.md) for how to port WAMR to a new platform.
- [Linux](./product-mini/README.md#linux),  [Linux SGX (Intel Software Guard Extension)](./doc/linux_sgx.md),  [MacOS](./product-mini/README.md#macos),  [Android](./product-mini/README.md#android), [Windows](./product-mini/README.md#windows), [Windows (MinGW, MSVC)](./product-mini/README.md#mingw)
- [Zephyr](./product-mini/README.md#zephyr),  [AliOS-Things](./product-mini/README.md#alios-things),  [VxWorks](./product-mini/README.md#vxworks), [NuttX](./product-mini/README.md#nuttx), [RT-Thread](./product-mini/README.md#RT-Thread), [ESP-IDF(FreeRTOS)](./product-mini/README.md#esp-idf)


## Getting started
- [Build VM core](./doc/build_wamr.md) and [Build wamrc AOT compiler](./wamr-compiler/README.md)
- [Build iwasm (mini product)](./product-mini/README.md): [Linux](./product-mini/README.md#linux), [SGX](./doc/linux_sgx.md), [MacOS](./product-mini/README.md#macos) and [Windows](./product-mini/README.md#windows)
- [Embed into C/C++](./doc/embed_wamr.md), [Embed into Python](./language-bindings/python), [Embed into Go](./language-bindings/go), [Embed in Rust](./language-bindings/rust)
- [Register native APIs for Wasm applications](./doc/export_native_api.md)
- [Build wamrc AOT compiler](./wamr-compiler/README.md)
- [Build Wasm applications](./doc/build_wasm_app.md)
- [Port WAMR to a new platform](./doc/port_wamr.md)
- [VS Code development container](./doc/devcontainer.md)
- [Samples](./samples) and [Benchmarks](./tests/benchmarks)
- [End-user APIs documentation](https://bytecodealliance.github.io/wamr.dev/apis/)


### Performance and memory
- [Blog: The WAMR memory model](https://bytecodealliance.github.io/wamr.dev/blog/the-wamr-memory-model/)
- [Blog: Understand WAMR heaps](https://bytecodealliance.github.io/wamr.dev/blog/understand-the-wamr-heaps/) and [stacks](https://bytecodealliance.github.io/wamr.dev/blog/understand-the-wamr-stacks/)
- [Blog: Introduction to WAMR running modes](https://bytecodealliance.github.io/wamr.dev/blog/introduction-to-wamr-running-modes/)
- [Memory usage tuning](./doc/memory_tune.md): the memory model and how to tune the memory usage
- [Memory usage profiling](./doc/build_wamr.md#enable-memory-profiling-experiment): how to profile the memory usage
- [Performance tuning](./doc/perf_tune.md): how to tune the performance
- [Benchmarks](./tests/benchmarks): checkout these links for how to run the benchmarks: [PolyBench](./tests/benchmarks/polybench), [CoreMark](./tests/benchmarks/coremark), [Sightglass](./tests/benchmarks/sightglass), [JetStream2](./tests/benchmarks/jetstream)
- [Performance and footprint data](https://github.com/bytecodealliance/wasm-micro-runtime/wiki/Performance): the performance and footprint data


Project Technical Steering Committee
====================================
The [WAMR PTSC Charter](./TSC_Charter.md) governs the operations of the project TSC.
The current TSC members:
- [dongsheng28849455](https://github.com/dongsheng28849455) - **Dongsheng Yan**, <dongsheng.yan@sony.com>
- [loganek](https://github.com/loganek) - **Marcin Kolny**, <mkolny@amazon.co.uk>
- [lum1n0us](https://github.com/lum1n0us) - **Liang He**， <liang.he@intel.com>
- [no1wudi](https://github.com/no1wudi) **Qi Huang**, <huangqi3@xiaomi.com>
- [qinxk-inter](https://github.com/qinxk-inter) - **Xiaokang Qin**， <xiaokang.qxk@antgroup.com>
- [ttrenner ](https://github.com/ttrenner) - **Trenner, Thomas**， <trenner.thomas@siemens.com>
- [wei-tang](https://github.com/wei-tang) - **Wei Tang**， <tangwei.tang@antgroup.com>
- [wenyongh](https://github.com/wenyongh) - **Wenyong Huang**， <wenyong.huang@intel.com>
- [woodsmc](https://github.com/woodsmc) - **Woods, Chris**， <chris.woods@siemens.com>
- [xujuntwt95329](https://github.com/xujuntwt95329) - **Jun Xu**， <Jun1.Xu@intel.com>
- [xwang98](https://github.com/xwang98) - **Xin Wang**， <xin.wang@intel.com> (chair)
- [yamt](https://github.com/yamt) - **Takashi Yamamoto**, <yamamoto@midokura.com>


License
=======
WAMR uses the same license as LLVM: the `Apache 2.0 license` with the LLVM
exception. See the LICENSE file for details. This license allows you to freely
use, modify, distribute and sell your own products based on WAMR.
Any contributions you make will be under the same license.

# More resources
- [Who use WAMR?](https://github.com/bytecodealliance/wasm-micro-runtime/wiki)
- [WAMR Blogs](https://bytecodealliance.github.io/wamr.dev/blog/)
- [Community news and events](https://bytecodealliance.github.io/wamr.dev/events/)
- [WAMR TSC meetings](https://github.com/bytecodealliance/wasm-micro-runtime/wiki/TSC-meeting-notes)

