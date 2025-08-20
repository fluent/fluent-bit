
# Samples
- [**basic**](./basic): Demonstrating how to use runtime exposed API's to call WASM functions, how to register native functions and call them, and how to call WASM function from native function.
- **[simple](./simple/README.md)**: The runtime is integrated with most of the WAMR APP libraries, and a few WASM applications are provided for testing the WAMR APP API set. It uses **built-in libc** and executes apps in **interpreter** mode by default.
- **[file](./file/README.md)**: Demonstrating the supported file interaction API of WASI. This sample can also demonstrate the SGX IPFS (Intel Protected File System), enabling an enclave to seal and unseal data at rest.
- **[littlevgl](./littlevgl/README.md)**: Demonstrating the graphic user interface application usage on WAMR. The whole [LVGL](https://github.com/lvgl/lvgl) 2D user graphic library and the UI application are built into WASM application.  It uses **WASI libc** and executes apps in **AOT mode** by default.
- **[gui](./gui/README.md)**: Move the [LVGL](https://github.com/lvgl/lvgl) library into the runtime and define a WASM application interface by wrapping the littlevgl API. It uses **WASI libc** and executes apps in **interpreter** mode by default.
- **[multi-thread](./multi-thread/)**: Demonstrating how to run wasm application which creates multiple threads to execute wasm functions concurrently, and uses mutex/cond by calling pthread related API's.
- **[spawn-thread](./spawn-thread)**: Demonstrating how to execute wasm functions of the same wasm application concurrently, in threads created by host embedder or runtime, but not the wasm application itself.
- **[wasi-threads](./wasi-threads/README.md)**: Demonstrating how to run wasm application which creates multiple threads to execute wasm functions concurrently based on lib wasi-threads.
- **[multi-module](./multi-module)**: Demonstrating the [multiple modules as dependencies](./doc/multi_module.md) feature which implements the [load-time dynamic linking](https://webassembly.org/docs/dynamic-linking/).
- **[ref-types](./ref-types)**: Demonstrating how to call wasm functions with argument of externref type introduced by [reference types proposal](https://github.com/WebAssembly/reference-types).
- **[wasm-c-api](./wasm-c-api/README.md)**: Demonstrating how to run some samples from [wasm-c-api proposal](https://github.com/WebAssembly/wasm-c-api) and showing the supported API's.
- **[socket-api](./socket-api/README.md)**: Demonstrating how to run wasm tcp server and tcp client applications, and how they communicate with each other.
- **[native-lib](./native-lib/README.md)**: Demonstrating how to write required interfaces in native library, build it into a shared library and register the shared library to iwasm.
- **[sgx-ra](./sgx-ra/README.md)**: Demonstrating how to execute Remote Attestation on SGX with [librats](https://github.com/inclavare-containers/librats), which enables mutual attestation with other runtimes or other entities that support librats to ensure that each is running within the TEE.
- **[workload](./workload/README.md)**: Demonstrating how to build and run some complex workloads, e.g. tensorflow-lite, XNNPACK, wasm-av1, meshoptimizer and bwa.
