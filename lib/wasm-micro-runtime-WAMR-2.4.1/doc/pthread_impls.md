# Pthread implementations

WAMR has two pthread implementations available as of writing this.

These implementations are not ABI-compatible. You at least need to rebuild
your wasm modules when migrating from one pthread implementation to another.

For new users, we recommend to use (or at least experiment)
the new wasi-threads based implementation.
In future, we might remove the old implementation.

## WAMR lib-pthread (old)

  * The pthread API is directly implemented as host functions in WAMR.
    (`WAMR_BUILD_LIB_PTHREAD`)

  * Only minimum API is implemented as of writing this.
    (eg. no pthread barriers)

  * WAMR-specific ABI

  * [Known limitations](pthread_library.md#known-limits)

## wasi-threads (new)

  * The pthread API is implemented in wasi-libc, based on
    [wasi-threads](https://github.com/WebAssembly/wasi-threads)
    and [WASM threads](https://github.com/WebAssembly/threads) proposals.

  * It requires a recent-enough version of wasi-libc. The experimental support
    is included in
    [wasi-sdk 20.0](https://github.com/WebAssembly/wasi-sdk/releases/tag/wasi-sdk-20)
    or later.
    To build your application, cmake users can use the
    [cmake toolchain file](https://github.com/WebAssembly/wasi-sdk/blob/main/wasi-sdk-pthread.cmake)
    provided by wasi-sdk.

  * wasi-threads is implemented as a host function in WAMR.
    (`WAMR_BUILD_LIB_WASI_THREADS`)

  * The ABI is specified in wasi-threads proposal.
    You can run the same wasm modules on other runtimes which implement
    the proposal. (wasmtime, toywasm, ...)

  * Basically more feature-rich and complete than WAMR lib-pthread.

    **EXCEPTION**: `pthread_exit` is not available as of writing this.
    If `pthread_exit` is important for your use cases, please speak up in
    the [GitHub issue](https://github.com/WebAssembly/wasi-threads/issues/7).

    **EXCEPTION**: For threads created by `pthread_create`, the AUX stack
    (aka C shadow stack) overflow detection mechanism is disabled as of
    writing this.
    If it's important for your use cases, please speak up in the
    [GitHub issue](https://github.com/WebAssembly/wasi-threads/issues/12).

# References

* https://github.com/bytecodealliance/wasm-micro-runtime/issues/1790
