# Fork of libco for Fluent Bit

This repository is a fork of the original library [libco](https://byuu.org/library/libco/) v18 created by Byuu. Compared to the original version it have the following changes:

- Core
  - ARMv8: workaround for [GCC bug](https://gcc.gnu.org/bugzilla/show_bug.cgi?id=90907).
  - Added [aarch64.c](aarch64.c) backend file created by [webgeek1234](https://github.com/webgeek1234).
  - Fixes on settings.h to get MacOS support.
- API
  - co_create() have a third argument to retrieve the real size of the stack created.

This library is used inside [Fluent Bit](http://github.com/fluent/fluent-bit) project, so this repo aims to keep aligned with latest releases but including our required patches.

Eduardo Silva <edsiper@gmail.com>

## Testing

Configure and run the native runtime tests with:

```sh
cmake -S . -B build -DLIBCO_TESTS=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure --no-tests=error
```

The runtime suite checks repeated and nested coroutine switches, active handles,
stack-local values, allocation/deletion, and isolation between OS threads. Checks
remain enabled in Release builds. On Linux and FreeBSD it also builds the SJLJ
and ucontext backends independently; on Windows it also builds fibers. Disable
these extra variants with `-DLIBCO_TESTS_PORTABLE=OFF`. SJLJ tests disable
`_FORTIFY_SOURCE` for that backend because glibc's checked `longjmp` rejects its
intentional alternate-stack jumps. Coroutine creation is serialized because
SJLJ temporarily installs a process-wide signal handler.

[GitHub Actions](.github/workflows/ci.yml) runs on pushes, pull requests, and manual
requests. Every matrix entry builds and executes tests; QEMU entries are runtime
tests, not just cross-compilation checks.

| Platform | Architectures / backends | Execution |
| --- | --- | --- |
| Ubuntu 26.04, GCC and Clang | x86-64, AArch64; SJLJ, ucontext | Native |
| Ubuntu 26.04, GCC | i686, ARM hard-float, AArch64, RISC-V64, PPC32 big-endian, PPC64 big-endian, PPC64 little-endian; SJLJ, ucontext | QEMU user mode |
| macOS, Clang | x86-64, AArch64 | Native |
| Windows, MSVC and MinGW GCC/Clang | x86, x86-64; automatic selection and explicit fibers | Native |
| Emscripten 6.0.9 | wasm32 Asyncify fibers | Node.js |

Debug and Release configurations cover the native and emulated Linux, macOS,
and Windows targets (native Linux GCC uses Release only). WebAssembly
runs Debug, Release, and AddressSanitizer, including the existing worker reuse,
external consumer, and expected-fault tests. RISC-V also runs its existing stack
headroom regression. The SDK version is pinned to the version required by
`emscripten.c`.

This matrix covers every backend source file; it does not claim exhaustive ABI,
register-preservation, browser, or CPU-extension coverage. Windows GNU/Clang builds select the OS fiber backend before CPU-specific
backends to avoid the MinGW x64 assembly context-alignment crash.

See [the open PR review](doc/pr-review.md) for the status of PRs #8 and #12.
