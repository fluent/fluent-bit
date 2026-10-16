# Open PR review

Reviewed on 2026-09-21 against local HEAD `9572739` and refreshed
`origin/master` (`6714dff`). Their source trees are identical. No PR was merged,
closed, or commented on as part of this review.

## PR #8: aarch64 FreeBSD malloc header

https://github.com/edsiper/flb_libco/pull/8

**Recommendation: close as superseded for the supported CMake build.**

The PR replaces `<malloc.h>` with `<malloc_np.h>` on FreeBSD and enables
`HAVE_POSIX_MEMALIGN`. Commit `4400e0a` (merged PR #10, 2021-12-18) already
added symbol detection for `posix_memalign` in `stdlib.h` and `malloc_np.h`.
`aarch64.c` uses those results to avoid `<malloc.h>` and select
`posix_memalign`. That change is present on current master.

The initial hosted CI run on Ubuntu 24.04 passed both FreeBSD architectures,
including AArch64. FreeBSD jobs were subsequently removed from the CI matrix;
these historical results do not constitute ongoing FreeBSD coverage.

Scope: compiling `libco.c` directly without the CMake feature definitions can
still reach the `<malloc.h>` fallback. Such consumers must supply the feature
macros or receive a separate standalone-build portability fix; the CMake fix
does not establish that every non-CMake integration is covered.

## PR #12: select Windows fibers before CPU backends

https://github.com/edsiper/flb_libco/pull/12

**The Windows dispatch fix from PR #12 is now incorporated in PR #16, adapted
to preserve Emscripten dispatch. Once #16 is merged, #12 is superseded.**

Before this fix, GNU/Clang dispatch selected `amd64.c` or `x86.c` before checking
`_WIN32`. This fix selects fibers before CPU backends on Windows, preserving the
subsequently added Emscripten dispatch as the first choice.

However, `settings.h` already defines `LIBCO_MPROTECT` on Windows, and both
assembly backends call `VirtualProtect(..., PAGE_EXECUTE_READ, ...)` during
initialization. Thus a read-only code array does not by itself establish the
claimed first-switch DEP crash. Neither backend checks `VirtualProtect`'s return
value, so an actual protection failure remains possible. MSVC x64 already uses
fibers, but MSVC x86 still uses `x86.c`; the PR only changes the GNU/Clang branch.
It therefore does not make *every* Windows compiler/architecture use fibers.

The new Windows CI jobs execute the same runtime suite against automatic
selection and an explicitly built fiber backend, with MSVC and MinGW GCC/Clang in Debug
and Release. They can establish whether switching fails with a current native
toolchain. The Wine results below are supplementary and do not replace the reported
Fluent Bit workload on native Windows.

### Reproduction evidence

Using Ubuntu 24.04's MinGW-w64 GCC 13 (win32 thread model), Release, and Wine 9:

- `co-runtime` fails with `EXCEPTION_ACCESS_VIOLATION` (`0xc0000005`).
- `co-runtime-fiber` passes with the same compiler and runtime.
- The fault is at `co_swap_function+0x27`, instruction
  `movaps %xmm6,0x50(%rdx)`. The logged `rdx` is `0x00007ffffe8922b8`:
  the destination is 8 modulo 16, violating `movaps` alignment requirements.
- A temporary copy with Windows dispatched to fibers before CPU checks passes
  both Debug and Release (automatic selection and explicit fibers, 4 tests).
  The same selection change is now applied in `libco.c`.
- The failing instruction is inside executable swap code, so this particular
  failure is not an instruction-fetch DEP violation.
- `amd64.c` declares the primary TLS context as a `long long[64]` without an
  explicit 16-byte alignment requirement; the MinGW binary uses emulated TLS.

The [initial hosted run](https://github.com/edsiper/flb_libco/actions/runs/35651560349)
passed 38 of 39 jobs. UCRT64 Debug built successfully, then `co-runtime`
segfaulted while `co-runtime-fiber` passed. The push run reproduced that same
failure. This confirms a native Windows failure in automatic assembly selection;
the hosted CTest log does not contain an instruction-level diagnosis.

The fix selects fibers for GNU/Clang Windows builds. MSVC dispatch is unchanged.
No failing checks are disabled or marked as allowed failures.

## Local CI validation

- GCC and Clang x86-64: Debug and Release, all three backends pass (12 tests).
- GCC/QEMU: i686, ARM hard-float, AArch64, RISC-V64, PPC32, PPC64 big-endian,
  PPC64 little-endian, Debug and Release, all pass (44 tests including the
  RISC-V stack regression).
- Emscripten 6.0.9 / Node: Debug and Release pass (4 tests each); ASan passes
  (6 tests, including expected heap/stack overflow diagnostics). ASan CI enables
  memory growth to accommodate sanitizer overhead.
- `LIBCO_TESTS=OFF` builds; `LIBCO_TESTS_PORTABLE=OFF` builds and runs only the
  automatic backend's runtime test.
- `actionlint` 1.7.12 and `git diff --check` pass.
- Initial hosted CI: all Linux, macOS, FreeBSD, WebAssembly, and nine of ten
  Windows jobs passed; UCRT64 Debug exposed the backend bug described above.

## Worker reuse test synchronization

The next hosted run passed all ten Windows jobs but exposed an existing race in
`co-wasm-worker-reuse` in Debug and Release. `pthread_join` requests worker cleanup
through a message to the JavaScript main thread; it does not wait for that worker
to be returned to Emscripten's pool. An immediate `pthread_create` can allocate a
new Node worker, causing the marker assertion to fail before reuse is exercised.

The test now waits, with a five-second deadline, for the pool's single spare
worker after each join. It retains the marker and fiber-state checks. This uses
the existing two-worker pool and the already pinned SDK; strict pool size alone
would not fix this because Emscripten ignores that setting in Node. CI repeats
the reuse test 20 times in each WebAssembly configuration.
