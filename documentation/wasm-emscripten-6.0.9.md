# Emscripten 6.0.9 migration

Validated on Linux on 2026-09-08 using the official Emscripten 6.0.9 SDK,
its bundled Node 24.19.0, Chromium 151, and Valgrind 3.23.0.
This remains an experimental browser port, not cross-browser production certification.

## Implementation

- `.emscripten-version` is the browser toolchain pin. CMake rejects incompatible
  SDKs before downloading/building dependencies; libco also checks compiler macros.
- The SDK declares its incoming Module API, including `mainScriptUrlOrBlob`,
  which newer Emscripten releases no longer include by default.
- Monkey uses the public non-suspending `poll(..., 0)` syscall and blocks on
  Emscripten's readiness queues until I/O or the next worker-owned timer.
  Direct FS stream inspection and periodic 10 ms wakeups were removed.
- Timer ownership, coalescing, and the no-thread-per-timer behavior are retained.
  A new Fluent Bit regression exercises waits inside a libco fiber and pthread
  wakeup/return. Monkey's standalone test also covers cross-thread wakeups.
- The libco lifecycle, pthread return/reuse, and ASan stack-transition shims
  remain necessary in 6.0.9. They were not removed just to relax the version pin.
- ChunkIO keeps its `mremap` fallback and physical `nftw` deletion. The bundled
  tree includes the upstream draft's memory-only scan-signature and fixture fixes.
- Demo and test defaults select `build-wasm-6.0.9-release`. Versioned build trees
  preserve the older SDK/artifacts and avoid mixing incompatible object files.
- `.github/workflows/wasm-browser.yaml` adds optimized and ASan build/CTest jobs,
  using the version pin and a fixed emsdk bootstrap revision. Its YAML and shell
  syntax were checked locally; this new Fluent Bit workflow has not run remotely.

Upstream dependency drafts remain separate, with DCO-signed follow-up commits:
[ChunkIO #116](https://github.com/fluent/chunkio/pull/116),
[Monkey #448](https://github.com/monkey/monkey/pull/448), and
[flb_libco #14](https://github.com/edsiper/flb_libco/pull/14).
Fluent Bit's integration changes have not been committed or submitted as a PR.

## Feature choices

The shared poll backend already uses the new upstream readiness queues, so
switching to epoll would not remove the need for a browser timer adapter.
JSPI does not replace the current Asyncify fiber API. Experimental cross-origin
Wasm caching is not enabled: the SDK already streams compilation and needs its
existing cancellation/progress behavior. IDBFS auto-persistence is not enabled:
explicit quiescent checkpoints retain their existing failure/retry semantics.
Node-only raw sockets do not apply to the browser profile; HTTP still uses Fetch.

## Verification

| Check | Result |
| --- | --- |
| Optimized full-engine CTest | 15/15 passed |
| Full-engine WASM ASan CTest | 17/17 passed |
| Chromium SDK and full editable demo suites | Passed, optimized and ASan |
| Chromium fiber/event integration | Passed, optimized and ASan |
| Certificate-warning and trusted-certificate demo | Passed, optimized and ASan |
| SDK Node contract tests / Python sanitizer-output tests | Passed |
| Native engine/scheduler CTest | 2/2 passed |
| Native Fluent Bit stdout/HTTP integration, normal / strict Valgrind | 34/34 passed in each run |
| Standalone libco, optimized / ASan | 2/2 and 4/4 passed |
| Standalone Monkey, optimized / ASan | 1/1 and 1/1 passed |
| Standalone ChunkIO filesystem, optimized / ASan | 6/6 and 6/6 passed |
| Standalone ChunkIO memory-only | 2/2 passed |
| Native Monkey HTTP integration, normal / strict Valgrind | 34/34 passed in each run |
| Real 5.0.7 configure rejection | Passed; clear 6.0.9-required error |

Build commands (activate the new SDK first):

```sh
emcmake cmake -S . -B build-wasm-6.0.9-release -DFLB_WASM_BROWSER=ON \
  -DFLB_DEBUG=OFF -DFLB_RELEASE=OFF -DCMAKE_BUILD_TYPE=MinSizeRel
cmake --build build-wasm-6.0.9-release -j8
ctest --test-dir build-wasm-6.0.9-release --output-on-failure
emcmake cmake -S . -B build-wasm-6.0.9-asan -DFLB_WASM_BROWSER=ON \
  -DFLB_DEBUG=OFF -DFLB_RELEASE=OFF -DCMAKE_BUILD_TYPE=MinSizeRel \
  -DLIBCO_TESTS_ASAN=ON -DCMAKE_C_FLAGS=-fsanitize=address \
  '-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address -sALLOW_MEMORY_GROWTH=1'
cmake --build build-wasm-6.0.9-asan -j8
ctest --test-dir build-wasm-6.0.9-asan --output-on-failure
```

Exact browser commands used (repeat with `build-wasm-6.0.9-asan`):

```sh
/tmp/flb-wasm-browser-venv/bin/python tests/wasm/sdk_test.py --build-dir build-wasm-6.0.9-release --browser /home/edsiper/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome
/tmp/flb-wasm-browser-venv/bin/python tests/wasm/browser_page_test.py --build-dir build-wasm-6.0.9-release --browser /home/edsiper/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome
/tmp/flb-wasm-browser-venv/bin/python tests/wasm/browser_smoke.py --build-dir build-wasm-6.0.9-release --target flb-wasm-event-fiber --browser /home/edsiper/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome
/tmp/flb-wasm-browser-venv/bin/python tests/wasm/browser_page_test.py --build-dir build-wasm-6.0.9-release --browser /home/edsiper/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome --certificate-only
```

Native compatibility checks use Valgrind on Linux, since Valgrind cannot
instrument browser WebAssembly; the WASM checks use AddressSanitizer instead.
Native generated headers are restored by reconfiguring the native build after
WASM compilation. Do not compile native and WASM targets concurrently in this
source tree, which still has source-tree generated headers.

```sh
cmake -S . -B build -DFLB_TESTS_RUNTIME=On -DFLB_TESTS_INTERNAL=On
cmake --build build -j8
ctest --test-dir build -R '^flb-(it-scheduler|rt-core_engine)$' --output-on-failure
tests/integration/.venv/bin/python -m pytest tests/integration/scenarios/out_stdout/tests/test_out_stdout_001.py tests/integration/scenarios/out_http -q
VALGRIND=1 VALGRIND_STRICT=1 tests/integration/.venv/bin/python -m pytest tests/integration/scenarios/out_stdout/tests/test_out_stdout_001.py tests/integration/scenarios/out_http -q
```

## Startup measurements

Three fresh Chromium processes per case, caching disabled, no compression:

| Condition | Median click-to-running | Median engine phase |
| --- | ---: | ---: |
| Local HTTPS | 129.640 ms | 32.890 ms |
| 20 Mbps, 40 ms latency | 3888.335 ms | 31.705 ms |

The optimized SDK WASM is 8,322,585 bytes. The results confirm working cold
startup, not a general speedup or a guarantee on mobile devices. Removing idle
poll wakeups does not remove network transfer or initial compilation costs.

```sh
/tmp/flb-wasm-browser-venv/bin/python tests/wasm/startup_benchmark.py --build-dir build-wasm-6.0.9-release --browser /home/edsiper/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome --runs 3
/tmp/flb-wasm-browser-venv/bin/python tests/wasm/startup_benchmark.py --build-dir build-wasm-6.0.9-release --browser /home/edsiper/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome --runs 3 --download-mbps 20 --latency-ms 40
```

## Remaining release gates

- Chrome 151 startup worker retention reproduced despite sequential bootstrap.
  Failure cleanup now requests cooperative child shutdown before terminating
  the parent, with a bounded fallback for unavailable children. The prepared
  worker pool is still reused. `sdk_test.py --pthread-only` repeats faults at
  the first and fourth workers three times in both optimized and ASan builds.
  Script startup is serialized; the historical startup timings above predate
  this change.
- Optional ASan `detect_stack_use_after_return=1` still aborts during `munmap`
  cleanup. Reproduced both with libco and a pthread-only program without libco
  or Asyncify on 6.0.9. Default ASan heap/stack checks and intentional fault
  diagnostics pass; no sanitizer checks were disabled to obtain those passes.
- Firefox/WebKit, mobile devices, and production CSP/bundler qualification
  remain outside this Chromium-based validation. The package remains private.

Local run logs and benchmark JSON are under `/tmp/flb609-*`. No generated
integration results, build artifacts, TLS keys, or virtual environments are
included in the upstream commits.
