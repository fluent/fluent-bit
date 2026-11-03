# Browser WASM review: 2026-10-23

The remote PR and this review use Emscripten 6.0.9. The local 6.0.11 migration
was never completed: the bundled libco backend explicitly rejects versions
other than 6.0.9, and neither 6.0.11 build passed that guard.

## Toolchain recommendation

Qualify Emscripten **6.0.13**, released 2026-10-19, rather than completing the
older 6.0.11 migration. It is the current stable SDK; 6.0.14 is in development.
The supported pin remains 6.0.9 until the libco guard and the complete optimized
and ASan test matrix have been updated together.

- 6.0.10 fixes runtime keepalive accounting when cancelling a pending timeout.
- 6.0.11 removes `FS.findObject`; 6.0.13 removes `FS.filesystems`.
  Fluent Bit's browser glue uses neither removed API; storage mounts `IDBFS`
  directly and uses explicit `FS.syncfs` checkpoints.
- 6.0.12 adds experimental main-thread epoll listeners. They do not replace the
  current poll/fiber backend or require a migration for this threaded SDK.
- The 6.0.13 pthread load/loaded command IDs remain 1/3, and workers still use
  the `em-pthread` name. Reading those internals is not runtime qualification.
- The upstream Asyncify/fiber code still does not justify removing Fluent Bit's
  libco compatibility shims. Rebuild all object files and dependencies on upgrade.

Sources: [release](https://github.com/emscripten-core/emscripten/releases/tag/6.0.13),
[changelog](https://github.com/emscripten-core/emscripten/blob/6.0.13/ChangeLog.md).

## Corrections and dependency refresh

Master now records rejected HTTP header setters in an `invalid_header` flag.
The browser adapters bypassed the native execution checks, allowing requests
with rejected fields to proceed with those fields omitted. Both legacy and NG
Fetch entry points now reject that flag. The regression test ignores a rejected
setter, adds a valid field, and verifies that neither API invokes Fetch.

The browser-only external OpenSSL build moves from 3.5.8 to **3.5.9** with its
published SHA-256 digest. This is a security patch release; the browser build
uses its crypto library, while browser Fetch supplies TLS. Bundled `lib/`
sources are unchanged. [OpenSSL release](https://github.com/openssl/openssl/releases/tag/openssl-3.5.9).

Lua 5.4.9 remains the final 5.4 release. Lua 5.5.1 is available but changes the
language/ABI and is a separate migration. Libyaml 0.2.5 remains the latest stable
release; 0.2.6-rc.1 is a prerelease.

## CI artifacts

The Browser WebAssembly workflow runs for every branch push, every pull request
update and manual dispatch. The optimized job packages the complete SDK after
its build, CTests and SDK unit tests pass, before browser validation. The artifact includes source/build commit IDs, the toolchain pin,
per-file checksums, and an archive checksum. It is retained for 30 days and is
explicitly experimental. Browser results and the ASan job remain separate validation gates; an available
artifact does not certify either passed.

## Remaining limitation

The previous pushed head's ASan job failed the delayed pthread-handshake case:
Playwright observed the SDK worker after the five-second teardown deadline,
despite prior repeated local passes. Keep that assertion and investigate any
recurrence; a passing optimized artifact is not evidence that ASan teardown or
production release gates have all passed.
[Previous failure](https://github.com/fluent/fluent-bit/actions/runs/36762866867/job/110049583377).

The rebased head `b2bddb61f` reproduced worker retention in the optimized hosted
SDK suite's missing-WASM failure case. A local test of the extracted artifact
also stalled during that negative path and was terminated after more than three
minutes; the regular optimized and ASan SDK suites passed locally. This is an
intermittent worker-lifecycle blocker, not a clean production validation result.
[Rebased-head failure](https://github.com/fluent/fluent-bit/actions/runs/39985931882/job/120524981380).

## Verification

Linux, Emscripten 6.0.9, Node 24.19.0 and Chromium 151:

- Fresh optimized build: 17/17 CTests passed.
- Fresh AddressSanitizer build: 19/19 CTests passed.
- SDK, full HTTPS page and pthread startup-fault suites passed in both builds.
  The fault scripts each run three rounds: 54 fault cases total for this review.
- The header regression fails without the adapter fix and passes with it.
- 23 Node SDK tests and 15 Python browser-harness tests passed.
- actionlint 1.7.12 passed; the exact workflow packaging script ran locally,
  archive/per-file checksums verified, and the extracted SDK passed a separate
  create/start/push/stats/stop/destroy and worker-cleanup smoke test.

Commands run from the WASM worktree (both build directories were configured
with `MinSizeRel`, `FLB_WASM_BROWSER=ON`, `FLB_DEBUG=OFF`, `FLB_RELEASE=OFF`;
the ASan build additionally used `LIBCO_TESTS_ASAN=ON`,
`CMAKE_C_FLAGS=-fsanitize=address` and
`CMAKE_EXE_LINKER_FLAGS=-fsanitize=address -sALLOW_MEMORY_GROWTH=1`):

```sh
for variant in release asan; do
  build_dir="/tmp/flb-wasm-review-20261023-$variant"
  ctest --test-dir "$build_dir" --output-on-failure
  browser-venv/bin/python tests/wasm/sdk_test.py --build-dir "$build_dir" --browser /home/edsiper/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome
  browser-venv/bin/python tests/wasm/browser_page_test.py --build-dir "$build_dir" --browser /home/edsiper/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome
  browser-venv/bin/python tests/wasm/sdk_test.py --build-dir "$build_dir" --browser /home/edsiper/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome --pthread-only
done
node --test tests/wasm/sdk_unit_test.mjs tests/wasm/sdk_worker_unit_test.mjs
browser-venv/bin/python -m unittest discover -s tests/wasm -p '*_test.py'
browser-venv/bin/python -m unittest discover -s tests/wasm -p 'test_*.py'
/tmp/flb-wasm-actionlint/actionlint .github/workflows/wasm-browser.yaml
```

Valgrind: **not run** for this update. The changed C adapter is compiled only
for Emscripten and executes inside the browser WASM runtime; the native Python
integration runner and Valgrind cannot exercise that adapter. The same focused
browser integration suites ran with AddressSanitizer/LeakSanitizer checks instead.
No new sanitizer diagnostics were reported. Native paths were unchanged.
