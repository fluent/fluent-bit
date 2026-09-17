# Browser WebAssembly port

Status: experimental worker engine with YAML, browser-local storage, Lua and HTTPS output. The C core and selected
plugins compile to WebAssembly. A real Chromium/Node test exercises
`lib -> modify -> grep -> two lib outputs`, all-drop chunks, and repeated
startup/shutdown. An experimental asynchronous JavaScript SDK now provides
engine lifecycle, JSON log ingestion, configuration assets and stdout callbacks.
The lower-level pipeline test remains a C program running in browser workers.

The supported toolchain is now Emscripten 6.0.9. See the
[migration and verification record](wasm-emscripten-6.0.9.md) for adopted SDK
features, current startup measurements, and remaining release gates.

`FLB_WASM_BROWSER=ON` selects this profile. The existing `FLB_WASM` option
embeds WAMR inside native Fluent Bit and is disabled here.

## Embeddable JavaScript SDK

Build `fluent-bit-runtime` using the optimized configuration below. Deploy the
complete `build-wasm-6.0.9-release/sdk/browser/` directory together on your application
origin. Import `createFluentBit` from `fluent-bit.js`; generated Emscripten exports
and worker messages are private implementation details.

The [SDK guide](../sdk/browser/README.md) documents the API, TypeScript types,
HTTPS/isolation headers, lifecycle, bounded queues, deadlines, persistent-storage
ownership, and remaining release gates. The package is private and experimental;
it has not been published or qualified across all browsers and mobile devices.

The editable demo now consumes this same SDK. Stop retains the initialized
runtime for subsequent starts; **Release runtime** destroys its workers and
memory. The first start downloads/initializes the runtime, while later starts
reuse it. YAML configuration changes still require stop/start.

The previous Emscripten 5.0.7 SDK WASM was 8,324,033 bytes. Three fresh Chromium processes measured
median click-to-running startup of 106.505 ms on local HTTPS and 3666.790 ms at
20 Mbps with 40 ms latency, without caching/compression. Engine startup was about
36–38 ms. These SDK measurements supersede the historical demo figures below;
they do not characterize mobile devices or large-scale deployment.

With Emscripten 6.0.9 and Chromium 151, the current SDK WASM is 8,322,585 bytes.
Three fresh-process samples measured median click-to-running of 129.640 ms on
local HTTPS and 3888.335 ms at 20 Mbps/40 ms latency, with no caching or compression.
Median engine phases were 32.890 ms and 31.705 ms respectively. These measurements
do not demonstrate a general startup speedup; the event-loop change removes
periodic idle wakeups and private filesystem access, not network download cost.

Focused verification (replace the Python/browser paths for your environment):

```sh
node --test tests/wasm/sdk_unit_test.mjs
tsc --noEmit --strict --target ES2022 --module NodeNext --moduleResolution NodeNext --lib ES2022,DOM tests/wasm/sdk_types_test.mts
python3 tests/wasm/sdk_test.py --build-dir build-wasm-6.0.9-release --browser /path/to/chromium
python3 tests/wasm/browser_page_test.py --build-dir build-wasm-6.0.9-release --browser /path/to/chromium
python3 tests/wasm/sdk_test.py --build-dir build-wasm-6.0.9-asan --browser /path/to/chromium
python3 tests/wasm/browser_page_test.py --build-dir build-wasm-6.0.9-asan --browser /path/to/chromium
```

The SDK tests cover lifecycle reuse, JSON ingestion, invalid configuration,
isolated instances, exclusive storage ownership, persisted backlog recovery,
missing runtime assets and worker cleanup. Contract tests cover queue limits,
cancellation, deadlines, callback failures and malformed worker responses.
The consumer type check passes with TypeScript 5.9.3, including negative cases.
Emscripten 6.0.9 Release CTest passes 15 tests; ASan CTest passes 17 tests. Both browser suites
pass in optimized and ASan builds, including graceful runtime exit for leak checks.

Native stdout/HTTP regression checks also pass all 34 cases normally and under
strict Valgrind:

```sh
tests/integration/.venv/bin/python -m pytest tests/integration/scenarios/out_stdout/tests/test_out_stdout_001.py tests/integration/scenarios/out_http -q
VALGRIND=1 VALGRIND_STRICT=1 tests/integration/.venv/bin/python -m pytest tests/integration/scenarios/out_stdout/tests/test_out_stdout_001.py tests/integration/scenarios/out_http -q
```

## Build and run

Activate Emscripten **6.0.9** first, as pinned in `.emscripten-version`.
Configuration rejects other versions before building dependencies. The
experimental libco backend still requires SDK-specific compatibility shims.
Install 6.0.9 in a separate emsdk checkout when preserving an older toolchain:

```sh
./emsdk install 6.0.9
./emsdk activate 6.0.9
source ./emsdk_env.sh
```

Use new build directories when upgrading: Emscripten does not guarantee ABI
compatibility across releases. Rebuild OpenSSL, libyaml, Lua and all bundled
libraries with the new SDK; do not reuse 5.0.7 object files or CMake caches.
CMake, Make, Perl, Flex, Bison and Node are also needed.

```sh
emcmake cmake -S . -B build-wasm -DFLB_WASM_BROWSER=ON
cmake --build build-wasm --target flb-wasm-dependencies co-wasm-test \
  flb-wasm-events flb-wasm-pipeline -j8
ctest --test-dir build-wasm -R 'flb-wasm-|co-wasm-test' --output-on-failure
```

Artifacts are paired `.js` and `.wasm` files under `build-wasm/bin/`.
The pipeline target links Fluent Bit's static library and registered plugins.
The legacy shared HTTP client selects Fetch for browser builds. `out_http` and
`out_loki` use their original plugin source, without browser-specific branches.
For older build caches, explicitly add `-DFLB_OUT_HTTP=ON -DFLB_OUT_LOKI=ON`.

Crypto primitives still require OpenSSL with native TLS disabled. The build
downloads SHA-256-pinned OpenSSL 3.5.8, cross-compiles its static crypto library,
and installs it in the build directory. No host OpenSSL is linked, and no
OpenSSL sources are added to `lib/`. Initial builds need network access;
subsequent builds reuse the downloaded source.

YAML configuration is enabled by default. The build also downloads SHA-256-pinned
libyaml 0.2.5 and cross-compiles it; host libyaml is never linked. On an existing
browser build cache created before YAML support, configure with
`-DFLB_CONFIG_YAML=ON`. Build the new acceptance targets with:

```sh
cmake --build build-wasm --target flb-wasm-yaml flb-wasm-storage flb-wasm-demo flb-wasm-lua -j8
```

### Optimized startup build

The development build enables `FLB_DEBUG`, which overrides CMake's build type.
For a size-optimized browser build, explicitly disable both Fluent Bit build-mode
overrides and use `MinSizeRel`:

```sh
emcmake cmake -S . -B build-wasm-6.0.9-release -DFLB_WASM_BROWSER=ON \
  -DFLB_DEBUG=OFF -DFLB_RELEASE=OFF -DCMAKE_BUILD_TYPE=MinSizeRel
cmake --build build-wasm-6.0.9-release -j8
ctest --test-dir build-wasm-6.0.9-release --output-on-failure
python3 tests/wasm/browser_server.py --build-dir build-wasm-6.0.9-release \
  --host 0.0.0.0 --port 8443 --http-port 8088
```

Stop an existing server on those ports before starting this one. Keep the debug
build separately for diagnostics. The optimized build retains all browser-profile
plugins and the test binaries' Emscripten runtime assertions and stack checks.

The page now reports preflight, module/runtime setup and engine-start timing in
the output pane. SDK engine timing covers configuration and `flb_start` on the
C command thread; click-to-running also includes worker dispatch.
Use a fresh browser process for every sample and disable HTTP caching:

```sh
python3 tests/wasm/startup_benchmark.py --build-dir build-wasm-6.0.9-release \
  --browser /path/to/chromium --runs 3
python3 tests/wasm/startup_benchmark.py --build-dir build-wasm-6.0.9-release \
  --browser /path/to/chromium --runs 3 --download-mbps 20 --latency-ms 40
```

The script needs Playwright and uses a temporary HTTPS certificate pinned only
in its test browser. It measures the standard editable dummy/processor/stdout
demo from the Start click to the engine's running notification, and verifies
clean Stop. Page navigation and initial editor loading are excluded. The
development server still uses `Cache-Control: no-store` and does not compress
assets, so these measurements do not depend on warm HTTP caching or gzip.

Measured on the development host with Chromium, three fresh-process samples per
case. These are historical pre-SDK demo measurements. The Debug baseline predates
the fiber fix; MinSizeRel was remeasured after the final fix with builds and other
browser tests finished:

| Measurement | Debug | MinSizeRel |
| --- | ---: | ---: |
| Demo WASM bytes | 40,582,959 | 8,322,482 |
| Cold startup, local HTTPS | about 1.3 s | about 0.13 s |
| Cold startup, 20 Mbps / 40 ms latency | 17.99 s | 3.76 s |

Final optimized medians were 132.355 ms locally and 3758.760 ms with the network
limit. The engine phase took about 40 ms; most throttled startup time was spent
loading the module/runtime, not switching fibers.

The pre-SDK optimized build passed all 13 WASM CTests and the full Chromium page suite
(HTTP/Loki/OTLP, Lua, editable pipelines, processors, storage and shutdown).
Startup includes real C-engine readiness, not just the module-loaded event.
These are development-host measurements, not a guarantee for other devices or
networks. The subsequent libco fix resolves the fiber stack-limit ordering
failure without disabling instrumentation; current sanitizer results and
remaining limitations are listed under "Memory checks and unresolved blockers".

## Manual HTML test page

From the repository root, start the local HTTPS server (Python standard library
plus OpenSSL for automatic development certificate generation):

```sh
python3 tests/wasm/browser_server.py --build-dir build-wasm
```

Open **https://127.0.0.1:8443/**. Plain HTTP on **http://127.0.0.1:8088/**
redirects to HTTPS, preserving the path and query. The page provides browser readiness checks,
an editable YAML playground, buttons for the YAML and filter pipelines, a storage reload test, and live logs
with explicit pass/fail results. It supplies the COOP/COEP headers needed for
workers; opening the HTML through `file://` will not work. Use `--port` for the
HTTPS port and `--http-port` for the separate redirect port if either is busy.
Only the test page assets and named WASM binaries are served,
not the entire source or build tree. No Python packages are needed to serve it.

To listen on all IPv4 interfaces, explicitly opt in:

```sh
python3 tests/wasm/browser_server.py --build-dir build-wasm --host 0.0.0.0 \
  --cert-host 192.168.20.171
```

Replace the example IP with this server's address; repeat `--cert-host` for other
IPs or DNS names clients will use. Use that address, not `0.0.0.0`, in the browser.
`localhost` and `127.0.0.1` are included automatically. Unrecognized HTTP Host
headers are rejected rather than redirected to an arbitrary destination.
Only expose this development server on a trusted network. The default bind
address remains `127.0.0.1`.

Without `--cert`/`--key`, startup generates and reuses a self-signed certificate
under `<build-dir>/.browser-tls/<host-set>/`, with a private key readable only
by its owner. Certificates are valid for one year; keys are never silently
overwritten. A new set of certificate hosts gets a separate certificate.
Chrome's certificate-warning exception is insufficient for direct nested pthread
script requests: the page and top-level SDK worker can load while pthread scripts
fail. The editable demo uses `demo-sdk-worker.js` to fetch the two same-origin
JavaScript assets and create in-memory blob modules for its nested workers.
This avoids additional nested-worker HTTPS script requests. It does not install
certificates, disable TLS validation, or bypass the initial browser warning.
Blob URLs are owned by the demo worker and explicitly revoked on graceful
destruction or adapter initialization failure. A custom demo CSP must permit
blob workers and blob module scripts; no policy is relaxed automatically.
The certificate-warning regression and editable startup suite pass in optimized
and ASan builds. The SDK also bootstraps pthread scripts sequentially before
creating the runtime, then reuses those workers. Sequential startup alone proved
insufficient in later fault runs. Failure cleanup now requests cooperative child
shutdown before parent termination, with a bounded fallback for unavailable
children. Repeated direct-loader failures on the first and fourth workers pass
cleanup checks in optimized and ASan builds under Chrome 151. This is independent
of the demo's certificate adapter.

The normal SDK still uses URL-backed assets and should be deployed with a
normally trusted HTTPS certificate. The fixed C acceptance-test buttons retain
their original loader; this development adapter applies to the editable SDK demo.

The regression first reproduces the direct-loader rejection, then verifies the
demo's startup, reuse and destruction after clicking through the warning, and
finally checks the trusted-certificate path. It does not change an OS trust store:

```sh
python3 tests/wasm/browser_page_test.py --build-dir build-wasm-6.0.9-release --browser /path/to/chrome --certificate-only
python3 tests/wasm/browser_page_test.py --build-dir build-wasm-6.0.9-asan --browser /path/to/chrome --certificate-only
```

The certificate path is printed at startup. **No system or browser trust store
is modified.** A trusted certificate remains preferable, and is required for
the unadapted SDK loader. Supply a certificate clients already trust with:

```sh
python3 tests/wasm/browser_server.py --host 0.0.0.0 \
  --cert /path/to/server-cert.pem --key /path/to/server-key.pem \
  --cert-host your-development-host.example
```

The supplied certificate must cover the client-facing hostnames/IPs. The server
requires TLS 1.2 or later and never falls back to serving the page over HTTP.
The HTTP listener only issues redirects, not test assets. A self-signed
certificate can trigger a browser warning until trusted; HTTPS alone does not
install trust. Never commit or share the private key. Moving from HTTP to HTTPS
also changes the IndexedDB origin; data from the old HTTP origin is not migrated.

The storage button loads fresh test frames for write, restore/delete, and
empty verification, committing IndexedDB before moving to the next phase. It
also checks commit failure/retry. An interrupted cycle can leave a test chunk;
use **Recover & delete interrupted test chunk** to recover and remove only
`/storage/chunkio-regression`. Use one test tab at a time. Keep the same origin
(hostname and port) when recovering data left by an earlier run.

### Editable pipeline playground

The default example runs `dummy -> content_modifier -> SQL -> stdout`.
It generates one record per second, adds `runtime: browser`, keeps records
whose `level` is `info`, and displays JSON lines beside the editor.

1. Edit the YAML (for example, change the dummy message, processor value, or SQL condition).
2. Choose an automatic-stop duration and press **Start demo**.
3. Watch stdout and engine diagnostics in **Live output**.
4. Press **Stop**, or wait for the duration to expire. Then edit and start again.
   **Reset example** restores the supplied configuration.

Config edits do not require recompilation. YAML is sent directly to a fresh
browser runtime, written to its temporary `/demo.yaml`, and loaded by the C
configuration parser. It is not uploaded to the server or saved across page
reloads. Each run gets an ephemeral filesystem, even if YAML requests filesystem
storage; only the dedicated storage test checkpoints IndexedDB. This editor does
not upload additional parser/include/data files.

The maximum configuration size is 64 KiB of UTF-8 and the duration is 1–300
whole seconds. Stop signals an atomic flag; engine shutdown and worker joins
stay on the C worker. The demo overrides `service.grace` to one second, then
destroys the engine and its frame. A shutdown watchdog reports failure if that
does not complete within 15 seconds; startup has a 45-second watchdog.
Config changes apply on the next Start, not to an already running pipeline.
Malformed YAML and unavailable plugins appear as failures in the output, and
the editor remains available for correction and retry.

Only compiled browser-profile plugins are available. HTTPS output is supported,
but raw TCP/UDP outputs and TDA are not; use `threaded: false` with `event_type`. The `dummy` input runs
until Stop/automatic stop unless its `samples` setting limits record generation
(that setting alone does not stop the engine).

### HTTPS output from the browser

Press **Load HTTPS example**, then **Start demo**. It runs
`dummy -> content_modifier -> http + stdout`. The **HTTPS receiver** panel
shows requests actually received by the local development server; **Live output**
shows stdout and HTTP status/retry diagnostics. Edit the YAML to change the
payload, processors, format, headers or destination. Restart the Python server
after updating its code so the new receiver routes are registered.

```yaml
pipeline:
  outputs:
    - name: http
      match: '*'
      browser.url: https://collector.example/ingest
      format: json_lines
      http.response_timeout: 5s
      retry_limit: 3
```

`browser.url` is now an optional **shared output property**, not an HTTP-plugin
property. It overrides the complete HTTPS destination, including path and query.
Without it, the shared client uses the plugin's normal `host`, `port` and request
URI; browser transport always uses HTTPS. Set `port: 443` for an ordinary HTTPS
collector. `tls: on` is accepted; disabling TLS or overriding the browser's
certificate verification is unsupported. The browser performs TLS validation.
For a different origin, the receiving
server must allow the page's origin, method and headers through CORS, including
the preflight. Same-origin delivery needs no extra CORS setup. The local demo
receiver accepts same-origin requests only by default.

The shared client supports GET/HEAD/POST/PUT/PATCH/DELETE (no bodies on GET/HEAD).
The unchanged HTTP output supports POST/PUT, existing JSON/MessagePack serialization,
gzip/snappy/zstd compression, basic authentication and explicit custom headers.
Fetch omits ambient cookies/credentials and rejects redirects. Browser-controlled
headers (including Host, Cookie and Content-Length) are rejected; Fetch may
combine duplicate headers. The legacy client's generated Host/Content-Length/
Connection headers are not emitted; existing User-Agent headers are ignored in
favor of the browser's value. Never embed production secrets in a public demo page.
Per-record `body_key`/`headers_key` now follow the unchanged HTTP plugin path.
OAuth2 token acquisition, proxies, read-idle
timeouts and output workers are unsupported. Keep `workers: 0` (the browser
default); explicit response timeouts are bounded to 1–120 seconds. An unset or
zero client timeout selects a 30-second default; a smaller positive `net.io_timeout`
also limits the request. Separate connect/read-idle deadlines are not emulated.

The bridge bounds requests to 8 MiB, response bodies to 64 KiB, headers to 128 pairs /
64 KiB, and outstanding requests to 32. The existing client's response-buffer
limit also applies (including synthesized headers and the terminating NUL).
Fetch owns copies of the C payload and headers before the output coroutine yields.
During Stop, requests may complete within the engine's grace period. At actual
teardown the core cancels outstanding requests, removes their timers and resumes
the suspended plugin callbacks so they release their own serialized/compressed
buffers, HTTP clients and connection contexts. There are no asynchronous callbacks
into freed C buffers. Routing and retry scheduling remain in the C engine, and
status classification stays in each plugin. For `out_http`, 200–205 succeeds, 4xx except 408/429
is a permanent error, and other statuses or transport failures retry. A clean
demo shutdown is **not proof that all records were delivered**; check the
receiver and diagnostics. The playground is ephemeral and Stop can discard
pending retries after its one-second grace period.

The development receiver is a test fixture, not a production collector: it
accepts at most 1 MiB per request and retains only the latest 20 request previews
per run (8 KiB each), up to 16 runs. Entries expire after 10 minutes and are
held only in server memory. Authorization values are never captured. The
generated `/collect/<uuid>` URL pairs with `/received/<uuid>` for inspection;
these URLs are not an authentication mechanism. Test query parameters include
`?fail=1` (first attempt returns 503), `?status=400` and `?delay=2`.

Focused browser and transport checks:

```sh
cmake --build build-wasm --target flb-wasm-demo flb-wasm-http flb-wasm-http-lifecycle -j8
ctest --test-dir build-wasm -R '^flb-wasm-http' --output-on-failure
python3 tests/wasm/browser_server_test.py
python3 tests/wasm/browser_page_test.py --build-dir build-wasm --http-only --browser /path/to/chromium
python3 tests/wasm/browser_smoke.py --build-dir build-wasm-6.0.9-asan --target flb-wasm-http --browser /path/to/chromium
```

The standalone bridge test exercises binary ownership, response bounds, invalid
headers, timeouts, concurrency limits and cancellation using a mocked Fetch. It
also uses the unchanged legacy client allocation/header lookup/destruction APIs
to validate response status, binary bodies, headers and response-buffer limits.
`flb-wasm-http-lifecycle` verifies forced shutdown of two pending client calls,
including plugin-side cleanup and removal of both request timers.
The page test uses real HTTPS for JSON/MessagePack delivery, per-record bodies,
503 retry, permanent 400, gzip/PUT/basic auth, allowed/denied cross-origin requests,
timeout and Stop in flight. It also covers unchanged Loki with standard host/
port/URI/TLS settings, an output processor, 204 responses, retries and two-plugin Stop.
The ASan command requires a separately configured/built ASan transport target;
it does not establish full-engine sanitizer coverage.

Native regression commands for the HTTP output change:

```sh
ctest --test-dir build -R '^flb-rt-out_http$' --output-on-failure
tests/integration/.venv/bin/python -m pytest tests/integration/scenarios/out_http/tests/test_out_http_001.py tests/integration/scenarios/out_http/tests/test_out_http_chunked_response_001.py -q
VALGRIND=1 VALGRIND_STRICT=1 tests/integration/.venv/bin/python -m pytest tests/integration/scenarios/out_http/tests/test_out_http_001.py tests/integration/scenarios/out_http/tests/test_out_http_chunked_response_001.py -q
```

In the original HTTP prototype verification, runtime CTest passed 14/15 cases; its `in_http` case could not bind
hard-coded port 8888 because an existing listener occupies it. That listener
was left untouched, and a network-namespace retry was denied by the host
(`unshare: ... /proc/self/uid_map: Operation not permitted`). The integration
scenarios use dynamic ports and are independent of this collision.

Original HTTP prototype verification: both integration commands passed all 20 cases
(149.42 seconds normally, 175.84 seconds with strict Valgrind). All nine WASM
CTests, 12 server tests and the full Chromium page suite passed. The standalone
HTTP bridge passed ASan in both Node and Chromium. The full ASan engine was
rebuilt and retried in Chromium, but failed before execution with
`yyjson_read_opts: local count too large`. This historical compilation blocker
is avoided by the optimized ASan recipe below. Native generated headers were
restored after the WASM builds.

### Shared HTTP transport boundary

Plugins keep their existing calls to `flb_upstream_conn_get()`,
`flb_http_client()`, header/auth helpers, `flb_http_do()` and destruction/release.
In browser builds, upstream connections are socket-free request contexts and
`flb_http_do()` dispatches to Fetch. Native builds keep their socket transport.
No code changes remain under `plugins/out_http`, `plugins/out_loki` or
`plugins/out_opentelemetry` for this port.

The generic `flb_http_client_ng` interface now uses the same Fetch backend:
session creation, request builders/setters, authorization, request execution,
response headers/binary bodies and destruction are available. Shared C code
still owns the request/response objects; browser code owns HTTPS negotiation.
The adapter explicitly maps the different method enums used by the two APIs.
`request_execute_step()` completes one buffered request, yielding the engine
coroutine while Fetch runs; it does not expose partial wire frames.

OpenTelemetry is enabled in the browser profile. Both `http2: off` (legacy
client) and `http2: on` (generic client with automatic negotiation) work for
OTLP/HTTP. For example, paste this into the page's configuration editor and
replace the destination with a CORS-enabled collector:

```yaml
service:
  flush: 1
pipeline:
  inputs:
    - name: dummy
      dummy: '{"message":"Hello from browser OTLP"}'
  outputs:
    - name: opentelemetry
      match: '*'
      host: collector.example
      port: 443
      tls: on
      http2: on
      grpc: off
      logs_uri: /v1/logs
```

Here `http2: on` selects the generic API, not a guarantee of HTTP/2 on the
wire. Its request/response protocol field uses the HTTP/1.1 message model;
Fetch does not expose the negotiated wire version. `http2: force` and
`grpc: on` are rejected, not silently downgraded. Fetch cannot expose the
trailers required by native gRPC. This is a browser platform boundary, not
an OTel-specific transport implementation. See the
[Fetch API definitions](https://fetch.spec.whatwg.org/#fetch-api).

Generic-client verification:

```sh
ctest --test-dir build-wasm --output-on-failure
ctest --test-dir build-wasm-6.0.9-asan -R '^flb-wasm-http(-ng|-ng-objects)?$' --output-on-failure
ctest --test-dir build -j2 -R '^flb-(it-(http_client|http_server|opentelemetry|upstream_tls)|rt-(http_client_chunked|out_loki))$' --output-on-failure
tests/integration/.venv/bin/python -m pytest tests/integration/scenarios/out_http tests/integration/scenarios/out_loki tests/integration/scenarios/out_opentelemetry -q
VALGRIND=1 VALGRIND_STRICT=1 tests/integration/.venv/bin/python -m pytest tests/integration/scenarios/out_http tests/integration/scenarios/out_loki tests/integration/scenarios/out_opentelemetry -q
```

The normal WASM suite passes all 12 tests. Chromium also passes the generic
client and mixed legacy/generic forced-shutdown tests. The page tests exercise
OTLP logs, metrics and traces, both client APIs, output processors, basic auth,
gzip, a 503 retry, a 204 response, Stop with a pending OTel request, and rejection
of unsupported gRPC/forced HTTP/2 configurations. `browser_page_test.py
--otel-only` runs these focused
page checks with the same `--build-dir` and `--browser` options shown above.

ASan passes the shared response test and the generic client object-ownership
test (32 create/destroy cycles, URL parsing, bearer auth and compression).
The libco stack-switch fix also allows the coroutine transport and mixed-client
shutdown tests to pass ASan. This does not establish that every full-engine
shutdown path is leak-free; see the current sanitizer limitations below.

Native regression verification passes all six focused CTests and all 46
HTTP/Loki/OpenTelemetry integration cases normally (241.36 seconds), including
native HTTP/2 and gRPC. All 46 cases also pass with strict Linux Valgrind
(293.44 seconds). The full Chromium page suite passes, and the final rebuilt
artifacts pass the focused generic-client, mixed-client shutdown and OTel page
checks. No output plugin or bundled-library code was changed to add the generic
browser client adapter. Native generated configuration headers are restored.

Shared-transport native verification commands:

```sh
ctest --test-dir build -j2 -R '^flb-(it-(http_client|upstream_tls|config_map)|rt-(http_client_chunked|out_loki|config_map_opts))$' --output-on-failure
tests/integration/.venv/bin/python -m pytest tests/integration/scenarios/out_http tests/integration/scenarios/out_loki -q
VALGRIND=1 VALGRIND_STRICT=1 tests/integration/.venv/bin/python -m pytest tests/integration/scenarios/out_http tests/integration/scenarios/out_loki -q
tests/integration/.venv/bin/python -m pytest tests/integration/test_fluent_bit_manager_startup.py tests/integration/test_macos_leaks_manager.py -q
```

Verification exposed two fixture timing problems: randomized retry backoff could
outlast a 15-second observation window, and the startup helper did not retry
health-check read timeouts under Valgrind. The two HTTP timeout fixtures now
bound retry backoff to 1–2 seconds; the helper retries connection/read timeouts
within its existing startup deadline. Tests cover transient failures, persistent
timeout, early process exit and unexpected exceptions. No production timeout
or retry policy was changed to accommodate these tests.

Earlier legacy-transport verification: 10 WASM CTests, six focused native CTests,
12 server tests and 12 test-helper regressions passed. HTTP/Loki integration
passed all 21 cases normally (132.88 seconds) and with strict Valgrind
(156.82 seconds). The full Chromium page suite passed on rerun, including HTTP,
Loki, Lua, processors, storage and failure recovery. An earlier long browser run
failed during the module HEAD/download precheck with `TypeError: Failed to fetch`;
this was not reproduced in the instrumented rerun and its cause is unconfirmed.
Native generated headers were restored. The live HTTPS server subsequently
switched to the optimized `build-wasm-6.0.9-release` artifacts.

The shared-client and binary-response test passes ASan in Node and Chromium.
The forced-shutdown coroutine test now passes ASan with the libco fix. The
optimized ASan build also avoids the `yyjson_read_opts` local-count limit.
Current full-engine memory-check results are recorded below separately from
these focused transport checks.

The client populates `resp.status`, `resp.payload`, `resp.payload_size` and
response-header lookup. The response buffer is synthesized from the status,
browser-visible headers and decoded body, **not a raw wire capture**. Fetch owns
HTTP framing and decompression; CORS can restrict which response headers are
visible. TLS and connection pooling belong to the browser, too. Upstream gauges
count logical request contexts, not the browser's physical TCP connections.

For example, the existing Loki plugin can be configured directly:

```yaml
pipeline:
  outputs:
    - name: loki
      match: '*'
      host: collector.example
      port: 443
      tls: on
      uri: /loki/api/v1/push
      labels: job=browser
      line_format: json
```

Both complete-request client APIs are adapted. Incremental
`flb_http_do_request()` / response streaming,
HTTP/2 wire control, gRPC trailers, OAuth2 and raw socket protocols are not
implemented. Other HTTP outputs still need build/dependency and protocol tests
before entering the browser allowlist; sharing an API is not proof of browser
compatibility. The adapter reports transport success/failure, not plugin-specific
retry policy. Its sent-byte count represents the body, not browser-managed wire headers.

### Lua scripting in the browser

Press **Load Lua example**, then **Start demo**. The example runs the Lua filter
in an input processor chain, adds the interpreter version, sums an array, and
preserves JSON nulls. Edit the script directly in the YAML `code: |` block.
Traditional `pipeline.filters` Lua configuration is supported too, as are the
three-argument and five-argument (metadata-aware) callbacks.

The browser uses **portable Lua 5.4.9, not LuaJIT**. `FLB_WASM_LUA=ON` is the
browser default; native builds still use `FLB_LUAJIT` and the existing bundled
LuaJIT. The build downloads Lua from lua.org with a pinned SHA-256 into the
build tree and compiles a static interpreter using the same Emscripten/pthread
ABI. No Lua sources are added to or modified under `lib/`.

For a browser cache created before this feature, explicitly enable the filter:

```sh
emcmake cmake -S . -B build-wasm -DFLB_WASM_BROWSER=ON \
  -DFLB_WASM_LUA=ON -DFLB_FILTER_LUA=ON
cmake --build build-wasm --target flb-wasm-demo flb-wasm-lua -j8
```

To omit it, set both `-DFLB_WASM_LUA=OFF -DFLB_FILTER_LUA=OFF`.
LuaJIT itself remains rejected by the browser profile: disabling its JIT still
requires an architecture-specific interpreter that has no WASM backend.

Compatibility limits:

- Lua 5.4 language/library behavior applies, not complete LuaJIT 5.1 compatibility.
  LuaJIT bytecode, `jit`, `ffi`, and LuaJIT's `bit` module are unavailable;
  Lua 5.4 has its own bitwise operators and `table.unpack`.
- No dynamic native modules, host processes, or host filesystem access.
  `script:` and pure-Lua modules can use files provided in the browser virtual
  filesystem, but this playground currently accepts inline code only.
- This is not an untrusted-script sandbox. Run scripts you trust; an infinite
  loop can require the demo's shutdown watchdog to discard the runtime.
- Lua 5.4 signed 64-bit integers are preserved on the MessagePack conversion
  path; unsigned values above `INT64_MAX` are represented as floating point.

The standalone `flb-wasm-lua` target runs the Lua conversion tests, including
64-bit integer boundaries. It passes normally and under WASM ASan in Node and
Chromium. The optimized ASan build also runs the full pipeline; standalone Lua
coverage is not a substitute for sanitizing the complete pipeline.

```sh
ctest --test-dir build-wasm -R flb-wasm-lua --output-on-failure
ctest --test-dir build-wasm-6.0.9-asan -R flb-wasm-lua --output-on-failure
/tmp/flb-wasm-browser-venv/bin/python tests/wasm/browser_smoke.py \
  --build-dir build-wasm-6.0.9-asan --target flb-wasm-lua --browser /path/to/chromium
/tmp/flb-wasm-browser-venv/bin/python tests/wasm/browser_page_test.py \
  --build-dir build-wasm --lua-only --browser /path/to/chromium
```

Native regression verification passes 14 Lua integration cases both normally
and under strict Valgrind, covering filter/processor callbacks and rejected
scripts. These tests also exposed and verify cleanup of initialized input
resources when processor initialization fails, plus Lua VM cleanup when a
callback is missing or top-level script execution fails.

```sh
tests/integration/.venv/bin/python -m pytest tests/integration/scenarios/filter_lua/tests/test_filter_lua_001.py -q
VALGRIND=1 VALGRIND_STRICT=1 tests/integration/.venv/bin/python -m pytest tests/integration/scenarios/filter_lua/tests/test_filter_lua_001.py -q
ctest --test-dir build -R '^(flb-it-lua|flb-rt-filter_lua|flb-it-processor|flb-it-input_chunk_routes)$' --output-on-failure
```

All four native CTest targets pass. The native Lua conversion unit test also
passes direct Valgrind execution with zero errors and no remaining allocations.

### Fixed acceptance tests

The separate YAML and filter acceptance buttons also use ephemeral virtual
filesystems. The collapsed acceptance-test YAML fixture is read-only and embedded
in `flb-wasm-yaml`: rebuild that target after editing its fixture on disk.
There is no JavaScript record-ingestion API yet. Expected malformed
YAML errors appear before the valid YAML test; the final status determines
whether the test passed. Missing binaries produce an actionable error.

Page-level HTTPS automation covers edited UTF-8 configs, real stdout, SQL drops,
manual/automatic stop, invalid YAML/plugins, reset/restart, all buttons, interrupted-cycle
recovery, missing binaries, unsupported browser capabilities, invalid runner
arguments, narrow-screen layout, and HTTP asset restrictions:

```sh
/tmp/flb-wasm-browser-venv/bin/python tests/wasm/browser_page_test.py \
  --build-dir build-wasm --browser /path/to/chromium
/tmp/flb-wasm-browser-venv/bin/python tests/wasm/browser_page_test.py \
  --build-dir build-wasm-6.0.9-asan --storage-only --browser /path/to/chromium
python3 tests/wasm/browser_server_test.py
```

The browser test pins only its temporary certificate's public key in its
ephemeral Chromium process; it does not disable certificate validation globally
or alter client trust stores. Use `--test-host <this-machine-IP>` to validate
HTTPS browser requirements on a non-loopback address. Server tests verify
certificate rejection/trust, redirect targets, hostname validation, key reuse
and permissions, and that a stalled TLS handshake cannot block the listener.

The second command requires an existing ASan `flb-wasm-storage` build. This page
uses the same previously built C binaries; changes to HTML/JS/Python do not
require a native rebuild. The native integration/Valgrind harness does not run
browser modules, so browser storage memory checks use the WASM ASan build.

Verified on the development host (both commands passed, including the expected
missing-binary failure followed by a successful retry):

```sh
/tmp/flb-wasm-browser-venv/bin/python tests/wasm/browser_page_test.py --build-dir build-wasm --browser /home/edsiper/.cache/ms-playwright/chromium_headless_shell-1181/chrome-linux/headless_shell
/tmp/flb-wasm-browser-venv/bin/python tests/wasm/browser_page_test.py --build-dir build-wasm-6.0.9-asan --storage-only --browser /home/edsiper/.cache/ms-playwright/chromium_headless_shell-1181/chrome-linux/headless_shell
```

HTTPS validation also passed with `--test-host 192.168.20.171` added to both
commands above, exercising a real non-loopback address. The standard-library
TLS/redirect suite passes with `python3 tests/wasm/browser_server_test.py`.
Native Valgrind was not run for these server/page changes: the native harness
cannot execute browser/WASM modules; the storage browser run used WASM ASan.

For the editable demo, native stdout regression coverage passed all 14 cases
both normally and with strict Valgrind:

```sh
tests/integration/.venv/bin/python -m pytest tests/integration/scenarios/out_stdout/tests/test_out_stdout_001.py -q
VALGRIND=1 VALGRIND_STRICT=1 tests/integration/.venv/bin/python -m pytest tests/integration/scenarios/out_stdout/tests/test_out_stdout_001.py -q
```

The interactive browser-only suite can also be selected with `--demo-only`.
An unoptimized ASan build of `flb-wasm-demo` exceeded Chromium's function-local
limit in `yyjson_read_opts`. Use the optimized ASan recipe below to run the
interactive engine. Native Valgrind coverage does not substitute for this test:

```sh
/tmp/flb-wasm-browser-venv/bin/python tests/wasm/browser_page_test.py \
  --build-dir build-wasm-6.0.9-asan --demo-only --browser /path/to/chromium
```

## Headless browser verification

Browser verification uses Playwright with an existing Chromium executable:

```sh
python3 -m venv /tmp/flb-wasm-browser-venv
/tmp/flb-wasm-browser-venv/bin/pip install playwright
/tmp/flb-wasm-browser-venv/bin/python tests/wasm/browser_smoke.py \
  --build-dir build-wasm --target flb-wasm-pipeline --browser /path/to/chromium
```

Repeat with targets `co-wasm-test`, `flb-wasm-events`, `flb-wasm-dependencies`,
`flb-wasm-yaml` and `flb-wasm-storage`. The runner serves files over loopback with COOP/COEP
headers and waits for actual worker completion. It checks module exit and
browser errors, not just page load. Verified browser: Chromium headless shell
1181. Firefox and Safari have not been tested.

Some dependencies generate headers in the source tree. **Do not build native
and WASM concurrently from one checkout.** Reconfigure after switching targets,
or use separate source checkouts.

## Acceptance coverage

| Test | Coverage |
| --- | --- |
| flb-wasm-dependencies | Valid/invalid JSON, CMetrics counter -> MessagePack -> decode -> Prometheus, invalid MessagePack. |
| co-wasm-test | Two worker threads, nested switches with live stack values, invalid sizes, repeated allocation/deletion, normal return and explicit pthread exit. |
| flb-wasm-events | Invalid durations, timers, disable/rearm, finite and zero waits, channels, queue capacity, worker spawn/join, repeated cleanup. |
| flb-wasm-pipeline | SHA-256 known answer, modify/grep, all-drop chunk, two-output fan-out, three create/start/stop/destroy cycles. |
| flb-wasm-build-profile | Defaults, minimal mode, incompatible overrides, native defaults, stale-cache and wrong-toolchain rejection. |
| flb-wasm-yaml | Reject malformed YAML; load a filesystem-backed pipeline; content_modifier, SQL, envelope for logs; cumulative_to_delta, metrics_selector, labels for metrics; probabilistic sampling for traces. |
| flb-wasm-storage | Chunk growth/remapping, checksum, metadata, sync/down/up, reopen and deletion; symlink-safe recursive cleanup. Chromium additionally verifies IndexedDB recovery across reloads, persisted deletion and transaction failure/retry. |

Option-policy tests do not need Emscripten:

```sh
cmake -DTEST_BINARY_ROOT=/tmp/flb-wasm-profile-tests -P tests/wasm/check_profile.cmake
```

## Plugin policy

The profile retains 37 candidates plus the automatically enabled stream
processor input. Compilation is not runtime validation of every plugin.
New plugins default to disabled unless added to `FLB_WASM_BROWSER_PLUGINS`.
Existing CMake options can disable candidates; `FLB_MINIMAL=ON` disables their
defaults. Incompatible enabled options fail configuration.

| Area | Candidates |
| --- | --- |
| Inputs | lib, dummy, random, emitter, event_type, fluentbit_metrics, fluentbit_logs, storage_backlog. |
| Filters | alter_size, expect, grep, log_to_metrics, lua (portable interpreter), modify, multiline, nest, parser, record_modifier, rewrite_tag, stdout, throttle, type_converter. |
| Processors | content_modifier, cumulative_to_delta, labels, metrics_selector, opentelemetry_envelope, SQL, sampling. |
| Outputs | lib, null, stdout, counter, flowcounter, http, loki and opentelemetry (shared Fetch HTTPS). |
| Data capabilities | Parsers, regex, record accessor, stream processing, metrics, traces, profiles, MessagePack, JSON, compression. |
| Excluded | OS collectors, socket listeners/raw TCP/UDP outputs, cloud credentials, LuaJIT, WAMR, Kafka, Zig, GPU/ML libraries, native TLS, SQLite storage, checklist (requires SQLite), TDA (Ripser runtime failure). |

All seven enabled processors are exercised, not merely compiled. This is not
coverage of every processor mode: sampling currently tests probabilistic mode,
for example. The eighth registered processor, TDA, compiles but crashes during
repeated Ripser computations. Ripser contains static enumerators retaining
references to a per-call object (also reproduced as native ASan
stack-use-after-return), and a 64-bit shift on a 32-bit `long`. Its bundled
sources have not been changed: separate authorization is required. TDA remains
excluded rather than shipping a known-crashing processor. Unregistered local
experimental processor directories are not part of this build profile.

The YAML test sets `threaded: false` on the synthetic `event_type` inputs. Their
default dedicated-input-thread collector handshake failed in this runtime;
non-threaded collectors run on the engine worker. Dedicated threaded inputs
are rejected during initialization. Browser HTTPS uses browser-managed TLS, not the
native TLS socket backend.

The tested metrics chain places cumulative_to_delta last. A conversion before
metrics_selector lost the counter's delta aggregation flag during subsequent
metric copying. General processor-order parity needs separate CMetrics work;
that bundled library has not been modified.

## YAML and browser-local filesystem

ChunkIO's filesystem backend is enabled. `/storage` is mounted on Emscripten
IDBFS and restored from IndexedDB **before C main runs**. These are virtual
files scoped to the browser origin, not host paths or Web Storage `localStorage`.
The mount uses MEMFS without persistence under Node, or when the embedding page
sets `Module.flbStoragePersistent = false` before loading the generated script.
An optional `Module.flbStoragePath` selects a dedicated top-level mount directory.

Use the ordinary YAML configuration interface with a file in the virtual FS;
`tests/wasm/data/processors.yaml` is a complete tested example. Filesystem input
chunks require both the service path and the input storage type:

```yaml
service:
  storage.path: /storage/fluent-bit
  storage.sync: full
  storage.checksum: on
pipeline:
  inputs:
    - name: lib
      tag: browser.logs
      storage.type: filesystem
  outputs:
    - name: stdout
      match: '*'
```

There are two distinct sync boundaries. ChunkIO `cio_chunk_sync()` / closing
chunks flushes mappings into the virtual filesystem. The embedding page must
then explicitly commit that filesystem to IndexedDB:

```js
// After stopping/quiescing writers and syncing/closing their chunks:
await Module.flbStorage.sync();
```

`storage.sync: full` alone does not commit IndexedDB. The JS call does not flush
live C mappings or pause the engine, and unload callbacks cannot guarantee an
async commit. Restore failures abort startup; commit failures reject the promise
and can be retried. The browser test checkpoints after C cleanup before reload.
Use a single writer per origin/mount: multi-tab coordination is not implemented.
Quota, browser eviction and private-browsing policies still apply. This is not
crash-atomic with output acknowledgements and does not promise exactly-once delivery.

## Upstream ownership and portability changes

User approval covers these bundled-library edits. Keep their patches separate
from Fluent Bit glue. No commits or PRs have been created.

| Upstream destination | Scope |
| --- | --- |
| fluent/chunkio | Memory-only guards/tests; Emscripten nftw deletion and mmap resize fallback; filesystem browser tests and test-owned leak cleanup. |
| monkey/monkey | Separate shared HTTP constants from server headers, typed pthread entry wrapper, browser poll/timers. |
| edsiper/flb_libco | Emscripten fiber backend, SDK compatibility handling, coroutine tests. |

The dependency tests can also be built independently for upstream review:

```sh
emcmake cmake -S lib/monkey/test/wasm -B /tmp/flb-monkey-wasm-tests
cmake --build /tmp/flb-monkey-wasm-tests -j8
ctest --test-dir /tmp/flb-monkey-wasm-tests --output-on-failure
emcmake cmake -S lib/flb_libco -B /tmp/flb-libco-wasm-tests -DLIBCO_TESTS=ON
cmake --build /tmp/flb-libco-wasm-tests -j8
ctest --test-dir /tmp/flb-libco-wasm-tests --output-on-failure
emcmake cmake -S lib/chunkio -B /tmp/flb-chunkio-wasm-fs \
  -DCIO_BACKEND_FILESYSTEM=ON -DCIO_TESTS=ON
cmake --build /tmp/flb-chunkio-wasm-fs -j8
ctest --test-dir /tmp/flb-chunkio-wasm-fs --output-on-failure
```

Browser polling uses Emscripten 6.0.9's public POSIX poll interface: zero-timeout
probes use its non-suspending syscall, and blocking waits use the SDK readiness
queue with the nearest timer deadline. There are no periodic 10 ms wakeups or
direct accesses to private FS stream handlers. Timers remain worker-owned, with
coalesced pipe notifications and no thread per timer. Waiting on the browser
main thread is rejected. The native poll implementation remains unchanged.
The event-fiber regression covers nonblocking and blocking waits inside libco,
cross-pthread wakeups, timers, and normal coroutine/pthread teardown.

The new epoll implementation is not needed for this path: keeping the shared
poll backend uses the same upstream readiness queues without introducing an
additional timer adapter. JSPI is not a replacement for the Asyncify fiber API.
The SDK explicitly declares mainScriptUrlOrBlob in INCOMING_MODULE_JS_API, as
required by newer Emscripten versions. Startup promise rejections remain observed.
Experimental cross-origin Wasm caching and IDBFS auto-persistence are not enabled;
streaming compilation and explicit storage checkpoints retain their semantics.

Libco allocates separate C and Asyncify stacks and forbids fiber migration
across threads. In Emscripten 6.0.9, first fiber entry still misses a keepalive
decrement; nested rewind can also finalize a pthread before its outer entry
wrapper returns. A local shim balances first entry, preserves the final rewind
return value, and leaves finalization to the outer wrapper. Reused workers reset
the trampoline state left by `pthread_exit`. Tests cover NULL/non-NULL pthread
returns, explicit `pthread_exit(value)`, worker reuse, and nested switches.

The shim reads the destination fiber descriptor before installing its stack
bounds, then restores the stack pointer without an intervening instrumented
heap access. ASan start/finish notifications track the active stack. Deliberate
heap/stack out-of-bounds writes and stack exhaustion verify that checks remain
active. Assertions-disabled builds with stack-check levels 0, 1 and 2 also run
the positive regression. This is wasm32-only and uses private SDK interfaces;
validated SDK fixes should replace it before relaxing the version requirement.

Fluent Bit glue removes unconditional dependencies on disabled TLS, HTTP server
and SQL storage facilities. Shared HTTP-server configuration remains available
without compiling the server implementation. Native feature implementations
are retained.

Filesystem pipeline testing also required a width-correct timestamp format for
chunk names on 32-bit targets. SQL now copies length-delimited MessagePack
strings using their explicit length, with regression cases for non-terminated,
embedded-NUL, empty and missing values. These are Fluent Bit-owned patches,
separate from the bundled-library changes.

## Memory checks and unresolved blockers

```sh
emcmake cmake -S . -B build-wasm-6.0.9-asan -DFLB_WASM_BROWSER=ON \
  -DFLB_DEBUG=OFF -DFLB_RELEASE=OFF -DCMAKE_BUILD_TYPE=MinSizeRel \
  -DLIBCO_TESTS_ASAN=ON \
  -DCMAKE_C_FLAGS=-fsanitize=address \
  '-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address -sALLOW_MEMORY_GROWTH=1'
cmake --build build-wasm-6.0.9-asan -j8
ctest --test-dir build-wasm-6.0.9-asan --output-on-failure
```

The optimized build passes all 15 WASM CTests under ASan, including the full
pipeline, YAML/seven processors, HTTP clients, and coroutine shutdown. The libco,
generic HTTP, HTTP lifecycle, pipeline and YAML targets also pass Chromium ASan
smoke tests. No ASan or stack-overflow checks were disabled. The fault tests
require both a nonzero exit and the expected diagnostic; timeouts are failures.
The complete Chromium page suite passes both with and without ASan, including
HTTP/Loki/OTLP pending-request Stop, editable Lua/processor pipelines, and storage
reload/failure recovery. Expected configuration failures also reject sanitizer
diagnostics instead of treating them as a successful negative test.

```sh
python3 tests/wasm/browser_page_test.py --build-dir build-wasm-6.0.9-asan --browser /path/to/chromium
python3 tests/wasm/browser_page_test.py --build-dir build-wasm-6.0.9-release --browser /path/to/chromium
python3 -m unittest discover -s tests/wasm -p test_browser_page.py
```

Enabling execution exposed two cleanup issues, addressed separately from libco:

- The pipeline test's SHA-256 fixture left OpenSSL thread-local state on the
  proxied main worker (674 bytes). The fixture now calls `OPENSSL_thread_stop()`
  there before process exit, whose callbacks run on the browser runtime thread.
- Forced browser HTTP shutdown resumed cancelled flushes after the event loop
  had stopped, leaving completed coroutines unreaped. Browser engine teardown
  now drains the finished-flush lists before destroying output instances.

Remaining SDK limitations:

- Unoptimized ASan + Asyncify can still exceed the VM's per-function local limit
  in `yyjson_read_opts`; use the optimized recipe above.
- Optional `detect_stack_use_after_return=1` still fails in Emscripten 6.0.9's
  `FakeStack::Destroy` / `munmap` during pthread teardown. This reproduces in a
  standalone pthread program with no libco or Asyncify. The passing runs use
  the SDK's default ASan settings, not this optional mode; the mode is not
  silently suppressed. Stack-buffer-overflow detection remains tested.

Fiber-fix native verification passed 2/2 engine/scheduler CTests and 34/34
HTTP/stdout integration cases both normally and with strict Linux Valgrind.
The native binary was rebuilt and native generated headers restored. Commands:

```sh
ctest --test-dir build -R '^flb-(it-scheduler|rt-core_engine)$' --output-on-failure
tests/integration/.venv/bin/python -m pytest tests/integration/scenarios/out_http -q
VALGRIND=1 VALGRIND_STRICT=1 tests/integration/.venv/bin/python -m pytest tests/integration/scenarios/out_http -q
tests/integration/.venv/bin/python -m pytest tests/integration/scenarios/out_stdout/tests/test_out_stdout_001.py -q
VALGRIND=1 VALGRIND_STRICT=1 tests/integration/.venv/bin/python -m pytest tests/integration/scenarios/out_stdout/tests/test_out_stdout_001.py -q
```

These native checks do not execute the Emscripten backend: the WASM checks use
ASan because Valgrind cannot instrument browser WebAssembly modules. Keep
`lib/flb_libco` backend/tests as an `edsiper/flb_libco` patch, separate from the
Fluent Bit engine cleanup, test harness and documentation changes.

Native ChunkIO tests pass with filesystem support enabled and disabled.
Memory-only context/memfs tests also pass Valgrind with zero errors and all
allocations freed. The native integration harness cannot launch WASM modules;
shared-core/native HTTP regression coverage runs separately in normal and
strict Valgrind modes. Functional success does not establish memory safety.

The filesystem coverage passes all six standalone Emscripten ChunkIO tests
with ASan enabled. The worker storage target also passes ASan in Node and
Chromium, including reload recovery and transaction failure/retry. The native
filesystem suite passes all five tests; `cio-test-fs --exec=never` passes strict
Valgrind with zero errors and no remaining allocations. Two test-owned leaks
were fixed without suppressions. The SDK limitations above still apply; clean
filesystem tests alone do not establish full-engine memory safety.

```sh
emcmake cmake -S lib/chunkio -B /tmp/flb-chunkio-wasm-fs-asan \
  -DCIO_BACKEND_FILESYSTEM=ON -DCIO_TESTS=ON \
  '-DCMAKE_C_FLAGS=-O1 -fsanitize=address' \
  '-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address -sALLOW_MEMORY_GROWTH=1'
cmake --build /tmp/flb-chunkio-wasm-fs-asan -j8
ctest --test-dir /tmp/flb-chunkio-wasm-fs-asan --output-on-failure
```

Earlier filesystem verification passed: 7/7 WASM CTests, Chromium YAML and storage tests,
16/16 focused native CTests, and 4/4 storage-backlog integration cases both
normally and with strict Valgrind. Native SQL and YAML unit tests also pass
strict Valgrind with zero errors and no remaining allocations. Exact commands:

```sh
ctest --test-dir build-wasm -R 'flb-wasm-|co-wasm-test' --output-on-failure
ctest --test-dir build -R '^flb-(it-(config_format.*|processor.*|cumulative_to_delta|input_chunk.*|storage_.*)|rt-(in_storage_backlog|processor_.*))$' --output-on-failure
tests/integration/.venv/bin/python -m pytest \
  tests/integration/scenarios/in_storage_backlog/tests/test_in_storage_backlog_001.py -q
VALGRIND=1 VALGRIND_STRICT=1 tests/integration/.venv/bin/python -m pytest \
  tests/integration/scenarios/in_storage_backlog/tests/test_in_storage_backlog_001.py -q
valgrind --leak-check=full --show-leak-kinds=all --errors-for-leak-kinds=all \
  --error-exitcode=99 ./build/bin/flb-it-processor_sql --exec=never
valgrind --leak-check=full --show-leak-kinds=all --errors-for-leak-kinds=all \
  --error-exitcode=99 ./build/bin/flb-it-config_format_yaml --exec=never
```

Native verification on the development host passed: full build, seven focused
CTests, and all 49 HTTP integration cases both normally and with strict Valgrind.
The independent native Monkey poll timer test also passed. Exact shared-core
verification commands (from the Fluent Bit root):

```sh
./tests/integration/setup-venv.sh
cmake -S . -B build -DFLB_TESTS_RUNTIME=On -DFLB_TESTS_INTERNAL=On
cmake --build build -j8
ctest --test-dir build -R '^flb-(it-(crypto|hash|gzip|config_map|http_server)|rt-(out_lib|config_map_opts))$' --output-on-failure
tests/integration/.venv/bin/python -m pytest \
  tests/integration/scenarios/in_http/tests/test_in_http_001.py \
  tests/integration/scenarios/out_http/tests/test_out_http_001.py \
  tests/integration/scenarios/internal_http_server/tests/test_internal_http_server_001.py -q
VALGRIND=1 VALGRIND_STRICT=1 tests/integration/.venv/bin/python -m pytest \
  tests/integration/scenarios/in_http/tests/test_in_http_001.py \
  tests/integration/scenarios/out_http/tests/test_out_http_001.py \
  tests/integration/scenarios/internal_http_server/tests/test_internal_http_server_001.py -q
```

## Next milestones

1. Resolve sanitizer/fiber lifecycle support.
2. Expose an asynchronous JavaScript API for configure, push, output delivery
   and stop/destroy, with bounded queues and explicit buffer ownership.
3. Validate emitters, multiline, processors, retries, other signals, failure
   cleanup and longer-running workloads.
4. Validate additional HTTP-based outputs against the shared Fetch backend;
   both client APIs and HTTP/Loki/OTLP outputs are now available.
5. Extend IndexedDB durability/backlog validation, cross-browser support, packaging and CI.

The pthread ABI requires SharedArrayBuffer and cross-origin isolation.
There is no single-thread fallback. Browser suspension, memory limits and
cancellation still need lifecycle design before an embedding API is published.

## Platform references

- [Emscripten CMake builds](https://emscripten.org/docs/compiling/Building-Projects.html)
- [Browser networking](https://emscripten.org/docs/porting/networking.html)
- [Fetch, CORS and credentials](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API/Using_Fetch)
- [Browser-controlled request headers](https://developer.mozilla.org/en-US/docs/Glossary/Forbidden_request_header)
- [Pthreads and main-thread restrictions](https://emscripten.org/docs/porting/pthreads.html)
- [Emscripten fibers](https://emscripten.org/docs/api_reference/fiber.h.html)
- [WASM sanitizers](https://emscripten.org/docs/debugging/Sanitizers.html)
- [Python TLS server contexts](https://docs.python.org/3.12/library/ssl.html)
- [OpenSSL development certificate generation](https://docs.openssl.org/3.2/man1/openssl-req/)
- [Emscripten filesystem and IDBFS](https://emscripten.org/docs/api_reference/Filesystem-API.html)
- [libyaml releases](https://github.com/yaml/libyaml/releases)
- [OpenSSL releases](https://openssl-library.org/source/)
