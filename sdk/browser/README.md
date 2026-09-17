# Fluent Bit browser SDK (experimental)

This is an early embeddable SDK, not a production support or throughput promise.
It runs the real C engine in an isolated worker with a private pthread runtime.
Thousands of application users each run their own instance on their device;
this does not mean thousands of instances or workers in one browser tab.

## Build and deploy

Configure Fluent Bit with Emscripten 6.0.9 and `FLB_WASM_BROWSER=ON`,
`FLB_DEBUG=OFF`, `FLB_RELEASE=OFF`, and `CMAKE_BUILD_TYPE=MinSizeRel`.
Build target `fluent-bit-runtime`. The complete distributable is in
`build-wasm-6.0.9-release/sdk/browser/`; copy the entire directory, not only the WASM.
The CMake install component is `wasm-sdk`. No registry publication is performed.
The package is deliberately private until the release gates below are met.

Serve on the application origin over HTTPS (localhost is allowed), with:

```text
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Content-Type: application/wasm   (for .wasm files)
```

JavaScript files require a JavaScript MIME type. Do not return an SPA's HTML
fallback for missing assets. Keep every release in an immutable versioned
directory so cached JS and WASM cannot be mixed. Enable HTTP compression and
long-lived caching for that directory, but not for an unversioned manifest.
The development demo server intentionally disables caching/compression.
Bundlers must preserve/copy the worker, generated runtime and WASM as assets.
`workerUrl` can select their deployed same-origin location. Do not use a blob
or cross-origin worker URL. CSP must permit the worker and Emscripten's nested
workers, WASM compilation, and the configured HTTPS output destinations;
validate your exact CSP before rollout. COOP/COEP may affect existing embeds.

## Use

```js
import {createFluentBit} from './fluent-bit.js';

const fluent = await createFluentBit({
  onStdout: line => console.log(line),
  onStderr: line => console.error(line),
  onError: error => console.error(error.code, error.message)
});
try {
  await fluent.start({yaml: `
service:
  flush: 0.2
pipeline:
  inputs:
    - name: lib
      alias: application
      tag: application
  outputs:
    - name: stdout
      match: '*'
      format: json_lines
`});
  await fluent.push({input: 'application', records: [{message: 'Hello'}]});
  // Keep the instance alive while your application produces telemetry.
} finally {
  await fluent.destroy();
}
```

Dummy inputs, YAML processors, Lua and browser-compatible HTTP outputs use the
same YAML as the demo. A `lib` input is needed only for JavaScript `push()`.
Write Lua/config assets with `writeFile('/config/script.lua', source)` before
starting. Filesystem asset operations are rejected while the engine runs.

## Lifecycle and delivery contract

- Creation resolves when the command worker and C runtime are ready. `start()`
  resolves only when `flb_start()` succeeds. These are different milestones.
- One engine per SDK instance. Start/stop cycles reuse its downloaded module.
  Multiple instances have separate memory/FS/workers; prefer one per application.
- Operations are FIFO and promises always settle on response, failure, or timeout.
  Configuration changes require stop/start. There is no claimed live reload.
- `push()` copies its batch and resolves with bytes/records accepted by the input
  pipe, not records processed or delivered. Timestamps are assigned at submission.
  JSON number precision and JSON serialization semantics apply; BigInt/cycles are
  rejected. This is a logs API, not an arbitrary MessagePack/OTLP ingestion API.
- A partial input write makes the instance unusable: it cannot be replayed safely.
  Queue-full errors mean the command was not sent and may be retried after draining.
- `stop()` applies the grace configured by `start({graceSeconds})` (default 5,
  maximum 30), releases the engine, and checkpoints persistent storage. Grace
  expiry may drop outstanding data. A successful stop is not an output receipt.
- `destroy()` stops then releases the runtime and workers. It is idempotent.
  `destroy({force:true})` and timeout recovery can lose unflushed data. A timeout
  fails closed: the instance is terminated, not reused in an unknown state.
- AbortSignal cancels creation only. No implicit unload handler claims to flush
  on navigation/tab close. Applications must own their shutdown policy.
- Callbacks run on the application thread; thrown/rejected callbacks are isolated
  and reported through `onError`. Do not use stdout as a lossless data transport.

Default deadlines: initialization/operation 45 seconds, destroy 15 seconds.
Choose a destroy deadline longer than your configured grace plus checkpoint time.
`onProgress({stage, loadedBytes, totalBytes})` distinguishes runtime JavaScript,
WASM download, compilation, pthread initialization and C command-thread startup.
Downloads retain streaming compilation; progress does not buffer another WASM
copy. `totalBytes` is zero when the decoded size is unknown (including compressed
responses). The demo displays these stages and a download byte counter.
The private `fluent-bit-pthread.js` asset is required too. Each pthread explicitly
acknowledges its JavaScript handler before receiving shared WASM state. Worker
load/decoding errors are captured from construction and forwarded as runtime
errors; `[SDK pthread]` diagnostics identify boot, handler readiness, payload
receipt and completed initialization. Failed initialization cancels streaming
WASM work and terminates the created pthread workers before reporting failure.
The four pthread scripts initialize sequentially before the runtime is created;
the runtime then reuses those workers. This avoids cancelling sibling module
loads when a script fails, at the cost of serializing their startup latency.

## Limits and storage

The API bounds YAML to 64 KiB; batches to 1000 records/1 MiB; pending operations
to 16/8 MiB. Files are limited to 1 MiB each, 32 files/8 MiB total beneath
`/config/`. Log delivery has bounded batches and an acknowledgment window;
individual lines are truncated at 4096 characters and overload is reported as
`E_LOG_DROPPED`. Configure Fluent Bit chunk/retry/memory limits too: SDK admission
limits alone do not bound downstream backlog. WASM growth is capped at 1 GiB;
worker and JS heap allocations are additional, not included in that cap.
The SDK caps its pthread pool at four workers and rejects dedicated threaded
inputs at startup; set `threaded: false`, including for `event_type` inputs.

`await fluent.getStats()` returns an immutable snapshot of lifetime accepted
records/bytes, current queued commands/bytes (including the query itself), queue
admission rejections, dropped log lines, allocated Wasm memory, HTTP requests
awaiting completion/consumption, and checkpoint state. Acceptance measures the
input handoff, not remote delivery. Wasm memory is allocated capacity, not live
usage; these counters do not measure engine backlog, retries or output drops.

Persistent storage is opt-in:

```js
const fluent = await createFluentBit({
  storage: {persistent: true, namespace: 'my-app'}
});
console.log(fluent.info.storagePath); // Use this path in YAML storage.path.
```

Web Locks prevent concurrent writers to the same namespace across tabs/instances;
busy namespaces fail with `E_STORAGE_BUSY`. Do not rename a namespace casually:
it selects a different browser-local store. Closing/destroying does not erase it.
Checkpoints happen only with writers stopped. On `E_STORAGE`, retry
`syncStorage()` before destruction or restarting; restart is blocked until a
checkpoint succeeds. `getStats().checkpointRequired` remains true during a
persistent run, after failed startup, and after a failed checkpoint. A failed
persistent startup also needs `stop()` or `syncStorage()` before retrying.
`lastCheckpointTime` is the last
successful persistent checkpoint time, not a delivery watermark. A shutdown
error is terminal because the runtime cannot safely establish quiescence.
Browser quotas, private mode, eviction and
crashes can still lose data. No exactly-once/crash-atomic guarantee is provided.
The `/config/` asset directory is ephemeral and separate from persistent chunks.

YAML and Lua are trusted application code. This SDK is not a sandbox for hostile
configuration. Browser HTTP still follows Fetch/CORS restrictions; secrets in a
browser are visible to its user. No remote service, telemetry collection, or
automatic update is built into the facade.

## Release gates

Before promoting this experimental API: run ASan lifecycle/network/storage and
fault tests; validate Firefox/WebKit as well as Chromium; exercise CSP/bundlers,
multiple tabs and storage quota failures; measure low-memory/mobile devices and
long-running queues; review API/version compatibility and dependency licenses;
produce checksummed reproducible release assets and security/update procedures.
Passing Chromium tests alone is not a claim that all these gates are complete.

The Emscripten 6.0.9 migration passes the optimized/ASan SDK and demo suites.
The Chrome 151 worker-retention failure is covered by repeated startup fault tests
against the first and fourth workers. Sequential bootstrap alone was insufficient
in later runs. Failed startup now requests cooperative child shutdown before
terminating the parent, with a 250 ms fallback for an unresponsive child. Optional ASan
`detect_stack_use_after_return=1` still fails during the SDK's pthread `munmap`
cleanup (also without libco or Asyncify); that limitation is unchanged.
