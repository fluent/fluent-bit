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
Browser builds require a separate build directory; in-source configurations are
rejected to keep generated SDK assets from overwriting source files.
The CMake install component is `wasm-sdk`. No registry publication is performed.
The npm package remains private. Validated archives are published as experimental
GitHub release assets as described below.

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

For interactive runs, create one instance and retain it across runs:

```js
await fluent.start({yaml, graceSeconds: 0});
await fluent.push({input: 'application', records});
await fluent.drain(); // Output callbacks have been invoked; no setTimeout is needed.
await fluent.stop();  // The module and pthread pool remain warm.
// Repeat start/push/drain/stop with the next YAML, then destroy on final disposal.
```

A zero-grace stop checks shutdown immediately instead of waiting for a one-second
shutdown tick. Call `drain()` first when queued local records must finish.
The regular engine event loop still runs; there is no scheduler-free batch mode
or guaranteed runtime in milliseconds. Timers/network retries and buffered
processors cannot be replaced by a general synchronous pipeline call.
Configure `FLB_WASM_PTHREAD_POOL_SIZE` (3–16, default 3) at build time if a workload
needs additional pthreads. CMake sets both the runtime pool and worker limit.
One or two threads cannot host the current SDK's three concurrent C threads.

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
- `drain()` immediately collects pending `lib` pipe data, flushes chunks through
  the engine, awaits completion of local output tasks, and invokes queued
  stdout/stderr callbacks before resolving. It does not await promises returned
  by those callbacks; applications must track their own asynchronous work.
  It requires exclusively nonthreaded, memory-backed
  `lib` inputs and `stdout`/`null` outputs; other pipelines reject with
  `E_UNSUPPORTED`. Filtered/dropped and unmatched records need not produce output.
  Filter/processor-private buffered records are outside this engine-chunk barrier.
  Existing bounded log transport can truncate/drop lines; this is not a lossless
  output collection API. The operation deadline still applies.
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
The pthread scripts initialize sequentially before the runtime is created;
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
The SDK defaults to three pthread workers (command, engine, logging) and rejects dedicated threaded
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

## Experimental CI artifacts

The Browser WebAssembly workflow builds and tests optimized and AddressSanitizer
configurations for every branch push, pull request update, and manual run. After
the optimized build, CTests and SDK unit tests pass, its run exposes the Actions artifact
`fluent-bit-browser-experimental-<source-commit>` for 30 days.

Download that artifact from the workflow run, then verify and extract it:

```sh
sha256sum -c fluent-bit-browser-experimental.tar.gz.sha256
tar -xzf fluent-bit-browser-experimental.tar.gz
cd fluent-bit-browser-experimental
sha256sum -c SHA256SUMS
```

Deploy the entire extracted directory on the application origin. Import
`createFluentBit` from `fluent-bit.js`; the worker and runtime assets must remain
beside it. See the hosting instructions above for HTTPS and COOP/COEP headers.
`build-info.json` records the Emscripten version, source commit, and exact build
commit (the PR merge commit for pull request runs). These are experimental,
unsanitized browser assets, not a production release or an npm publication.
Artifact availability does not imply the subsequent browser tests or the ASan
job passed; check the workflow results before choosing a build.

## Published experimental SDKs

After both optimized and ASan jobs pass all CTest, SDK, browser lifecycle,
startup-fault and demo tests, master pushes publish a GitHub prerelease named
`wasm-browser-<full-commit>`. Each snapshot has its own tag and assets; it does
not replace the latest stable Fluent Bit release. PRs and branch pushes only
produce Actions artifacts. The `fluent-bit-browser-validated-<source-commit>`
Actions artifact contains the same release payload after the complete matrix
passes, including a browser test of the extracted archive and FTS ingestion.

The staging release workflow calls this same build after creating a version
release. The SDK is built from that release tag, not master. Releases that
predate the browser profile are skipped. Releases published outside the staging
workflow also trigger the browser workflow. For recovery, dispatch Browser
WebAssembly with `release_tag` set to an existing version tag such as `v5.2.0`.
A manual run without a release tag builds/tests without publishing.

A version release provides these files (snapshots use the full commit instead
of `v5.2.0`):

- `fluent-bit-browser-experimental-v5.2.0.tar.gz`: complete optimized SDK.
- `fluent-bit-browser-experimental-v5.2.0.tar.gz.sha256`: archive checksum.
- `fluent-bit-browser-experimental-v5.2.0.json`: source/build commits, toolchain,
  SDK version, archive SHA-256, and the successful validation run URL.

Existing assets are never overwritten. Publication downloads the assets again
and compares them with the validated payload; an existing asset with different
bytes fails verification. The original archive's `build-info.json` describes
its build-stage checks; the external JSON manifest records the subsequent
complete matrix validation. Publication copies the exact tested archive bytes.

### Consume from Fluent Bit Studio

Pin an explicit release or snapshot in Studio's deployment pipeline. Download
and verify the archive there, then serve the extracted SDK on Studio's own
origin. Do not load workers directly from GitHub or automatically select a
moving latest version in an open browser session.

```sh
flb_tag=v5.2.0
flb_asset="fluent-bit-browser-experimental-$flb_tag"
gh release download "$flb_tag" --repo fluent/fluent-bit \
  --pattern "$flb_asset.tar.gz" --pattern "$flb_asset.tar.gz.sha256" \
  --pattern "$flb_asset.json"
sha256sum -c "$flb_asset.tar.gz.sha256"
mkdir -p "public/wasm/$flb_tag"
tar -xzf "$flb_asset.tar.gz" --strip-components=1 -C "public/wasm/$flb_tag"
(cd "public/wasm/$flb_tag" && sha256sum -c SHA256SUMS)
```

Import `/wasm/v5.2.0/fluent-bit.js` in Studio, keeping the runtime, WASM and both
worker scripts beside it. Preserve the HTTPS, COOP/COEP, MIME and CSP settings
above. Use immutable caching for the versioned directory. Published archives
remain experimental and do not imply a production support guarantee.

## Typed scripting processor

The default browser artifact includes the `fts` processor using portable Lua 5.4.
Supply a policy with `writeFile('/config/policy.lua', source)` and reference that
path from the YAML processor's `script` property. `jit: true` is unavailable in
browser builds. See the [FTS guide](https://github.com/fluent/fluent-bit/blob/master/plugins/processor_fts/README.md) for
policies, typed values and resource limits.

## Release gates

Before promoting this experimental API: run ASan lifecycle/network/storage and
fault tests; validate Firefox/WebKit as well as Chromium; exercise CSP/bundlers,
multiple tabs and storage quota failures; measure low-memory/mobile devices and
long-running queues; review API/version compatibility and dependency licenses;
produce checksummed reproducible release assets and security/update procedures.
Passing Chromium tests alone is not a claim that all these gates are complete.

The Emscripten 6.0.9 migration passes the optimized/ASan SDK and demo suites.
The Chrome 151 worker-retention failure is covered by repeated startup fault tests
against the first and last workers. Sequential bootstrap alone was insufficient
in later runs. Failed startup now requests cooperative child shutdown before
terminating the parent, with a 250 ms fallback for an unresponsive child. Optional ASan
`detect_stack_use_after_return=1` still fails during the SDK's pthread `munmap`
cleanup (also without libco or Asyncify); that limitation is unchanged.
