/* SPDX-License-Identifier: Apache-2.0 */

const ABI = 1;
// Emscripten 6.0.9 libpthread.js command IDs (the toolchain is pinned).
const PTHREAD_LOAD = 1;
const PTHREAD_LOADED = 3;
// Keep the prewarmed pool aligned with cmake/wasm-sdk.cmake.
const PTHREAD_POOL_SIZE = 4;
const preparedWorkers = new Map();
let runtime;
let state = 'loading';
let initialized = false;
let active = null;
let releaseStorage = null;
let logs = [];
let logBytes = 0;
let dropped = 0;
let logInFlight = false;
let logTimer = null;
const encoder = new TextEncoder();
const files = new Map();
let fileBytes = 0;
let logDrains = [];
let wasmDownload = null;
let wasmInitialization = null;
let checkpointRequired = false;
let checkpointFailures = 0;
let lastCheckpointTime = null;
let acceptedBytes = 0;
let acceptedRecords = 0;

async function checkpoint() {
    checkpointRequired = true;
    try {
        await runtime.flbStorage.sync();
        checkpointRequired = false;
        if (runtime.flbStorage.persistent) { lastCheckpointTime = Date.now(); }
    }
    catch (_) {
        checkpointFailures++;
        throw fail('E_STORAGE', 'Storage checkpoint failed; call syncStorage() to retry before restarting');
    }
}

// Only this private SDK worker's global is changed, never the application's.
// Observe failures at construction, before Emscripten finishes compiling WASM
// and attaches its handlers. Gate load on the child's explicit runtime handshake.
const BrowserWorker = self.Worker;
const pthreadWorkers = new Set();
self.Worker = class extends BrowserWorker {
    #runtimeReady = false;
    #load = null;
    #resolveReady;
    #rejectReady;
    #resolveClosed;
    #ready = new Promise((resolve, reject) => { this.#resolveReady = resolve; this.#rejectReady = reject; });
    constructor(url, options) {
        const prepared = preparedWorkers.get(options?.name);
        if (prepared) {
            preparedWorkers.delete(options.name);
            return prepared;
        }
        if (pthreadWorkers.size >= PTHREAD_POOL_SIZE) {
            throw fail('E_LIMIT', 'Browser pthread pool exhausted');
        }
        super(url, options);
        this.#ready.catch(() => {});
        pthreadWorkers.add(this);
        const name = options?.name || 'pthread';
        this.addEventListener('error', event => {
            event.preventDefault();
            event.stopImmediatePropagation();
            this.#rejectReady(new Error(event.message || 'Worker script failed to load'));
            fatal(`${name}: ${event.message || 'worker script failed to load'} (${url})`);
        });
        this.addEventListener('messageerror', () => {
            this.#rejectReady(new Error('Invalid worker response'));
            fatal(`${name}: invalid worker response`);
        });
        this.addEventListener('message', event => {
            if (event.data?.flbPthread === 1) {
                event.stopImmediatePropagation();
                const {stage, message} = event.data;
                if (stage === 'closed') { this.#resolveClosed?.(); return; }
                log('stderr', `[SDK pthread] ${name}: ${stage}${message ? ': ' + message : ''}`);
                if (stage === 'error') {
                    this.#rejectReady(new Error(message));
                    fatal(`${name}: ${message}`);
                }
                if (stage === 'runtime-ready') {
                    this.#runtimeReady = true;
                    this.#resolveReady();
                    if (this.#load) {
                        const args = this.#load;
                        this.#load = null;
                        try { super.postMessage(...args); }
                        catch (error) { fatal(`${name}: unable to send WASM payload: ${error.message}`); }
                    }
                }
            }
            else if (event.data?.cmd === PTHREAD_LOADED) {
                log('stderr', `[SDK pthread] ${name}: ready`);
            }
        });
    }
    get ready() { return this.#ready; }
    async shutdown() {
        // Let initialized children close before their owner exits. Terminating
        // both levels at once can retain a Chromium worker after startup fails.
        let timer;
        try {
            await new Promise(resolve => {
                this.#resolveClosed = resolve;
                timer = setTimeout(resolve, 250);
                super.postMessage({flbShutdown: 1});
            });
        }
        catch (_) { /* An unavailable child will be terminated below. */ }
        finally { clearTimeout(timer); this.terminate(); }
    }
    postMessage(...args) {
        if (args[0]?.cmd === PTHREAD_LOAD && !this.#runtimeReady) {
            if (this.#load) { throw fail('E_PROTOCOL', 'Duplicate pthread load request'); }
            this.#load = args;
            return;
        }
        super.postMessage(...args);
    }
    terminate() {
        this.#rejectReady(new Error('Pthread initialization cancelled'));
        this.#load = null;
        pthreadWorkers.delete(this);
        super.terminate();
    }
};

function fail(code, message) {
    const error = new Error(message);
    error.code = code;
    return error;
}
function post(message) { self.postMessage({abi: ABI, ...message}); }
function progress(stage, loadedBytes = 0, totalBytes = 0) {
    post({type: 'progress', stage, loadedBytes, totalBytes});
}

async function instantiateRuntime(imports, receive) {
    // Finish bootstrapping child scripts before starting streaming compilation.
    // Early child failures must not race an in-flight WASM compiler/termination.
    progress('initializing-workers');
    await Promise.all([...pthreadWorkers].map(worker => worker.ready));
    if (state === 'failed') { throw fail('E_LOAD', 'Runtime initialization cancelled'); }
    progress('downloading-wasm');
    wasmDownload = new AbortController();
    const response = await fetch(new URL('./fluent-bit-runtime.wasm', import.meta.url),
                                 {signal: wasmDownload.signal});
    if (!response.ok || !response.body) {
        throw fail('E_LOAD', `WASM download failed (HTTP ${response.status})`);
    }
    const totalBytes = response.headers.get('Content-Encoding') ? 0 :
        Number(response.headers.get('Content-Length')) || 0;
    const reader = response.body.getReader();
    let loadedBytes = 0;
    let lastProgress = 0;
    const stream = new ReadableStream({
        async pull(controller) {
            try {
                const {done, value} = await reader.read();
                if (done) {
                    progress('compiling-wasm', loadedBytes, totalBytes);
                    controller.close();
                    return;
                }
                loadedBytes += value.byteLength;
                const now = performance.now();
                if (now - lastProgress >= 250 || loadedBytes === totalBytes) {
                    progress('downloading-wasm', loadedBytes, totalBytes);
                    lastProgress = now;
                }
                controller.enqueue(value);
            }
            catch (error) { controller.error(error); }
        },
        cancel(reason) { return reader.cancel(reason); }
    });
    // Preserve streaming compilation and backpressure; do not buffer a second WASM copy.
    const result = await WebAssembly.instantiateStreaming(
        new Response(stream, {headers: response.headers}), imports);
    progress('initializing-workers', loadedBytes, totalBytes);
    receive(result.instance, result.module);
}
function flushLogs() {
    clearTimeout(logTimer);
    logTimer = null;
    if (logInFlight || (!logs.length && !dropped)) { return; }
    logInFlight = true;
    post({type: 'logs', entries: logs, dropped});
    logs = [];
    dropped = 0;
    logBytes = 0;
}
async function drainLogs() {
    flushLogs();
    if (logInFlight || logs.length || dropped) {
        await new Promise(resolve => logDrains.push(resolve));
    }
}
function log(stream, value) {
    const raw = String(value);
    const text = raw.length > 4096 ? raw.slice(0, 4096) + ' [truncated]' : raw;
    const size = text.length * 2;
    if (logs.length >= 256 || logBytes + size > 65536) { dropped++; }
    else { logs.push({stream, text}); logBytes += size; }
    if (logTimer === null) { logTimer = setTimeout(flushLogs, 16); }
}
async function fatal(message, code = 'E_RUNTIME') {
    if (state === 'failed' || state === 'destroyed') { return; }
    state = 'failed';
    wasmDownload?.abort();
    await Promise.all([...pthreadWorkers].map(worker => worker.shutdown()));
    preparedWorkers.clear();
    // Finish cancelling streaming compilation before the owner terminates us.
    // Otherwise an early pthread error can leave a streaming WASM task alive.
    if (wasmInitialization) { await wasmInitialization.catch(() => {}); }
    releaseStorage?.();
    flushLogs();
    post({type: 'fatal', code, message: String(message)});
    // Nothing can recover this runtime; release the worker's own event loop.
    self.close();
}

async function lockStorage(namespace) {
    if (!self.navigator.locks) {
        throw fail('E_UNSUPPORTED', 'Persistent storage requires the Web Locks API');
    }
    await new Promise((resolve, reject) => {
        self.navigator.locks.request(`fluent-bit:${namespace}`, {ifAvailable: true}, async lock => {
            if (!lock) { reject(fail('E_STORAGE_BUSY', 'Storage namespace is already in use')); return; }
            await new Promise(release => { releaseStorage = release; resolve(); });
        }).catch(reject);
    });
}

async function initialize(options) {
    progress('loading-runtime');
    const {default: createRuntime} = await import('./fluent-bit-runtime.js');
    const persistent = options.storage.persistent;
    const path = persistent ? `/flb-${options.storage.namespace}` : '/storage';
    if (persistent) { await lockStorage(options.storage.namespace); }
    // Bootstrap one script at a time, before creating Emscripten's runtime.
    // Cancelling sibling module loads after an early failure can retain nested
    // workers in Chromium even after terminate(). Emscripten reuses this exact
    // pool when its factory constructs the corresponding named workers.
    const pthreadUrl = new URL('./fluent-bit-pthread.js', import.meta.url).href;
    progress('initializing-workers');
    const pool = [];
    for (let index = 0; index < PTHREAD_POOL_SIZE; index++) {
        const worker = new self.Worker(pthreadUrl, {type: 'module', name: `em-pthread-${index + 1}`});
        pool.push(worker);
        await worker.ready;
        if (state === 'failed') { return; }
    }
    pool.forEach((worker, index) => preparedWorkers.set(`em-pthread-${index + 1}`, worker));
    let ready;
    const started = new Promise(resolve => { ready = resolve; });
    runtime = await createRuntime({
        instantiateWasm: (imports, receive) => {
            wasmInitialization = instantiateRuntime(imports, receive);
            wasmInitialization.catch(error => fatal(`WASM initialization failed: ${error.message}`));
            return {};
        },
        onRuntimeInitialized: () => progress('starting-command-thread'),
        locateFile: file => new URL(file, import.meta.url).href,
        mainScriptUrlOrBlob: pthreadUrl,
        flbStoragePersistent: persistent,
        flbStoragePath: path,
        print: text => log('stdout', text),
        printErr: text => log('stderr', text),
        onAbort: fatal,
        onSdkReady: (abi, engineVersion) => ready({abi, engineVersion}),
        onSdkResult: (id, result, engineMs) => {
            if (!active || active.id !== id) { fatal('Unexpected engine response'); return; }
            const request = active;
            active = null;
            request.resolve({result, engineMs});
        },
        onExit: code => {
            if (active?.operation === 4 && code === 0) {
                const request = active;
                active = null;
                request.resolve({result: 0});
            }
            else { fatal(`Engine runtime exited unexpectedly (${code})`); }
        }
    });
    const info = await started;
    if (info.abi !== ABI) { throw fail('E_ABI', 'SDK and WASM ABI versions do not match'); }
    runtime.FS.mkdirTree('/config');
    state = 'ready';
    post({type: 'ready', info: {...info, storagePath: path, persistent}});
}

function command(id, operation, data = new Uint8Array(), name = '', grace = 5) {
    if (active) { throw fail('E_BUSY', 'An engine command is already active'); }
    let dataPointer = 0;
    let namePointer = 0;
    return new Promise((resolve, reject) => {
        try {
            if (data.byteLength) {
                dataPointer = runtime._malloc(data.byteLength);
                if (!dataPointer) { throw fail('E_MEMORY', 'Unable to allocate command payload'); }
                runtime.HEAPU8.set(data, dataPointer);
            }
            if (name) {
                const bytes = encoder.encode(name + '\0');
                namePointer = runtime._malloc(bytes.byteLength);
                if (!namePointer) { throw fail('E_MEMORY', 'Unable to allocate input name'); }
                runtime.HEAPU8.set(bytes, namePointer);
            }
            active = {id, operation, resolve, reject};
            if (runtime._flb_wasm_sdk_submit(id, operation, namePointer,
                                             dataPointer, data.byteLength, grace) !== 0) {
                active = null;
                throw fail('E_BUSY', 'Engine rejected the command');
            }
            // C now owns both allocations.
            dataPointer = 0;
            namePointer = 0;
        }
        catch (error) {
            if (dataPointer) { runtime._free(dataPointer); }
            if (namePointer) { runtime._free(namePointer); }
            reject(error);
        }
    });
}

async function execute(request) {
    const {id, method, payload} = request;
    let response;
    if (method === 'getStats') {
        return {wasmMemoryBytes: runtime.HEAPU8.buffer.byteLength,
            activeHttpRequests: runtime.flbBrowserHttp.pending(),
            acceptedBytes, acceptedRecords, checkpointRequired, checkpointFailures, lastCheckpointTime};
    }
    if (method === 'start') {
        if (!['ready', 'stopped'].includes(state)) { throw fail('E_STATE', 'Engine is not stopped'); }
        if (checkpointRequired) { throw fail('E_STORAGE', 'Retry syncStorage() before restarting'); }
        // Failed engine initialization can also modify restored chunk files.
        checkpointRequired = runtime.flbStorage.persistent;
        response = await command(id, 1, payload.yaml, '', payload.grace);
        if (response.result !== 0) { throw fail('E_CONFIG', 'Engine startup failed; inspect stderr'); }
        state = 'running';
        return {engineMs: response.engineMs};
    }
    if (method === 'stop') {
        response = await command(id, 2);
        state = 'stopped';
        if (response.result !== 0) { throw fail('E_SHUTDOWN', 'Engine shutdown failed'); }
        if (runtime.flbBrowserHttp.pending() !== 0) { throw fail('E_SHUTDOWN', 'HTTP requests remain active'); }
        await checkpoint();
        await drainLogs();
        return null;
    }
    if (method === 'push') {
        if (state !== 'running') { throw fail('E_STATE', 'Engine is not running'); }
        response = await command(id, 3, payload.data, payload.input);
        if (response.result === -2) { throw fail('E_INPUT', 'Select a unique alias of a configured lib input'); }
        if (response.result < 0) { throw fail('E_INGEST', 'Input did not accept the batch'); }
        if (response.result !== payload.data.byteLength) {
            // A partially accepted JSON batch cannot safely be replayed.
            throw fail('E_PARTIAL_WRITE', 'Input accepted a partial batch; destroy this instance');
        }
        acceptedBytes += response.result;
        acceptedRecords += payload.count;
        return {acceptedBytes: response.result, acceptedRecords: payload.count};
    }
    if (state === 'running') { throw fail('E_STATE', 'Stop the engine before filesystem operations'); }
    if (method === 'writeFile') {
        const total = fileBytes - (files.get(payload.path) || 0) + payload.data.byteLength;
        if (total > 8 * 1024 * 1024 || (!files.has(payload.path) && files.size >= 32)) {
            throw fail('E_LIMIT', 'SDK asset storage limit exceeded');
        }
        runtime.FS.mkdirTree(payload.path.slice(0, payload.path.lastIndexOf('/')));
        runtime.FS.writeFile(payload.path, payload.data);
        files.set(payload.path, payload.data.byteLength);
        fileBytes = total;
        return null;
    }
    if (method === 'readFile') {
        if (runtime.FS.stat(payload.path).size > 1024 * 1024) { throw fail('E_LIMIT', 'File exceeds SDK read limit'); }
        return runtime.FS.readFile(payload.path);
    }
    if (method === 'syncStorage') {
        await checkpoint();
        return null;
    }
    if (method === 'destroy') {
        await command(id, 4);
        releaseStorage?.();
        state = 'destroyed';
        return null;
    }
    throw fail('E_PROTOCOL', 'Unknown SDK operation');
}

let executing = false;
self.onmessage = async ({data}) => {
    if (!data || data.abi !== ABI) { fatal('SDK message ABI mismatch'); return; }
    if (data.type === 'log-ack') {
        logInFlight = false;
        flushLogs();
        if (!logInFlight && !logs.length && !dropped) {
            const waiting = logDrains;
            logDrains = [];
            waiting.forEach(resolve => resolve());
        }
        return;
    }
    if (data.type === 'init' && !initialized) {
        initialized = true;
        try { await initialize(data.options); }
        catch (error) { await fatal(error.message, error.code || 'E_LOAD'); }
        return;
    }
    if (data.type !== 'request' || !Number.isSafeInteger(data.id) || executing || !runtime) {
        fatal('Invalid or concurrent SDK request');
        return;
    }
    executing = true;
    try {
        const value = await execute(data);
        post({type: 'response', id: data.id, ok: true, value});
    }
    catch (error) {
        await drainLogs();
        post({type: 'response', id: data.id, ok: false,
              code: error.code?.startsWith('E_') ? error.code : 'E_FILESYSTEM', message: error.message});
    }
    finally { executing = false; }
};
self.addEventListener('unhandledrejection', event => { event.preventDefault(); fatal(event.reason); });
