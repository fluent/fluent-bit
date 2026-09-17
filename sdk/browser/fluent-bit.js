/* SPDX-License-Identifier: Apache-2.0 */
export const SDK_VERSION = '0.1.0-experimental';
const ABI = 1;
const MAX_PAYLOAD = 1024 * 1024;
const encoder = new TextEncoder();

export class FluentBitError extends Error {
    constructor(code, message) {
        super(message);
        this.name = 'FluentBitError';
        this.code = code;
    }
}
function error(code, message) { return new FluentBitError(code, message); }
function integer(value, min, max, name) {
    if (!Number.isInteger(value) || value < min || value > max) {
        throw error('E_ARGUMENT', `${name} must be an integer between ${min} and ${max}`);
    }
    return value;
}
function object(value, name) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        throw error('E_ARGUMENT', `${name} must be an object`);
    }
}
function bytes(value, maximum, name) {
    let result;
    if (typeof value === 'string') {
        if (value.length > maximum) { throw error('E_LIMIT', `${name} exceeds ${maximum} bytes`); }
        result = encoder.encode(value);
    }
    else if (value instanceof Uint8Array) {
        if (value.byteLength > maximum) { throw error('E_LIMIT', `${name} exceeds ${maximum} bytes`); }
        result = value.slice();
    }
    else { throw error('E_ARGUMENT', `${name} must be a string or Uint8Array`); }
    if (result.byteLength > maximum) { throw error('E_LIMIT', `${name} exceeds ${maximum} bytes`); }
    return result;
}
function assetPath(path) {
    if (typeof path !== 'string' || path.length > 240 || !path.startsWith('/config/') ||
        path.slice(8).split('/').some(part => !/^[A-Za-z0-9_-][A-Za-z0-9_.-]*$/.test(part))) {
        throw error('E_ARGUMENT', 'File paths must name an asset beneath /config/ without traversal');
    }
    return path;
}

export function getBrowserSupport() {
    const missing = [];
    if (!globalThis.isSecureContext) { missing.push('secure context (HTTPS or localhost)'); }
    if (!globalThis.crossOriginIsolated) { missing.push('cross-origin isolation (COOP/COEP)'); }
    for (const [name, kind] of [['WebAssembly', 'object'], ['Worker', 'function'],
                               ['SharedArrayBuffer', 'function']]) {
        if (typeof globalThis[name] !== kind) { missing.push(name); }
    }
    return {supported: missing.length === 0, missing};
}

class FluentBit {
    #worker;
    #options;
    #state = 'loading';
    #info;
    #pending = null;
    #sequence = 0;
    #tail = Promise.resolve();
    #queued = 0;
    #queuedBytes = 0;
    #rejectedCommands = 0;
    #droppedLogLines = 0;
    #closing = false;
    #destroyPromise;
    #ready;
    #resolveReady;
    #rejectReady;
    #loadTimer;
    #detachAbort = () => {};

    constructor(options, workerUrl) {
        this.#options = options;
        this.#ready = new Promise((resolve, reject) => {
            this.#resolveReady = resolve;
            this.#rejectReady = reject;
        });
        try {
            this.#worker = new Worker(workerUrl, {type: 'module', name: 'fluent-bit'});
            this.#worker.onmessage = event => this.#message(event.data);
            this.#worker.onerror = event => {
                event.preventDefault();
                this.#fatal(error('E_WORKER', event.message || 'SDK worker failed to load'));
            };
            this.#worker.onmessageerror = () => this.#fatal(error('E_PROTOCOL', 'Invalid worker response'));
            this.#loadTimer = setTimeout(() => this.#fatal(error('E_TIMEOUT', 'SDK initialization timed out')),
                                         options.initTimeoutMs);
            if (options.signal) {
                const abort = () => this.#fatal(error('E_ABORTED', 'SDK initialization was aborted'));
                options.signal.addEventListener('abort', abort, {once: true});
                this.#detachAbort = () => options.signal.removeEventListener('abort', abort);
                if (options.signal.aborted) { abort(); return; }
            }
            this.#worker.postMessage({abi: ABI, type: 'init', options: {storage: options.storage}});
        }
        catch (cause) { this.#fatal(error('E_WORKER', `Unable to create SDK worker: ${cause.message}`)); }
    }
    get state() { return this.#state; }
    get info() { return this.#info; }
    async ready() { await this.#ready; return this; }

    #callback(name, value) {
        const handler = this.#options[name];
        if (!handler) { return; }
        const failed = () => {
            if (name !== 'onError') { this.#callback('onError', error('E_CALLBACK', `${name} callback failed`)); }
        };
        try { Promise.resolve(handler(value)).catch(failed); }
        catch (_) { failed(); }
    }
    #setState(state) {
        if (state === this.#state) { return; }
        this.#state = state;
        this.#callback('onStateChange', state);
    }
    #fatal(failure) {
        if (['failed', 'destroyed'].includes(this.#state)) { return; }
        clearTimeout(this.#loadTimer);
        this.#detachAbort();
        this.#worker?.terminate();
        this.#setState('failed');
        this.#rejectReady(failure);
        if (this.#pending) {
            clearTimeout(this.#pending.timer);
            this.#pending.reject(failure);
            this.#pending = null;
        }
        this.#callback('onError', failure);
    }
    #message(message) {
        if (['failed', 'destroyed'].includes(this.#state)) { return; }
        if (!message || message.abi !== ABI) { this.#fatal(error('E_ABI', 'SDK ABI mismatch')); return; }
        if (message.type === 'progress') {
            if (!['loading-runtime', 'downloading-wasm', 'compiling-wasm',
                  'initializing-workers', 'starting-command-thread'].includes(message.stage) ||
                !Number.isSafeInteger(message.loadedBytes) || message.loadedBytes < 0 ||
                !Number.isSafeInteger(message.totalBytes) || message.totalBytes < 0) {
                this.#fatal(error('E_PROTOCOL', 'Invalid SDK startup progress'));
                return;
            }
            if (this.#state === 'loading') {
                this.#callback('onProgress', Object.freeze({stage: message.stage,
                    loadedBytes: message.loadedBytes, totalBytes: message.totalBytes}));
            }
        }
        else if (message.type === 'logs') {
            if (!Array.isArray(message.entries) || message.entries.length > 256 ||
                !Number.isSafeInteger(message.dropped) || message.dropped < 0 ||
                message.entries.some(entry => !entry || !['stdout', 'stderr'].includes(entry.stream) ||
                    typeof entry.text !== 'string' || entry.text.length > 4120)) {
                this.#fatal(error('E_PROTOCOL', 'Invalid SDK log batch'));
                return;
            }
            for (const entry of message.entries) {
                this.#callback(entry.stream === 'stdout' ? 'onStdout' : 'onStderr', entry.text);
            }
            if (message.dropped) {
                this.#droppedLogLines += message.dropped;
                this.#callback('onError', error('E_LOG_DROPPED', `${message.dropped} log lines dropped by SDK limits`));
            }
            this.#worker.postMessage({abi: ABI, type: 'log-ack'});
        }
        else if (message.type === 'ready' && this.#state === 'loading') {
            if (message.info?.abi !== ABI || typeof message.info.engineVersion !== 'string') {
                this.#fatal(error('E_ABI', 'Invalid engine handshake'));
                return;
            }
            clearTimeout(this.#loadTimer);
            this.#detachAbort();
            this.#info = Object.freeze({...message.info, sdkVersion: SDK_VERSION});
            this.#setState('ready');
            this.#resolveReady();
        }
        else if (message.type === 'fatal') {
            this.#fatal(error(message.code || 'E_RUNTIME', message.message));
        }
        else if (message.type === 'response' && this.#pending?.id === message.id) {
            if (typeof message.ok !== 'boolean' || (!message.ok &&
                (typeof message.code !== 'string' || typeof message.message !== 'string'))) {
                this.#fatal(error('E_PROTOCOL', 'Invalid SDK command response'));
                return;
            }
            const pending = this.#pending;
            this.#pending = null;
            clearTimeout(pending.timer);
            if (message.ok) { pending.resolve(message.value); }
            else {
                const failure = error(message.code, message.message);
                pending.reject(failure);
                if (['E_PARTIAL_WRITE', 'E_SHUTDOWN'].includes(message.code)) { this.#fatal(failure); }
            }
        }
        else { this.#fatal(error('E_PROTOCOL', 'Unexpected SDK response')); }
    }
    #send(method, payload = {}) {
        if (['failed', 'destroyed'].includes(this.#state)) {
            return Promise.reject(error('E_STATE', `SDK instance is ${this.#state}`));
        }
        const id = ++this.#sequence;
        if (id > 2147483647) { return Promise.reject(error('E_LIMIT', 'Command sequence exhausted')); }
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => this.#fatal(error('E_TIMEOUT', `${method} timed out; runtime terminated`)),
                                     this.#options.operationTimeoutMs);
            this.#pending = {id, resolve, reject, timer};
            try { this.#worker.postMessage({abi: ABI, type: 'request', id, method, payload}); }
            catch (_) { this.#fatal(error('E_PROTOCOL', 'Unable to send SDK command')); }
        });
    }
    #enqueue(action, size = 0) {
        if (this.#closing || ['failed', 'destroyed'].includes(this.#state)) {
            return Promise.reject(error('E_STATE', 'SDK instance is closing or unavailable'));
        }
        if (this.#queued >= 16 || this.#queuedBytes + size > 8 * MAX_PAYLOAD) {
            this.#rejectedCommands++;
            return Promise.reject(error('E_BACKPRESSURE', 'SDK command queue is full'));
        }
        this.#queued++;
        this.#queuedBytes += size;
        const operation = this.#tail.then(() => {
            if (['failed', 'destroyed'].includes(this.#state)) { throw error('E_STATE', 'SDK instance is unavailable'); }
            return action();
        });
        this.#tail = operation.catch(() => {}).finally(() => {
            this.#queued--;
            this.#queuedBytes -= size;
        });
        return operation;
    }

    async start(options) {
        object(options, 'start options');
        if (typeof options.yaml !== 'string' || !options.yaml.trim() || options.yaml.includes('\0')) {
            throw error('E_ARGUMENT', 'yaml must be nonempty text without NUL bytes');
        }
        const yaml = bytes(options.yaml, 65536, 'yaml');
        const grace = integer(options.graceSeconds ?? 5, 0, 30, 'graceSeconds');
        return this.#enqueue(async () => {
            if (!['ready', 'stopped'].includes(this.#state)) { throw error('E_STATE', 'Stop before starting again'); }
            this.#setState('starting');
            try {
                const result = await this.#send('start', {yaml, grace});
                this.#setState('running');
                return result;
            }
            catch (failure) {
                if (this.#state !== 'failed') { this.#setState('stopped'); }
                throw failure;
            }
        }, yaml.byteLength);
    }
    async #stop() {
        if (['failed', 'destroyed'].includes(this.#state)) {
            throw error('E_STATE', 'SDK instance is unavailable');
        }
        this.#setState('stopping');
        try { await this.#send('stop'); }
        finally { if (this.#state !== 'failed') { this.#setState('stopped'); } }
    }
    stop() { return this.#enqueue(() => this.#stop()); }

    async push(options) {
        object(options, 'push options');
        if (typeof options.input !== 'string' || !/^[A-Za-z0-9_.-]{1,128}$/.test(options.input)) {
            throw error('E_ARGUMENT', 'input must be a lib input alias');
        }
        if (!Array.isArray(options.records) || options.records.length < 1 || options.records.length > 1000) {
            throw error('E_ARGUMENT', 'records must contain between 1 and 1000 JSON objects');
        }
        let json;
        try {
            const now = Date.now() / 1000;
            let length = 0;
            json = options.records.map(record => {
                object(record, 'record');
                const text = JSON.stringify(record);
                const parsed = JSON.parse(text);
                object(parsed, 'serialized record');
                const event = `[${now},${text}]`;
                length += event.length;
                if (length > MAX_PAYLOAD) { throw error('E_LIMIT', 'Batch exceeds SDK size limit'); }
                return event;
            }).join('');
        }
        catch (cause) {
            if (cause.code === 'E_LIMIT') { throw cause; }
            throw error('E_ARGUMENT', 'Records must be JSON-serializable objects');
        }
        const data = bytes(json, MAX_PAYLOAD, 'batch');
        const input = options.input;
        const count = options.records.length;
        return this.#enqueue(() => this.#send('push', {input, data, count}), data.byteLength);
    }
    async writeFile(path, value) {
        path = assetPath(path);
        const data = bytes(value, MAX_PAYLOAD, 'file');
        return this.#enqueue(() => this.#send('writeFile', {path, data}), data.byteLength);
    }
    async readFile(path) {
        path = assetPath(path);
        return this.#enqueue(() => this.#send('readFile', {path}));
    }
    syncStorage() { return this.#enqueue(() => this.#send('syncStorage')); }
    getStats() {
        return this.#enqueue(async () => Object.freeze({...await this.#send('getStats'),
            state: this.#state, queuedCommands: this.#queued, queuedBytes: this.#queuedBytes,
            rejectedCommands: this.#rejectedCommands, droppedLogLines: this.#droppedLogLines}));
    }

    destroy(options = {}) {
        if (this.#destroyPromise) { return this.#destroyPromise; }
        if (!options || typeof options !== 'object' || Array.isArray(options) ||
            (options.force !== undefined && typeof options.force !== 'boolean')) {
            return Promise.reject(error('E_ARGUMENT', 'force must be boolean'));
        }
        this.#closing = true;
        this.#destroyPromise = (async () => {
            let timer;
            try {
                if (options.force || ['failed', 'destroyed'].includes(this.#state)) { return; }
                const deadline = new Promise((_, reject) => {
                    timer = setTimeout(() => {
                        const failure = error('E_TIMEOUT', 'Destroy deadline exceeded; data may not be flushed');
                        this.#fatal(failure);
                        reject(failure);
                    }, this.#options.destroyTimeoutMs);
                });
                await Promise.race([this.#tail.then(async () => {
                    await this.#stop();
                    await this.#send('destroy');
                }), deadline]);
            }
            finally {
                clearTimeout(timer);
                if (this.#pending) {
                    clearTimeout(this.#pending.timer);
                    this.#pending.reject(error('E_DESTROYED', 'SDK instance was destroyed'));
                    this.#pending = null;
                }
                this.#worker?.terminate();
                this.#setState('destroyed');
            }
        })();
        return this.#destroyPromise;
    }
}

export async function createFluentBit(options = {}) {
    object(options, 'options');
    const support = getBrowserSupport();
    if (!support.supported) { throw error('E_UNSUPPORTED', `Browser requirements missing: ${support.missing.join(', ')}`); }
    for (const key of ['onStdout', 'onStderr', 'onStateChange', 'onError', 'onProgress']) {
        if (options[key] !== undefined && typeof options[key] !== 'function') {
            throw error('E_ARGUMENT', `${key} must be a function`);
        }
    }
    const storage = options.storage ?? {persistent: false};
    object(storage, 'storage');
    if (storage.persistent !== undefined && typeof storage.persistent !== 'boolean') {
        throw error('E_ARGUMENT', 'storage.persistent must be boolean');
    }
    if (storage.persistent && (!/^[A-Za-z0-9_-]{1,64}$/.test(storage.namespace || '') ||
        typeof indexedDB !== 'object')) {
        throw error('E_ARGUMENT', 'Persistent storage requires IndexedDB and an explicit namespace');
    }
    if (options.signal !== undefined && !(options.signal instanceof AbortSignal)) {
        throw error('E_ARGUMENT', 'signal must be an AbortSignal');
    }
    if (options.signal?.aborted) { throw error('E_ABORTED', 'SDK initialization was aborted'); }
    let workerUrl;
    try {
        if (options.workerUrl !== undefined && typeof options.workerUrl !== 'string' &&
            !(options.workerUrl instanceof URL)) {
            throw error('E_ARGUMENT', 'workerUrl must be a string or URL');
        }
        workerUrl = new URL(options.workerUrl ?? './fluent-bit-worker.js', import.meta.url);
    }
    catch (_) { throw error('E_ARGUMENT', 'workerUrl must be a valid string or URL'); }
    if (workerUrl.origin !== globalThis.location.origin || !['http:', 'https:'].includes(workerUrl.protocol)) {
        throw error('E_ARGUMENT', 'Host SDK worker assets on the application origin');
    }
    const instance = new FluentBit({...options,
        storage: {persistent: storage.persistent === true, namespace: storage.namespace},
        initTimeoutMs: integer(options.initTimeoutMs ?? 45000, 100, 120000, 'initTimeoutMs'),
        operationTimeoutMs: integer(options.operationTimeoutMs ?? 45000, 100, 120000, 'operationTimeoutMs'),
        destroyTimeoutMs: integer(options.destroyTimeoutMs ?? 15000, 100, 60000, 'destroyTimeoutMs')
    }, workerUrl);
    return instance.ready();
}
