/* SPDX-License-Identifier: Apache-2.0 */
export const SDK_VERSION = '0.1.0-experimental';
const ABI = 1;
const MAX_PAYLOAD = 1024 * 1024;
const MAX_HEADERS = 64;
const encoder = new TextEncoder();
const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

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
function inputAlias(value) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9_.-]{1,128}$/.test(value)) {
        throw error('E_ARGUMENT', 'input must be the alias of an input in external source mode');
    }
    return value;
}
// One buffer for the whole request, so one size check bounds body and context.
// Layout (little endian): method, path, header count and body lengths, then
// method, path, each header as name length, value length, name, value, body.
function serializeRequest(method, path, headers, body) {
    const parts = [encoder.encode(method), encoder.encode(path)];
    let size = 16 + parts[0].byteLength + parts[1].byteLength + body.byteLength;
    for (const [name, value] of headers) {
        const pair = [encoder.encode(name), encoder.encode(value)];
        parts.push(...pair);
        size += 8 + pair[0].byteLength + pair[1].byteLength;
    }
    if (size > MAX_PAYLOAD) { throw error('E_LIMIT', `request exceeds ${MAX_PAYLOAD} bytes`); }
    const data = new Uint8Array(size);
    const view = new DataView(data.buffer);
    view.setUint32(0, parts[0].byteLength, true);
    view.setUint32(4, parts[1].byteLength, true);
    view.setUint32(8, headers.length, true);
    view.setUint32(12, body.byteLength, true);
    let offset = 16;
    for (const part of parts.slice(0, 2)) { data.set(part, offset); offset += part.byteLength; }
    for (let index = 2; index < parts.length; index += 2) {
        view.setUint32(offset, parts[index].byteLength, true);
        view.setUint32(offset + 4, parts[index + 1].byteLength, true);
        offset += 8;
        data.set(parts[index], offset);
        offset += parts[index].byteLength;
        data.set(parts[index + 1], offset);
        offset += parts[index + 1].byteLength;
    }
    data.set(body, offset);
    return data;
}
function requestHeaders(value) {
    if (value === undefined) { return []; }
    const entries = Array.isArray(value) ? value :
        (value && typeof value === 'object' ? Object.entries(value) : null);
    if (!entries || entries.length > MAX_HEADERS) {
        throw error('E_ARGUMENT', `headers must be an object or a list of at most ${MAX_HEADERS} pairs`);
    }
    return entries.map(entry => {
        if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== 'string' ||
            typeof entry[1] !== 'string' || !TOKEN.test(entry[0]) || !entry[1] ||
            /[\u0000-\u0008\u000a-\u001f\u007f]/.test(entry[1])) {
            throw error('E_ARGUMENT', 'headers must be name and value text without control characters');
        }
        return [entry[0], entry[1]];
    });
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
    #workerClosed = false;
    #terminationTimer;
    #options;
    #state = 'loading';
    #info;
    #pending = null;
    #replies = new Map();
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
        if (state === this.#state || this.#state === 'destroyed' ||
            (this.#state === 'failed' && state !== 'destroyed')) { return; }
        this.#state = state;
        this.#callback('onStateChange', state);
    }
    #terminateWorker() {
        if (this.#workerClosed) {
            // Give self-close time to finish before enforcing the fallback.
            // Immediate termination can interrupt nested worker cleanup.
            if (this.#terminationTimer === undefined) {
                this.#terminationTimer = setTimeout(() => this.#worker?.terminate(), 250);
            }
        }
        else { this.#worker?.terminate(); }
    }
    #fatal(failure) {
        if (['failed', 'destroyed'].includes(this.#state)) { return; }
        clearTimeout(this.#loadTimer);
        this.#detachAbort();
        this.#terminateWorker();
        this.#setState('failed');
        this.#rejectReady(failure);
        if (this.#pending) {
            clearTimeout(this.#pending.timer);
            this.#pending.reject(failure);
            this.#pending = null;
        }
        this.#settleReplies(failure);
        this.#callback('onError', failure);
    }
    // Requests still waiting for a reply are settled when the engine goes away.
    #settleReplies(failure) {
        const waiting = [...this.#replies.values()];
        this.#replies.clear();
        waiting.forEach(waiter => waiter.reject(failure));
    }
    #reply(message) {
        if (!Number.isSafeInteger(message.id) || ![0, 1, 2].includes(message.outcome) ||
            !Number.isSafeInteger(message.status) || typeof message.truncated !== 'boolean' ||
            !Array.isArray(message.headers) || !(message.body instanceof Uint8Array) ||
            message.headers.some(header => !Array.isArray(header) || header.length !== 2 ||
                typeof header[0] !== 'string' || typeof header[1] !== 'string')) {
            this.#fatal(error('E_PROTOCOL', 'Invalid SDK request reply'));
            return;
        }
        // A reply is delivered once; unknown and repeated ids are ignored.
        const waiter = this.#replies.get(message.id);
        if (!waiter) { return; }
        this.#replies.delete(message.id);
        if (message.outcome === 0) {
            waiter.resolve(Object.freeze({status: message.status,
                headers: Object.freeze(message.headers.map(header => Object.freeze([...header]))),
                body: message.body, truncated: message.truncated}));
        }
        else if (message.outcome === 1) {
            waiter.reject(error('E_REQUEST_FAILED',
                'The input processed the request without a reply; do not submit it again'));
        }
        else { waiter.reject(error('E_STOPPED', 'The engine stopped before the request was processed')); }
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
            this.#workerClosed = message.closed === true;
            this.#fatal(error(message.code || 'E_RUNTIME', message.message));
        }
        else if (message.type === 'reply') { this.#reply(message); }
        else if (message.type === 'response' && this.#pending?.id === message.id) {
            if (typeof message.ok !== 'boolean' || (!message.ok &&
                (typeof message.code !== 'string' || typeof message.message !== 'string'))) {
                this.#fatal(error('E_PROTOCOL', 'Invalid SDK command response'));
                return;
            }
            const pending = this.#pending;
            this.#pending = null;
            clearTimeout(pending.timer);
            if (message.ok) {
                // A terminal reply confirms that the owner called self.close().
                // Interrupting it with terminate() can retain nested Chromium workers.
                if (pending.method === 'destroy' && message.closed === true) {
                    this.#workerClosed = true;
                }
                pending.resolve(message.value);
            }
            else {
                const failure = error(message.code, message.message);
                pending.reject(failure);
                if (['E_PARTIAL_WRITE', 'E_SHUTDOWN'].includes(message.code)) { this.#fatal(failure); }
            }
        }
        else { this.#fatal(error('E_PROTOCOL', 'Unexpected SDK response')); }
    }
    #send(method, payload = {}, register = null) {
        if (['failed', 'destroyed'].includes(this.#state)) {
            return Promise.reject(error('E_STATE', `SDK instance is ${this.#state}`));
        }
        const id = ++this.#sequence;
        if (id > 2147483647) { return Promise.reject(error('E_LIMIT', 'Command sequence exhausted')); }
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => this.#fatal(error('E_TIMEOUT', `${method} timed out; runtime terminated`)),
                                     this.#options.operationTimeoutMs);
            this.#pending = {id, method, resolve, reject, timer};
            // A waiter is in place before the command leaves, so a reply
            // cannot arrive ahead of it.
            register?.(id);
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
                if (['failed', 'destroyed'].includes(this.#state)) {
                    throw error('E_STATE', 'SDK instance is unavailable');
                }
                this.#setState('running');
                return result;
            }
            catch (failure) {
                if (!['failed', 'destroyed'].includes(this.#state)) { this.#setState('stopped'); }
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
        finally {
            this.#settleReplies(error('E_STOPPED', 'The engine stopped before the request was answered'));
            if (!['failed', 'destroyed'].includes(this.#state)) { this.#setState('stopped'); }
        }
    }
    stop() { return this.#enqueue(() => this.#stop()); }

    drain() {
        return this.#enqueue(() => {
            if (this.#state !== 'running') { throw error('E_STATE', 'Engine is not running'); }
            return this.#send('drain');
        });
    }

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
    async pushBytes(options) {
        object(options, 'pushBytes options');
        const input = inputAlias(options.input);
        const data = bytes(options.data, MAX_PAYLOAD, 'data');
        if (!data.byteLength) { throw error('E_ARGUMENT', 'data must not be empty'); }
        return this.#enqueue(() => {
            if (this.#state !== 'running') { throw error('E_STATE', 'Engine is not running'); }
            return this.#send('pushBytes', {input, data});
        }, data.byteLength);
    }
    async request(options) {
        object(options, 'request options');
        const input = inputAlias(options.input);
        const method = options.method ?? 'POST';
        if (typeof method !== 'string' || !TOKEN.test(method) || method.length > 16) {
            throw error('E_ARGUMENT', 'method must be an HTTP method name');
        }
        if (typeof options.path !== 'string' || !/^\/[\x21-\x7e]*$/.test(options.path)) {
            throw error('E_ARGUMENT', 'path must start with / and contain no spaces');
        }
        const headers = requestHeaders(options.headers);
        // Handlers expect the Host header a client would always send.
        if (!headers.some(header => header[0].toLowerCase() === 'host')) {
            if (headers.length >= MAX_HEADERS) { throw error('E_ARGUMENT', 'too many headers'); }
            headers.push(['Host', 'localhost']);
        }
        const body = options.body === undefined ? new Uint8Array() :
            bytes(options.body, MAX_PAYLOAD, 'body');
        const data = serializeRequest(method, options.path, headers, body);
        let waiter;
        let requestId;
        const reply = new Promise((resolve, reject) => { waiter = {resolve, reject}; });
        reply.catch(() => {});
        // The queued action ends at admission. Waiting for the reply inside it
        // would keep later commands, stop() included, behind a paused input.
        await this.#enqueue(async () => {
            if (this.#state !== 'running') { throw error('E_STATE', 'Engine is not running'); }
            try {
                await this.#send('request', {input, data}, id => {
                    requestId = id;
                    this.#replies.set(id, waiter);
                });
            }
            catch (failure) {
                this.#replies.delete(requestId);
                throw failure;
            }
        }, data.byteLength);
        return reply;
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
                this.#settleReplies(error('E_DESTROYED', 'SDK instance was destroyed'));
                this.#terminateWorker();
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
