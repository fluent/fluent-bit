/* SPDX-License-Identifier: Apache-2.0 */
import {test, beforeEach, afterEach} from 'node:test';
import assert from 'node:assert/strict';
import {createFluentBit, getBrowserSupport} from '../../sdk/browser/fluent-bit.js';

const instances = [];
let reply;
class FakeWorker {
    constructor() { this.terminated = false; this.closed = false; instances.push(this); }
    postMessage(message) {
        queueMicrotask(() => {
            if (!this.terminated) { reply(this, message); }
        });
    }
    emit(message) {
        if (message.closed === true) { this.closed = true; }
        this.onmessage?.({data: {abi: 1, ...message}});
    }
    terminate() { this.terminated = true; }
}
const defaults = {workerUrl: 'https://sdk.test/sdk/fluent-bit-worker.js'};
beforeEach(() => {
    Object.assign(globalThis, {Worker: FakeWorker, isSecureContext: true,
        crossOriginIsolated: true, location: {origin: 'https://sdk.test'}});
    instances.length = 0;
    reply = (worker, message) => {
        if (message.type === 'init') {
            worker.emit({type: 'ready', info: {abi: 1, engineVersion: 'test'}});
        }
        if (message.type === 'request') {
            worker.emit({type: 'response', id: message.id, ok: true, value: {engineMs: 1}});
        }
    };
});
afterEach(() => { for (const worker of instances) { assert.equal(worker.terminated || worker.closed, true); } });

test('preflight rejects missing isolation without creating a worker', async () => {
    globalThis.crossOriginIsolated = false;
    assert.equal(getBrowserSupport().supported, false);
    await assert.rejects(createFluentBit(defaults), {code: 'E_UNSUPPORTED'});
    assert.equal(instances.length, 0);
});
test('initialization timeout and abort terminate the worker', async () => {
    reply = () => {};
    await assert.rejects(createFluentBit({...defaults, initTimeoutMs: 100}), {code: 'E_TIMEOUT'});
    const controller = new AbortController();
    const pending = createFluentBit({...defaults, signal: controller.signal});
    controller.abort();
    await assert.rejects(pending, {code: 'E_ABORTED'});
});
test('FIFO lifecycle, immutable info, and idempotent destruction', async () => {
    const sdk = await createFluentBit(defaults);
    assert.equal(Object.isFrozen(sdk.info), true);
    await Promise.all([sdk.start({yaml: 'pipeline: {}'}), sdk.stop(), sdk.start({yaml: 'pipeline: {}'})]);
    assert.equal(sdk.state, 'running');
    const first = sdk.destroy();
    assert.equal(first, sdk.destroy());
    await first;
    assert.equal(sdk.state, 'destroyed');
    await assert.rejects(sdk.stop(), {code: 'E_STATE'});
});
test('invalid arguments never enter the queue', async () => {
    await assert.rejects(createFluentBit({...defaults, workerUrl: 'https://['}), {code: 'E_ARGUMENT'});
    await assert.rejects(createFluentBit({...defaults, workerUrl: 3}), {code: 'E_ARGUMENT'});
    await assert.rejects(createFluentBit({...defaults, workerUrl: 'https://other.test/worker.js'}), {code: 'E_ARGUMENT'});
    const sdk = await createFluentBit(defaults);
    await assert.rejects(sdk.start({yaml: 'a\0b'}), {code: 'E_ARGUMENT'});
    await assert.rejects(sdk.start({yaml: 'x'.repeat(65537)}), {code: 'E_LIMIT'});
    await assert.rejects(sdk.writeFile('/config/a/../b', ''), {code: 'E_ARGUMENT'});
    await assert.rejects(sdk.push({input: 'app', records: [{number: 1n}]}), {code: 'E_ARGUMENT'});
    await assert.rejects(sdk.destroy({force: 'yes'}), {code: 'E_ARGUMENT'});
    await sdk.destroy();
});
test('bounded admission and forced destroy settle every pending request', async () => {
    const sdk = await createFluentBit(defaults);
    reply = () => {};
    const pending = Array.from({length: 16}, () => sdk.writeFile('/config/a', 'x'));
    const settled = Promise.allSettled(pending);
    await assert.rejects(sdk.writeFile('/config/b', 'x'), {code: 'E_BACKPRESSURE'});
    await sdk.destroy({force: true});
    assert.equal((await settled).filter(value => value.status === 'rejected').length, 16);
});
test('operation timeout is terminal and destroy remains bounded', async () => {
    const sdk = await createFluentBit({...defaults, operationTimeoutMs: 100});
    reply = () => {};
    await assert.rejects(sdk.start({yaml: 'pipeline: {}'}), {code: 'E_TIMEOUT'});
    assert.equal(sdk.state, 'failed');
    await sdk.destroy();
});
test('callback failures are isolated and log acknowledgments still flow', async () => {
    const codes = [];
    const sdk = await createFluentBit({...defaults,
        onStdout: async () => { throw new Error('application callback'); },
        onError: value => codes.push(value.code)});
    instances[0].emit({type: 'logs', entries: [{stream: 'stdout', text: 'x'}], dropped: 3});
    await new Promise(resolve => setTimeout(resolve, 0));
    assert.deepEqual(codes.sort(), ['E_CALLBACK', 'E_LOG_DROPPED']);
    await sdk.destroy();
});
test('drain invokes output callbacks without awaiting their asynchronous work', async () => {
    let releaseCallback;
    let callbackDone = false;
    const callback = new Promise(resolve => { releaseCallback = resolve; });
    const sdk = await createFluentBit({...defaults, onStdout: async () => {
        await callback;
        callbackDone = true;
    }});
    await sdk.start({yaml: 'pipeline: {}'});
    let drainRequest;
    reply = (worker, message) => {
        if (message.type === 'request' && message.method === 'drain') {
            drainRequest = message;
            worker.emit({type: 'logs', entries: [{stream: 'stdout', text: 'output'}], dropped: 0});
        }
        else if (message.type === 'log-ack') {
            worker.emit({type: 'response', id: drainRequest.id, ok: true, value: null});
        }
        else if (message.type === 'request') {
            worker.emit({type: 'response', id: message.id, ok: true, value: null});
        }
    };
    await sdk.drain();
    assert.equal(callbackDone, false);
    releaseCallback();
    await new Promise(resolve => setTimeout(resolve, 0));
    assert.equal(callbackDone, true);
    await sdk.destroy();
});
test('ABI mismatch rejects initialization and terminates', async () => {
    reply = worker => worker.emit({abi: 2, type: 'ready'});
    await assert.rejects(createFluentBit(defaults), {code: 'E_ABI'});
});
test('startup progress is validated, immutable, and callback errors are isolated', async () => {
    const updates = [];
    const errors = [];
    reply = worker => {
        worker.emit({type: 'progress', stage: 'downloading-wasm', loadedBytes: 512, totalBytes: 1024});
        worker.emit({type: 'ready', info: {abi: 1, engineVersion: 'test'}});
    };
    const sdk = await createFluentBit({...defaults,
        onProgress: update => { updates.push(update); throw new Error('callback'); },
        onError: error => errors.push(error.code)});
    assert.equal(updates[0].loadedBytes, 512);
    assert.equal(Object.isFrozen(updates[0]), true);
    assert.deepEqual(errors, ['E_CALLBACK']);
    await sdk.destroy({force: true});
    reply = worker => worker.emit({type: 'progress', stage: 'invalid', loadedBytes: -1, totalBytes: 0});
    await assert.rejects(createFluentBit(defaults), {code: 'E_PROTOCOL'});
});
test('checkpoint failure leaves a stopped instance and permits explicit retry', async () => {
    const sdk = await createFluentBit(defaults);
    reply = (worker, message) => {
        if (message.type !== 'request') { return; }
        if (message.method === 'stop') {
            worker.emit({type: 'response', id: message.id, ok: false, code: 'E_STORAGE', message: 'quota'});
        }
        else { worker.emit({type: 'response', id: message.id, ok: true, value: null}); }
    };
    await assert.rejects(sdk.stop(), {code: 'E_STORAGE'});
    assert.equal(sdk.state, 'stopped');
    await sdk.syncStorage();
    await sdk.destroy({force: true});
});
test('malformed messages fail closed without escaping the event handler', async () => {
    const sdk = await createFluentBit(defaults);
    instances[0].emit({type: 'logs', entries: null, dropped: 0});
    assert.equal(sdk.state, 'failed');
    await sdk.destroy();
});
test('queued payloads are copied before callers can mutate them', async () => {
    const sdk = await createFluentBit(defaults);
    const seen = [];
    const original = reply;
    reply = (worker, message) => {
        if (message.method === 'writeFile') { seen.push(message.payload.data[0]); }
        original(worker, message);
    };
    const payload = new Uint8Array([42]);
    const pending = sdk.writeFile('/config/a', payload);
    payload[0] = 7;
    await pending;
    assert.deepEqual(seen, [42]);
    await sdk.destroy();
});
test('destroy deadline bounds a stalled command and rejects all waiters', async () => {
    const sdk = await createFluentBit({...defaults, destroyTimeoutMs: 100});
    reply = () => {};
    const pending = sdk.start({yaml: 'pipeline: {}'});
    const rejection = assert.rejects(pending, {code: 'E_TIMEOUT'});
    await assert.rejects(sdk.destroy(), {code: 'E_TIMEOUT'});
    await rejection;
    assert.equal(sdk.state, 'destroyed');
});

test('oversized assets are rejected before copying caller memory', async () => {
    const sdk = await createFluentBit(defaults);
    const value = new Uint8Array(1024 * 1024 + 1);
    value.slice = () => { throw new Error('Unexpected allocation'); };
    await assert.rejects(sdk.writeFile('/config/large', value), {code: 'E_LIMIT'});
    await sdk.destroy();
});

test('shutdown errors terminate an instance that cannot establish quiescence', async () => {
    const sdk = await createFluentBit(defaults);
    reply = (worker, message) => worker.emit({type: 'response', id: message.id,
        ok: false, code: 'E_SHUTDOWN', message: 'Engine shutdown failed'});
    await assert.rejects(sdk.stop(), {code: 'E_SHUTDOWN'});
    assert.equal(sdk.state, 'failed');
    assert.equal(instances[0].terminated, true);
    await sdk.destroy();
});

test('status exposes immutable queue pressure and dropped-log counters', async () => {
    const sdk = await createFluentBit(defaults);
    const pending = Array.from({length: 16}, () => sdk.writeFile('/config/a', 'x'));
    const settled = Promise.allSettled(pending);
    await assert.rejects(sdk.writeFile('/config/a', 'x'), {code: 'E_BACKPRESSURE'});
    reply = (worker, message) => {
        if (message.type === 'request') worker.emit({type: 'response', id: message.id, ok: true, value: {}});
    };
    await settled;
    instances[0].emit({type: 'logs', entries: [], dropped: 4});
    const stats = await sdk.getStats();
    assert.equal(stats.rejectedCommands, 1);
    assert.equal(stats.droppedLogLines, 4);
    assert.equal(stats.queuedCommands, 1);
    assert.equal(stats.queuedBytes, 0);
    assert.equal(Object.isFrozen(stats), true);
    await sdk.destroy();
});

test('forced destruction during lifecycle callbacks preserves the terminal state', async () => {
    for (const stage of ['starting', 'stopping']) {
        let sdk;
        const states = [];
        sdk = await createFluentBit({...defaults, onStateChange(state) {
            states.push(state);
            if (state === stage) { sdk.destroy({force: true}); }
        }});
        const operation = stage === 'starting' ? sdk.start({yaml: 'pipeline: {}'}) : sdk.stop();
        await assert.rejects(operation, {code: 'E_STATE'});
        assert.equal(sdk.state, 'destroyed');
        assert.equal(states.at(-1), 'destroyed');
        assert.equal(instances.at(-1).terminated, true);
        await assert.rejects(sdk.getStats(), {code: 'E_STATE'});
    }
});

test('forced destruction after a startup response cannot revive the instance', async () => {
    const sdk = await createFluentBit(defaults);
    reply = (worker, message) => {
        if (message.type !== 'request') { return; }
        worker.emit({type: 'response', id: message.id, ok: true, value: {engineMs: 1}});
        sdk.destroy({force: true});
    };
    await assert.rejects(sdk.start({yaml: 'pipeline: {}'}), {code: 'E_STATE'});
    assert.equal(sdk.state, 'destroyed');
});

test('destroy lets an acknowledged owner close before enforcing termination', async () => {
    const sdk = await createFluentBit(defaults);
    const priorReply = reply;
    reply = (worker, message) => {
        if (message.method === 'destroy') {
            worker.emit({type: 'response', id: message.id, ok: true, closed: true});
        }
        else { priorReply(worker, message); }
    };
    await sdk.destroy();
    assert.equal(instances[0].closed, true);
    assert.equal(instances[0].terminated, false);
    await new Promise(resolve => setTimeout(resolve, 300));
    assert.equal(instances[0].terminated, true);
    assert.equal(sdk.state, 'destroyed');
});

test('fatal closure acknowledgement delays the termination fallback', async () => {
    reply = worker => worker.emit({type: 'fatal', code: 'E_LOAD',
        message: 'Injected download failure', closed: true});
    await assert.rejects(createFluentBit(defaults), {code: 'E_LOAD'});
    assert.equal(instances[0].closed, true);
    assert.equal(instances[0].terminated, false);
    await new Promise(resolve => setTimeout(resolve, 300));
    assert.equal(instances[0].terminated, true);
});


test('drain stays in FIFO order between push and stop on a warm instance', async () => {
    const sdk = await createFluentBit(defaults);
    await assert.rejects(sdk.drain(), {code: 'E_STATE'});
    const methods = [];
    let releaseDrain;
    let drainPosted;
    const draining = new Promise(resolve => { drainPosted = resolve; });
    reply = (worker, message) => {
        if (message.type !== 'request') { return; }
        methods.push(message.method);
        const respond = () => worker.emit({type: 'response', id: message.id, ok: true, value: null});
        if (message.method === 'drain') {
            releaseDrain = respond;
            drainPosted();
        }
        else { respond(); }
    };
    const operations = Promise.all([sdk.start({yaml: 'pipeline: {}'}),
        sdk.push({input: 'app', records: [{message: 'queued'}]}), sdk.drain(), sdk.stop()]);
    await draining;
    await new Promise(resolve => setTimeout(resolve, 0));
    assert.deepEqual(methods, ['start', 'push', 'drain']);
    releaseDrain();
    await operations;
    assert.deepEqual(methods, ['start', 'push', 'drain', 'stop']);
    await sdk.destroy();
});

// The engine answers a request command on admission; the reply is a separate
// message correlated by the id of that command.
function requestWorker(onRequest) {
    reply = (worker, message) => {
        if (message.type !== 'request') { return; }
        if (message.method === 'request' || message.method === 'pushBytes') {
            onRequest(worker, message);
            return;
        }
        worker.emit({type: 'response', id: message.id, ok: true, value: null});
    };
}
const admitted = (worker, message, value = null) =>
    worker.emit({type: 'response', id: message.id, ok: true, value});
const replied = (worker, id, fields = {}) => worker.emit({type: 'reply', id, outcome: 0, status: 201,
    truncated: false, headers: [['content-length', '0']], body: new Uint8Array(), ...fields});

test('pushBytes validates its arguments and resolves on admission', async () => {
    const sdk = await createFluentBit(defaults);
    const seen = [];
    requestWorker((worker, message) => {
        seen.push(message);
        admitted(worker, message, {acceptedBytes: message.payload.data.byteLength});
    });
    await assert.rejects(sdk.pushBytes({input: 'tcp', data: 'x'}), {code: 'E_STATE'});
    await sdk.start({yaml: 'pipeline: {}'});
    await assert.rejects(sdk.pushBytes({input: 'bad alias', data: 'x'}), {code: 'E_ARGUMENT'});
    await assert.rejects(sdk.pushBytes({input: 'tcp', data: ''}), {code: 'E_ARGUMENT'});
    await assert.rejects(sdk.pushBytes({input: 'tcp', data: 3}), {code: 'E_ARGUMENT'});
    await assert.rejects(sdk.pushBytes({input: 'tcp', data: new Uint8Array(1024 * 1024 + 1)}),
                         {code: 'E_LIMIT'});
    const data = new Uint8Array([123, 125]);
    const accepted = sdk.pushBytes({input: 'tcp', data});
    data[0] = 0;
    assert.deepEqual(await accepted, {acceptedBytes: 2});
    assert.equal(seen.length, 1);
    assert.equal(seen[0].payload.input, 'tcp');
    assert.deepEqual([...seen[0].payload.data], [123, 125]);
    await sdk.destroy();
});

test('request serializes one bounded buffer and resolves with the correlated reply', async () => {
    const sdk = await createFluentBit(defaults);
    const seen = [];
    requestWorker((worker, message) => {
        seen.push(message);
        admitted(worker, message);
        // Unknown ids are ignored, then the real reply, then a repeat of it.
        replied(worker, 9999);
        replied(worker, message.id, {status: 200, headers: [['content-type', 'application/json']],
                                     body: new Uint8Array([123, 125]), truncated: true});
        replied(worker, message.id, {status: 500});
    });
    await sdk.start({yaml: 'pipeline: {}'});
    for (const options of [{input: 'otlp'}, {input: 'otlp', path: 'v1/logs'},
                           {input: 'otlp', path: '/v1 logs'}, {input: 'otlp', path: '/', method: 'P OST'},
                           {input: 'otlp', path: '/', headers: {'bad name': 'x'}},
                           {input: 'otlp', path: '/', headers: {name: 'line\nbreak'}},
                           {input: 'otlp', path: '/', headers: [['a']]},
                           {input: 'otlp', path: '/', body: 7}]) {
        await assert.rejects(sdk.request(options), {code: 'E_ARGUMENT'});
    }
    await assert.rejects(sdk.request({input: 'otlp', path: '/', body: new Uint8Array(1024 * 1024)}),
                         {code: 'E_LIMIT'});
    await assert.rejects(sdk.request({input: 'otlp', path: '/', body: 'x',
        headers: {large: 'v'.repeat(1024 * 1024)}}), {code: 'E_LIMIT'});
    assert.equal(seen.length, 0);

    const result = await sdk.request({input: 'otlp', path: '/v1/logs?a=b',
        headers: {'Content-Type': 'application/json'}, body: '{}'});
    assert.equal(Object.isFrozen(result), true);
    assert.equal(result.status, 200);
    assert.equal(result.truncated, true);
    assert.deepEqual(result.headers, [['content-type', 'application/json']]);
    assert.deepEqual([...result.body], [123, 125]);

    // method, path, header count and body lengths, then the strings.
    const data = seen[0].payload.data;
    const view = new DataView(data.buffer);
    assert.deepEqual([0, 4, 8, 12].map(offset => view.getUint32(offset, true)), [4, 12, 2, 2]);
    const text = new TextDecoder().decode(data);
    assert.ok(text.includes('POST/v1/logs?a=b'));
    assert.ok(text.includes('Content-Typeapplication/json'));
    // A client always sends Host; handlers look for it.
    assert.ok(text.includes('Hostlocalhost'));
    assert.ok(text.endsWith('{}'));

    await sdk.request({input: 'otlp', path: '/', method: 'GET', headers: [['host', 'example']]});
    assert.equal(new DataView(seen[1].payload.data.buffer).getUint32(8, true), 1);
    await sdk.destroy();
});

test('a reply that arrives before the admission response still settles the request', async () => {
    const sdk = await createFluentBit(defaults);
    requestWorker((worker, message) => {
        replied(worker, message.id, {status: 204});
        admitted(worker, message);
    });
    await sdk.start({yaml: 'pipeline: {}'});
    assert.equal((await sdk.request({input: 'http', path: '/'})).status, 204);
    await sdk.destroy();
});

test('request outcomes without a reply reject with distinct errors', async () => {
    const sdk = await createFluentBit(defaults);
    let outcome = 1;
    requestWorker((worker, message) => {
        admitted(worker, message);
        worker.emit({type: 'reply', id: message.id, outcome, status: 0, truncated: false,
                     headers: [], body: new Uint8Array()});
    });
    await sdk.start({yaml: 'pipeline: {}'});
    await assert.rejects(sdk.request({input: 'http', path: '/'}), {code: 'E_REQUEST_FAILED'});
    outcome = 2;
    await assert.rejects(sdk.request({input: 'http', path: '/'}), {code: 'E_STOPPED'});
    assert.equal(sdk.state, 'running');
    await sdk.destroy();
});

test('a rejected admission leaves no waiter behind', async () => {
    const sdk = await createFluentBit(defaults);
    const ids = [];
    requestWorker((worker, message) => {
        ids.push(message.id);
        worker.emit({type: 'response', id: message.id, ok: false,
                     code: 'E_BACKPRESSURE', message: 'Input queue is full'});
    });
    await sdk.start({yaml: 'pipeline: {}'});
    await assert.rejects(sdk.request({input: 'http', path: '/'}), {code: 'E_BACKPRESSURE'});
    // A late reply for that id finds nothing to settle and is ignored.
    replied(instances[0], ids[0]);
    assert.equal(sdk.state, 'running');
    await sdk.destroy();
});

test('stop is not queued behind a request waiting for its reply', async () => {
    const sdk = await createFluentBit(defaults);
    const methods = [];
    reply = (worker, message) => {
        if (message.type !== 'request') { return; }
        methods.push(message.method);
        // The input is paused: requests are admitted and never answered.
        worker.emit({type: 'response', id: message.id, ok: true, value: null});
    };
    await sdk.start({yaml: 'pipeline: {}'});
    const first = sdk.request({input: 'http', path: '/one'});
    const second = sdk.request({input: 'http', path: '/two'});
    const outcomes = Promise.allSettled([first, second]);
    await sdk.stop();
    assert.deepEqual(methods, ['start', 'request', 'request', 'stop']);
    assert.equal(sdk.state, 'stopped');
    for (const outcome of await outcomes) {
        assert.equal(outcome.status, 'rejected');
        assert.equal(outcome.reason.code, 'E_STOPPED');
    }
    await sdk.destroy();
});

test('destroy settles requests that still wait for a reply', async () => {
    const sdk = await createFluentBit(defaults);
    requestWorker((worker, message) => admitted(worker, message));
    await sdk.start({yaml: 'pipeline: {}'});
    const waiting = sdk.request({input: 'http', path: '/'});
    const settled = Promise.allSettled([waiting]);
    await new Promise(resolve => setTimeout(resolve, 0));
    await sdk.destroy();
    assert.equal((await settled)[0].reason.code, 'E_STOPPED');
});

test('a malformed reply is a protocol failure', async () => {
    const sdk = await createFluentBit(defaults);
    requestWorker((worker, message) => {
        admitted(worker, message);
        worker.emit({type: 'reply', id: message.id, outcome: 7, status: 200, truncated: false,
                     headers: [], body: new Uint8Array()});
    });
    await sdk.start({yaml: 'pipeline: {}'});
    await assert.rejects(sdk.request({input: 'http', path: '/'}), {code: 'E_PROTOCOL'});
    assert.equal(sdk.state, 'failed');
});
