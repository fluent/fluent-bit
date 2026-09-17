/* SPDX-License-Identifier: Apache-2.0 */
import {test, beforeEach, afterEach} from 'node:test';
import assert from 'node:assert/strict';
import {createFluentBit, getBrowserSupport} from '../../sdk/browser/fluent-bit.js';

const instances = [];
let reply;
class FakeWorker {
    constructor() { this.terminated = false; instances.push(this); }
    postMessage(message) {
        queueMicrotask(() => {
            if (!this.terminated) { reply(this, message); }
        });
    }
    emit(message) { this.onmessage?.({data: {abi: 1, ...message}}); }
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
afterEach(() => { for (const worker of instances) { assert.equal(worker.terminated, true); } });

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
