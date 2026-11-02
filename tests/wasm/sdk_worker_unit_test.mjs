/* SPDX-License-Identifier: Apache-2.0 */
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

function worker(BrowserWorker = class {}) {
    const source = readFileSync(new URL('../../sdk/browser/fluent-bit-worker.js', import.meta.url), 'utf8');
    const context = vm.createContext({TextEncoder, setTimeout, clearTimeout,
        self: {Worker: BrowserWorker, addEventListener() {}}});
    // Startup is deliberately omitted: exercise the real command state machine
    // with a controllable storage backend, including rejected IndexedDB commits.
    vm.runInContext(source.replaceAll('import.meta.url', '"https://sdk.test/worker.js"'), context);
    vm.runInContext(`
        let failSync = true;
        runtime = {HEAPU8: new Uint8Array(65536), flbBrowserHttp: {pending: () => 0},
            flbStorage: {persistent: true, sync: async () => {
                if (failSync) throw new Error('QuotaExceededError');
            }}};
        state = 'running';
        checkpointRequired = true;
        command = async () => ({result: 0});
        drainLogs = async () => {};
    `, context);
    return {run: source => vm.runInContext(source, context),
        request: method => vm.runInContext(`execute({id: 1, method: '${method}', payload: {}})`, context)};
}

test('checkpoint failure blocks restart until a successful explicit retry', async () => {
    const sdk = worker();
    await assert.rejects(sdk.request('stop'), {code: 'E_STORAGE'});
    let stats = await sdk.request('getStats');
    assert.equal(stats.checkpointRequired, true);
    assert.equal(stats.checkpointFailures, 1);
    assert.equal(stats.lastCheckpointTime, null);
    await assert.rejects(sdk.request('start'), {code: 'E_STORAGE'});
    await assert.rejects(sdk.request('syncStorage'), {code: 'E_STORAGE'});
    sdk.run('failSync = false');
    await sdk.request('syncStorage');
    stats = await sdk.request('getStats');
    assert.equal(stats.checkpointRequired, false);
    assert.equal(stats.checkpointFailures, 2);
    assert.ok(stats.lastCheckpointTime > 0);
    await sdk.request('start');
    assert.equal((await sdk.request('getStats')).checkpointRequired, true);
    await assert.rejects(sdk.request('syncStorage'), {code: 'E_STATE'});
});

test('a shutdown error must not checkpoint storage with potentially active writers', async () => {
    const sdk = worker();
    sdk.run('command = async () => ({result: -1})');
    await assert.rejects(sdk.request('stop'), {code: 'E_SHUTDOWN'});
    assert.equal((await sdk.request('getStats')).checkpointFailures, 0);
});

test('dynamic pthread creation cannot exceed the qualified pool', () => {
    const sdk = worker();
    sdk.run('for (let i = 0; i < PTHREAD_POOL_SIZE; i++) pthreadWorkers.add({})');
    assert.throws(() => sdk.run('new self.Worker("unexpected.js")'), {code: 'E_LIMIT'});
});

class FakeBrowserWorker {
    constructor() { this.listeners = new Map(); this.messages = []; this.terminated = false; }
    addEventListener(type, listener) { this.listeners.set(type, listener); }
    postMessage(message) { this.messages.push(message); }
    terminate() { this.terminated = true; }
}

test('runtime termination keeps children tracked until their close acknowledgement', async () => {
    const sdk = worker(FakeBrowserWorker);
    sdk.run('active = {operation: 4}');
    const child = sdk.run('const child = new self.Worker("pthread.js"); child.terminate(); child');
    assert.equal(sdk.run('pthreadWorkers.size'), 1);
    assert.equal(child.terminated, false);
    child.listeners.get('message')({data: {flbPthread: 1, stage: 'closed'},
        stopImmediatePropagation() {}});
    await sdk.run('child.shutdown()');
    assert.equal(sdk.run('pthreadWorkers.size'), 0);
    assert.equal(child.terminated, false);
    sdk.run('active = null; child.terminate()');
    assert.equal(child.messages.length, 1);
});

test('unresponsive pthread shutdown remains bounded and forces termination', async () => {
    const sdk = worker(FakeBrowserWorker);
    sdk.run('active = {operation: 4}');
    const child = sdk.run('const child = new self.Worker("pthread.js"); child.terminate(); child');
    assert.equal(sdk.run('pthreadWorkers.size'), 1);
    await sdk.run('child.shutdown()');
    assert.equal(sdk.run('pthreadWorkers.size'), 0);
    assert.equal(child.terminated, true);
});

test('ordinary pthread termination still stops the worker immediately', () => {
    const sdk = worker(FakeBrowserWorker);
    const child = sdk.run('const child = new self.Worker("pthread.js"); child.terminate(); child');
    assert.equal(sdk.run('pthreadWorkers.size'), 0);
    assert.equal(child.terminated, true);
});

test('failed persistent startup requires checkpoint recovery too', async () => {
    const sdk = worker();
    sdk.run("state = 'stopped'; checkpointRequired = false; command = async () => ({result: -3})");
    await assert.rejects(sdk.request('start'), {code: 'E_CONFIG'});
    assert.equal((await sdk.request('getStats')).checkpointRequired, true);
    await assert.rejects(sdk.request('start'), {code: 'E_STORAGE'});
    sdk.run('failSync = false');
    await sdk.request('syncStorage');
    assert.equal((await sdk.request('getStats')).checkpointRequired, false);
});

test('graceful destruction drains child shutdown logs before replying and closing', async () => {
    const sdk = worker();
    sdk.run(`
        const teardown = [];
        let closingReply;
        state = 'stopped';
        command = async () => { teardown.push('engine'); return {result: 0}; };
        drainLogs = async () => { teardown.push('logs'); };
        pthreadWorkers.add({shutdown: async () => { teardown.push('child'); }});
        releaseStorage = () => teardown.push('storage');
        self.postMessage = message => {
            if (message.type === 'response' && message.ok) {
                closingReply = message.closed;
                teardown.push('response');
            }
        };
        self.close = () => teardown.push('close');
    `);
    await sdk.run(`self.onmessage({data: {abi: 1, type: 'request', id: 1,
        method: 'destroy', payload: {}}})`);
    assert.deepEqual(Array.from(sdk.run('teardown')),
        ['engine', 'child', 'logs', 'storage', 'close', 'response']);
    assert.equal(sdk.run('closingReply'), true);
    assert.equal(sdk.run('state'), 'destroyed');
});

test('fatal startup cleanup marks the owner closing before notifying its parent', async () => {
    const sdk = worker();
    sdk.run(`
        const teardown = [];
        let closingReply;
        pthreadWorkers.add({shutdown: async () => teardown.push('child')});
        releaseStorage = () => teardown.push('storage');
        self.close = () => teardown.push('close');
        self.postMessage = message => {
            if (message.type === 'fatal') {
                closingReply = message.closed;
                teardown.push('fatal');
            }
        };
    `);
    await sdk.run('fatal("injected startup failure")');
    assert.deepEqual(Array.from(sdk.run('teardown')), ['child', 'storage', 'close', 'fatal']);
    assert.equal(sdk.run('closingReply'), true);
    assert.equal(sdk.run('state'), 'failed');
});
