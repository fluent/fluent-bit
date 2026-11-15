/* SPDX-License-Identifier: Apache-2.0 */
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

function worker(BrowserWorker = class {}) {
    const source = readFileSync(new URL('../../sdk/browser/fluent-bit-worker.js', import.meta.url), 'utf8');
    const context = vm.createContext({TextEncoder, TextDecoder, setTimeout, clearTimeout,
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

test('runtime termination retains children until acknowledged cleanup finishes', async () => {
    const sdk = worker(FakeBrowserWorker);
    sdk.run('active = {operation: 4}');
    const child = sdk.run('const child = new self.Worker("pthread.js"); child.terminate(); child');
    assert.equal(sdk.run('pthreadWorkers.size'), 1);
    assert.equal(child.terminated, false);
    child.listeners.get('message')({data: {flbPthread: 1, stage: 'closed'},
        stopImmediatePropagation() {}});
    await new Promise(resolve => setTimeout(resolve, 0));
    assert.equal(child.terminated, true);
    assert.equal(sdk.run('pthreadWorkers.size'), 1);
    await sdk.run('child.shutdown()');
    assert.equal(sdk.run('pthreadWorkers.size'), 0);
    assert.equal(child.terminated, true);
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


test('drain validates state, reports unsupported pipelines and waits for log delivery', async () => {
    const sdk = worker();
    sdk.run('state = "stopped"');
    await assert.rejects(sdk.request('drain'), {code: 'E_STATE'});
    sdk.run('state = "running"; command = async () => ({result: -2})');
    await assert.rejects(sdk.request('drain'), {code: 'E_UNSUPPORTED'});
    sdk.run('command = async () => ({result: -1})');
    await assert.rejects(sdk.request('drain'), {code: 'E_DRAIN'});
    sdk.run(`let releaseCommand, releaseLogs, drainCalls = 0;
        command = () => new Promise(resolve => { releaseCommand = resolve; });
        drainLogs = () => {
            drainCalls++;
            return new Promise(resolve => { releaseLogs = resolve; });
        };`);
    let complete = false;
    const draining = sdk.request('drain').then(() => { complete = true; });
    await new Promise(resolve => setTimeout(resolve, 0));
    assert.equal(sdk.run('drainCalls'), 0);
    assert.equal(complete, false);
    sdk.run('releaseCommand({result: 0})');
    await new Promise(resolve => setTimeout(resolve, 0));
    assert.equal(sdk.run('drainCalls'), 1);
    assert.equal(complete, false);
    sdk.run('releaseLogs()');
    await draining;
    assert.equal(complete, true);
});

test('inspection results are decoded, feature-gated and report the engine reason', async () => {
    const sdk = worker();
    const output = value => `new TextEncoder().encode(JSON.stringify(${JSON.stringify(value)}))`;
    await assert.rejects(sdk.request('evaluateCondition'), {code: 'E_UNSUPPORTED'});
    await assert.rejects(sdk.request('getTopology'), {code: 'E_UNSUPPORTED'});
    await assert.rejects(sdk.request('takeTrace'), {code: 'E_UNSUPPORTED'});
    sdk.run(`features = ['condition', 'topology', 'trace'];
        let operations = [];
        command = async (id, operation, data, name, grace) => {
            operations.push([operation, grace]);
            return {result: 0, output: ${output({matched: [true, false]})}};
        };`);
    // Values come from the worker's own realm; compare them as JSON.
    assert.equal(JSON.stringify(await sdk.request('evaluateCondition')), '{"matched":[true,false]}');
    sdk.run(`command = async () => ({result: 0, output: ${output({error: "a rule needs a 'value'"})}})`);
    await assert.rejects(sdk.request('evaluateCondition'),
                         {code: 'E_CONDITION', message: "a rule needs a 'value'"});
    sdk.run('command = async () => ({result: -1, output: null})');
    await assert.rejects(sdk.request('evaluateCondition'), {code: 'E_CONDITION'});
    await assert.rejects(sdk.request('takeTrace'), {code: 'E_TRACE'});
    sdk.run('state = "stopped"');
    await assert.rejects(sdk.request('getTopology'), {code: 'E_STATE'});
    sdk.run(`state = "running"; command = async (id, operation, data, name, grace) => {
        operations.push([operation, grace]);
        return {result: 0, output: ${output({events: [], dropped: 0})}};
    };`);
    assert.equal(JSON.stringify(await sdk.request('takeTrace')), '{"events":[],"dropped":0}');
    assert.equal(sdk.run('JSON.stringify(operations)'), '[[6,null],[8,0]]');
});

test('start configures tracing before the engine and copies result buffers out', async () => {
    const sdk = worker();
    sdk.run(`features = ['trace']; runtime.flbStorage.persistent = false; checkpointRequired = false; state = 'stopped';
        let operations = [];
        command = async (id, operation, data, name, grace) => {
            operations.push([operation, grace]);
            return {result: 0, engineMs: 1};
        };`);
    await sdk.run(`execute({id: 1, method: 'start', payload: {yaml: new Uint8Array(1), grace: 0, trace: true}})`);
    sdk.run('state = "stopped"');
    await sdk.run(`execute({id: 2, method: 'start', payload: {yaml: new Uint8Array(1), grace: 0, trace: false}})`);
    assert.equal(sdk.run('JSON.stringify(operations)'), '[[8,1],[1,0],[8,2],[1,0]]');
    sdk.run(`features = []; state = 'stopped'`);
    await assert.rejects(sdk.run(`execute({id: 3, method: 'start',
        payload: {yaml: new Uint8Array(1), grace: 0, trace: true}})`), {code: 'E_UNSUPPORTED'});
});
