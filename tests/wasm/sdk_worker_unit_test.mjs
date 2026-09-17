/* SPDX-License-Identifier: Apache-2.0 */
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

function worker() {
    const source = readFileSync(new URL('../../sdk/browser/fluent-bit-worker.js', import.meta.url), 'utf8');
    const context = vm.createContext({TextEncoder, setTimeout, clearTimeout,
        self: {Worker: class {}, addEventListener() {}}});
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
