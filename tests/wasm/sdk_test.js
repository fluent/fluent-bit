/* SPDX-License-Identifier: Apache-2.0 */
(async () => {
    const {createFluentBit, getBrowserSupport} = await import('/sdk/fluent-bit.js');
    const check = (condition, message) => { if (!condition) { throw new Error(message); } };
    const rejected = async (action, code) => {
        try { await action(); }
        catch (error) { check(error.code === code, `${code}: got ${error.code}: ${error.message}`); return; }
        throw new Error(`Expected ${code}`);
    };
    const waitFor = async predicate => {
        for (let i = 0; i < 200; i++) {
            if (await predicate()) { return; }
            await new Promise(resolve => setTimeout(resolve, 25));
        }
        throw new Error('Timed out waiting for records');
    };
    const yaml = `service:
  flush: 0.1
  log_level: error
pipeline:
  inputs:
    - name: lib
      alias: app
      tag: app
  outputs:
    - name: stdout
      match: '*'
      format: json_lines
`;
    check(getBrowserSupport().supported, 'Browser preflight');
    const logs = [];
    const errors = [];
    const states = [];
    const progress = [];
    const fluent = await createFluentBit({onStdout: line => logs.push(line),
        onStderr: line => logs.push(line), onError: error => errors.push(error.code),
        onStateChange: state => states.push(state), onProgress: update => {
            progress.push(update);
            console.log(`SDK startup: ${update.stage} (${update.loadedBytes} bytes)`);
        }});
    try {
        check(['loading-runtime', 'downloading-wasm', 'compiling-wasm',
               'initializing-workers', 'starting-command-thread'].every(stage =>
            progress.some(update => update.stage === stage)), 'All initialization stages reported');
        check(progress.find(update => update.stage === 'compiling-wasm').loadedBytes > 0,
              'WASM download byte count');
        check(fluent.state === 'ready' && fluent.info.abi === 1, 'Ready handshake');
        await rejected(() => fluent.push({input: 'app', records: [{message: 'stopped'}]}), 'E_STATE');
        await rejected(() => fluent.writeFile('/config/../escape', 'no'), 'E_ARGUMENT');
        await fluent.writeFile('/config/example.lua', 'return "café"');
        check(new TextDecoder().decode(await fluent.readFile('/config/example.lua')) === 'return "café"', 'File roundtrip');
        for (let round = 0; round < 3; round++) {
            const result = await fluent.start({yaml, graceSeconds: 1});
            check(result.engineMs >= 0 && fluent.state === 'running', 'Engine ready');
            await rejected(() => fluent.start({yaml}), 'E_STATE');
            await rejected(() => fluent.writeFile('/config/active.lua', 'no'), 'E_STATE');
            await rejected(() => fluent.push({input: 'absent', records: [{message: 'wrong'}]}), 'E_INPUT');
            const message = `SDK café ☃ ${round}`;
            const accepted = await fluent.push({input: 'app', records: [{message}]});
            check(accepted.acceptedRecords === 1 && accepted.acceptedBytes > 0, 'Acceptance');
            const stats = await fluent.getStats();
            check(stats.acceptedRecords === round + 1 && stats.wasmMemoryBytes > 0 &&
                  stats.activeHttpRequests === 0 && Object.isFrozen(stats), 'SDK status snapshot');
            await waitFor(() => logs.some(line => {
                try { return JSON.parse(line).message === message; }
                catch (_) { return false; }
            }));
            await fluent.stop();
            check(fluent.state === 'stopped', 'Stopped');
        }
        await rejected(() => fluent.start({yaml: 'pipeline: [invalid]'}), 'E_CONFIG');
        await rejected(() => fluent.start({yaml: yaml.replace('      alias: app',
            '      threaded: true\n      alias: app')}), 'E_CONFIG');
        await fluent.writeFile('/config/sparse.lua', `function sparse(tag, ts, record)
            record.values = {[1] = "first", [3] = "third"}
            return 2, ts, record
        end`);
        await fluent.start({yaml: yaml.replace('  outputs:', `  filters:
    - name: lua
      match: '*'
      script: /config/sparse.lua
      call: sparse
  outputs:`), graceSeconds: 1});
        await fluent.push({input: 'app', records: [{message: 'sparse array regression'}]});
        await waitFor(() => logs.some(line => {
            try {
                const record = JSON.parse(line);
                return record.message === 'sparse array regression' &&
                    JSON.stringify(record.values) === '["first",null,"third"]';
            }
            catch (_) { return false; }
        }));
        await fluent.stop();
        await fluent.start({yaml, graceSeconds: 1});
        await fluent.stop();
        await fluent.syncStorage();
    }
    catch (error) { console.error(logs.join('\n')); throw error; }
    finally { await fluent.destroy(); }
    await fluent.destroy();
    check(fluent.state === 'destroyed', 'Destroyed');
    await rejected(() => fluent.start({yaml}), 'E_STATE');
    check(!errors.length, `Unexpected SDK errors: ${errors}`);
    check(states.includes('running') && states.includes('destroyed'), 'State notifications');

    // Two independent runtimes must not share virtual files or configuration.
    const first = await createFluentBit();
    const second = await createFluentBit();
    try {
        await first.writeFile('/config/isolated', 'first');
        await rejected(() => second.readFile('/config/isolated'), 'E_FILESYSTEM');
        await Promise.all([first.start({yaml, graceSeconds: 0}), second.start({yaml, graceSeconds: 0})]);
        await Promise.all([first.stop(), second.stop()]);
    }
    finally { await Promise.all([first.destroy(), second.destroy()]); }

    const namespace = `sdk-${crypto.randomUUID()}`;
    const storage = {persistent: true, namespace};
    let persistent = await createFluentBit({storage, onStdout: line => logs.push(line), onStderr: line => logs.push(line)});
    const token = crypto.randomUUID();
    const storageYaml = (path, target) => `service:
  flush: 0.1
  log_level: error
  storage.path: ${path}
  scheduler.base: 1
  scheduler.cap: 2
pipeline:
  inputs:
    - name: lib
      alias: app
      tag: persisted
      storage.type: filesystem
  outputs:
    - name: http
      match: '*'
      browser.url: ${location.origin}/collect/${target}
      format: json_lines
      retry_limit: false
`;
    try {
        await rejected(() => createFluentBit({storage}), 'E_STORAGE_BUSY');
        await persistent.start({yaml: storageYaml(persistent.info.storagePath, token + '?status=503'), graceSeconds: 0});
        await persistent.push({input: 'app', records: [{message: 'SDK persisted recovery'}]});
        await waitFor(async () => (await (await fetch(`/received/${token}`)).json()).attempts > 0);
        await persistent.stop();
        const stats = await persistent.getStats();
        check(!stats.checkpointRequired && stats.lastCheckpointTime > 0 &&
              stats.checkpointFailures === 0, 'Persistent checkpoint status');
    }
    finally { await persistent.destroy(); }
    persistent = await createFluentBit({storage, onStdout: line => logs.push(line), onStderr: line => logs.push(line)});
    const restoredToken = crypto.randomUUID();
    try {
        await persistent.start({yaml: storageYaml(persistent.info.storagePath, restoredToken), graceSeconds: 1});
        await waitFor(async () => (await (await fetch(`/received/${restoredToken}`)).json()).attempts > 0);
        const capture = await (await fetch(`/received/${restoredToken}`)).json();
        check(capture.requests.some(request => atob(request.base64).includes('SDK persisted recovery')), 'Persistent backlog replay');
        await persistent.stop();
    }
    finally { await persistent.destroy(); }
    check(!logs.some(line => /(?:ERROR|SUMMARY): (?:Address|Leak)Sanitizer/.test(line)), logs.join('\n'));
    return {passed: true, states, logs};
})()
