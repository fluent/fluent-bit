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
    const checkFts = async fluent => {
        await fluent.writeFile('/config/typed.lua', `local fb = require("fluentbit")
            assert(os == nil and io == nil and debug == nil and warn == nil)
            function process(log)
                if log.body:get_string("message") == "fts drop" then return fb.DROP end
                local view = log.body:get("nested")
                collectgarbage("collect")
                view:set("value", fb.int64(42))
                log.body:set("exact", fb.uint64("18446744073709551615"):value())
                log.body:set("fts", true)
                return fb.KEEP
            end`);
        const ftsYaml = yaml.replace('      tag: app', `      tag: app
      processors:
        logs:
          - name: fts
            script: /config/typed.lua`);
        await fluent.start({yaml: ftsYaml.replace('flush: 0.1', 'flush: 60'), graceSeconds: 0});
        await fluent.push({input: 'app', records: [
            {message: 'fts drop'}, {message: 'fts browser', nested: {value: 1}}]});
        await fluent.drain();
        await waitFor(() => logs.some(line => {
            try {
                const record = JSON.parse(line);
                return record.message === 'fts browser' && record.fts === true &&
                    record.nested.value === 42 && record.exact === '18446744073709551615';
            }
            catch (_) { return false; }
        }));
        await fluent.push({input: 'app', records: [{message: 'fts drop'}]});
        await fluent.drain();
        await fluent.stop();
        check(!logs.some(line => {
            try { return JSON.parse(line).message === 'fts drop'; }
            catch (_) { return false; }
        }), 'FTS drops records');
        await rejected(() => fluent.start({yaml: ftsYaml.replace('- name: fts',
            '- name: fts\n            jit: true\n            instruction_limit: 0')}), 'E_CONFIG');
        check(logs.some(line => line.includes('JIT is unavailable in this Lua runtime')),
              'FTS reports the unsupported JIT option');
        console.log('Browser FTS processor passed: typed values, nested views, drop and JIT rejection');
    };
    // Inspection reports what the engine decides: it must agree with delivery.
    const checkInspection = async fluent => {
        check(['condition', 'topology', 'trace'].every(name => fluent.info.features.includes(name)),
              'Inspection features are advertised');
        const records = [{level: 'error', service: 'web'}, {level: 'info', service: 'payments'},
                         {level: 'error', service: 'payments'}, {level: 'info', service: 'web'}];
        const errors = {rules: [{field: '$level', op: 'eq', value: 'error'}]};
        const either = {op: 'or', rules: [...errors.rules,
                                          {field: '$service', op: 'regex', value: '^pay'}]};
        check(JSON.stringify((await fluent.evaluateCondition({condition: errors, records})).matched) ===
              '[true,false,true,false]', 'Condition result before any pipeline runs');
        check(JSON.stringify((await fluent.evaluateCondition({condition: either, records})).matched) ===
              '[true,true,true,false]', 'Rules combined with or');
        try {
            await fluent.evaluateCondition({condition: {rules: [{field: '$level', op: 'eq'}]}, records});
            throw new Error('Expected E_CONDITION');
        }
        catch (error) {
            check(error.code === 'E_CONDITION' && error.message.includes("'value'"),
                  `Rejected condition carries the engine reason: ${error.code}: ${error.message}`);
        }
        await rejected(() => fluent.getTopology(), 'E_STATE');
        const routedYaml = `service:
  flush: 60
  log_level: error
pipeline:
  inputs:
    - name: lib
      alias: app
      tag: app
      routes:
        logs:
          - name: errors
            condition:
              rules:
                - field: $level
                  op: eq
                  value: error
            to:
              outputs:
                - alerts
                - name: absent
                  fallback: archive
          - name: rest
            condition:
              default: true
            to:
              outputs:
                - other
                - alerts
                - nowhere
  filters:
    - name: grep
      match: errors
      exclude: service payments
  outputs:
    - name: stdout
      alias: alerts
      match: nothing
      format: json_lines
    - name: 'null'
      alias: archive
      match: nothing
    - name: 'null'
      alias: other
      match: nothing
`;
        await fluent.start({yaml: routedYaml, graceSeconds: 0, trace: true});
        const topology = await fluent.getTopology();
        const [errorsRoute, restRoute] = topology.inputs[0].routes;
        check(topology.inputs[0].matchedOutputs.length === 0 &&
              JSON.stringify(topology.inputs[0].directOutputs) === '[0,1,2]', 'Routes replace tag matching');
        check(errorsRoute.outputs[0].status === 'connected' && errorsRoute.outputs[0].resolved === 0 &&
              errorsRoute.outputs[1].usedFallback && errorsRoute.outputs[1].resolved === 1,
              'Route outputs resolve by alias, then by fallback');
        // Only the first route of an input that names an output is connected to it.
        check(restRoute.isDefault && restRoute.outputs[0].status === 'connected' &&
              restRoute.outputs[1].status === 'already_connected' &&
              restRoute.outputs[2].status === 'not_found' && restRoute.outputs[2].resolved === null,
              'Skipped route outputs carry the engine reason');
        check(topology.filters[0].match === 'errors' && topology.filters[0].matchesInputs.length === 0,
              'Filter matches are reported against configured tags');
        await fluent.push({input: 'app', records});
        await fluent.drain();
        const {events, dropped} = await fluent.takeTrace();
        const routed = name => events.filter(event => event.stage === 'route' && event.route === name)
            .map(event => event.record).join();
        check(dropped === 0 && routed('errors') === '0,2' && routed('rest') === '1,3',
              `Each record is traced to its route: ${JSON.stringify(events)}`);
        check(events.some(event => event.stage === 'filter' && event.tag === 'errors' &&
              event.recordsIn === 2 && event.recordsOut === 1 && event.modified),
              'Filters are traced on the route tag');
        check(events.some(event => event.stage === 'output' && event.tag === 'errors' &&
              event.output === 0 && event.records === 1) &&
              events.some(event => event.stage === 'output' && event.tag === 'rest' &&
              event.output === 2 && event.records === 2) &&
              !events.some(event => event.stage === 'output' && event.tag === 'rest' && event.output === 0),
              'Outputs are traced with what they receive');
        check(!events.some(event => event.stage === 'unrouted'), 'Every record found a route');
        check(logs.filter(line => {
            try { return JSON.parse(line).level === 'error'; }
            catch (_) { return false; }
        }).length === 1, 'The trace agrees with what the output received');
        check((await fluent.takeTrace()).events.length === 0, 'Taking the trace empties it');
        await fluent.stop();
        // Tracing is per start.
        await fluent.start({yaml: routedYaml, graceSeconds: 0});
        await fluent.push({input: 'app', records});
        await fluent.drain();
        check((await fluent.takeTrace()).events.length === 0, 'A start without trace records nothing');
        await fluent.stop();
        console.log('Browser SDK inspection passed: conditions, topology and record trace');
    };
    // Metrics and traces enter as OTLP/JSON and pass the input's processors.
    const checkOtlp = async fluent => {
        check(fluent.info.features.includes('otlp'), 'OTLP ingestion is advertised');
        const metrics = JSON.stringify({resourceMetrics: [{
            resource: {attributes: [{key: 'service.name', value: {stringValue: 'shop'}}]},
            scopeMetrics: [{scope: {name: 'sdk'}, metrics: [
                {name: 'requests', unit: '1', sum: {aggregationTemporality: 2, isMonotonic: true,
                    dataPoints: [{attributes: [{key: 'route', value: {stringValue: '/'}}],
                                  timeUnixNano: '1700000000000000000', asInt: 'EXACT'}]}},
                {name: 'discarded', gauge: {dataPoints: [
                    {timeUnixNano: '1700000000000000000', asDouble: 1.5}]}}]}]}]})
            .replace('"EXACT"', '"9007199254740993"');
        const span = (name, id) => ({traceId: '5b8efff798038103d269b633813fc60c', spanId: id,
            name, kind: 2, startTimeUnixNano: '1700000000000000000',
            endTimeUnixNano: '1700000000500000000',
            attributes: [{key: 'http.route', value: {stringValue: `/${name}`}}]});
        const traces = {resourceSpans: [{
            resource: {attributes: [{key: 'service.name', value: {stringValue: 'shop'}}]},
            scopeSpans: [{scope: {name: 'sdk'},
                          spans: [span('checkout', 'eee19b7ec3c1b174'), span('health', 'eee19b7ec3c1b175')]}]}]};
        await rejected(() => fluent.pushOtlp({input: 'app', signal: 'metrics', payload: metrics}), 'E_STATE');
        await fluent.writeFile('/config/metrics.lua', `local fb = require("fluentbit")
            function process(metric)
                if metric.name == "discarded" then return fb.DROP end
                metric.name = "shop." .. metric.name
            end`);
        await fluent.writeFile('/config/traces.lua', `local fb = require("fluentbit")
            function process(span)
                if span.name == "health" then return fb.DROP end
                span.attributes:set("fts", "seen")
            end`);
        const otlpYaml = yaml.replace('      tag: app', `      tag: app
      processors:
        metrics:
          - name: fts
            script: /config/metrics.lua
        traces:
          - name: fts
            script: /config/traces.lua`).replace('json_lines', 'otlp_json').replace('flush: 0.1', 'flush: 60');
        await fluent.start({yaml: otlpYaml, graceSeconds: 0});
        await rejected(() => fluent.pushOtlp({input: 'app', signal: 'logs', payload: {}}), 'E_ARGUMENT');
        await rejected(() => fluent.pushOtlp({input: 'absent', signal: 'metrics', payload: metrics}), 'E_INPUT');
        await rejected(() => fluent.pushOtlp({input: 'app', signal: 'metrics', payload: '{"resourceMetrics":'}),
                       'E_ARGUMENT');
        await rejected(() => fluent.pushOtlp({input: 'app', signal: 'metrics', payload: traces}), 'E_ARGUMENT');
        await rejected(() => fluent.pushOtlp({input: 'app', signal: 'metrics',
            payload: {resourceMetrics: [{scopeMetrics: [{metrics: []}]}]}}), 'E_ARGUMENT');
        await rejected(() => fluent.pushOtlp({input: 'app', signal: 'traces', payload: 'null'}), 'E_ARGUMENT');
        const from = logs.length;
        for (const [signal, payload] of [['metrics', metrics], ['traces', JSON.stringify(traces)]]) {
            await rejected(() => fluent.pushOtlp({input: 'app', signal, payload: ' \t\r\n'}),
                           'E_ARGUMENT');
            for (const suffix of [`\n${payload}`, '\n{}', '\n{"partial":', '\ntrailing', '\u0000']) {
                await rejected(() => fluent.pushOtlp({input: 'app', signal, payload: payload + suffix}),
                               'E_ARGUMENT');
            }
        }
        const accepted = await fluent.pushOtlp({input: 'app', signal: 'metrics', payload: metrics});
        check(accepted.acceptedBytes === new TextEncoder().encode(metrics).length, 'Metrics acceptance');
        await fluent.pushOtlp({input: 'app', signal: 'traces', payload: ` \n${JSON.stringify(traces)}\t\r\n`});
        await fluent.drain();
        const printed = logs.slice(from).flatMap(line => {
            try { return [JSON.parse(line)]; }
            catch (_) { return []; }
        });
        const families = printed.flatMap(request => request.resourceMetrics || [])
            .flatMap(resource => resource.scopeMetrics).flatMap(scope => scope.metrics);
        check(families.length === 1 && families[0].name === 'shop.requests',
              `The metrics processor renames and drops families: ${logs.slice(from).join('\n')}`);
        check(logs.slice(from).some(line => line.includes('9007199254740993')),
              'A 64-bit metric value keeps every digit');
        const spans = printed.flatMap(request => request.resourceSpans || [])
            .flatMap(resource => resource.scopeSpans).flatMap(scope => scope.spans);
        check(spans.length === 1 && spans[0].name === 'checkout' &&
              spans[0].attributes.some(item => item.key === 'fts' && item.value.stringValue === 'seen'),
              `The traces processor edits and drops spans: ${logs.slice(from).join('\n')}`);
        // A result longer than the default line limit arrives whole when the host asks for it.
        const many = {resourceSpans: [{scopeSpans: [{spans: Array.from({length: 40}, (_, index) =>
            span(`step-${index}`, (0xeee19b7ec3c1b200n + BigInt(index)).toString(16)))}]}]};
        const lines = logs.length;
        await fluent.pushOtlp({input: 'app', signal: 'traces', payload: many});
        await fluent.drain();
        const long = logs.slice(lines).find(line => line.includes('step-39'));
        check(long && long.length > 4096 && JSON.parse(long).resourceSpans[0].scopeSpans[0].spans.length === 40,
              'A long OTLP line is delivered whole');
        // Logs and telemetry share the input.
        await fluent.push({input: 'app', records: [{message: 'beside telemetry'}]});
        await fluent.drain();
        await fluent.stop();
        console.log('Browser SDK OTLP ingestion passed: metrics, traces and rejected payloads');
    };
    check(getBrowserSupport().supported, 'Browser preflight');
    const logs = [];
    const errors = [];
    const states = [];
    const progress = [];
    const fluent = await createFluentBit({outputLineLimit: 65536, onStdout: line => logs.push(line),
        onStderr: line => logs.push(line), onError: error => errors.push(error.code),
        onStateChange: state => states.push(state), onProgress: update => {
            progress.push(update);
            console.log(`SDK startup: ${update.stage} (${update.loadedBytes} bytes)`);
        }});
    if (globalThis.ftsOnly) {
        try { await checkFts(fluent); return {passed: true}; }
        finally { await fluent.destroy(); }
    }
    try {
        check(['loading-runtime', 'downloading-wasm', 'compiling-wasm',
               'initializing-workers', 'starting-command-thread'].every(stage =>
            progress.some(update => update.stage === stage)), 'All initialization stages reported');
        check(progress.find(update => update.stage === 'compiling-wasm').loadedBytes > 0,
              'WASM download byte count');
        check(fluent.state === 'ready' && fluent.info.abi === 1, 'Ready handshake');
        await rejected(() => fluent.push({input: 'app', records: [{message: 'stopped'}]}), 'E_STATE');
        await rejected(() => fluent.drain(), 'E_STATE');
        await rejected(() => fluent.writeFile('/config/../escape', 'no'), 'E_ARGUMENT');
        await fluent.writeFile('/config/example.lua', 'return "café"');
        check(new TextDecoder().decode(await fluent.readFile('/config/example.lua')) === 'return "café"', 'File roundtrip');
        const timings = [];
        for (let round = 0; round < 10; round++) {
            const begin = performance.now();
            const result = await fluent.start({yaml: yaml.replace('flush: 0.1', 'flush: 60'),
                                               graceSeconds: 0});
            await fluent.drain(); // Empty pipelines must complete too.
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
            await fluent.drain();
            check(logs.some(line => {
                try { return JSON.parse(line).message === message; }
                catch (_) { return false; }
            }), 'Drain waits for output callbacks despite a 60-second flush interval');
            await fluent.stop();
            timings.push(performance.now() - begin);
            check(fluent.state === 'stopped', 'Stopped');
        }
        console.log(`Warm start/push/drain/stop milliseconds: ${JSON.stringify(timings)}`);
        // Count records at the output processor, emitting only eight small
        // cumulative summaries so the SDK log transport cannot drop the proof.
        await fluent.writeFile('/config/delivery-count.lua', `local fb = require("fluentbit")
            local delivered = 0
            function process(log)
                delivered = delivered + 1
                if delivered % 100 ~= 0 then return fb.DROP end
                log.body:set("message", "large batch delivered")
                log.body:set("delivered", delivered)
                return fb.KEEP
            end`);
        const largeBatchYaml = yaml.replace('flush: 0.1', 'flush: 60').replace(
            '      format: json_lines', `      format: json_lines
      processors:
        logs:
          - name: fts
            script: /config/delivery-count.lua`);
        await fluent.start({yaml: largeBatchYaml, graceSeconds: 0});
        for (let batch = 0; batch < 8; batch++) {
            await fluent.push({input: 'app', records: Array.from({length: 100},
                (_, index) => ({batch, index, message: 'x'.repeat(8000)}))});
        }
        await fluent.drain();
        const deliveredCounts = logs.flatMap(line => {
            try {
                const record = JSON.parse(line);
                return record.message === 'large batch delivered' ? [record.delivered] : [];
            }
            catch (_) { return []; }
        });
        check(JSON.stringify(deliveredCounts) === JSON.stringify([100, 200, 300, 400, 500, 600, 700, 800]),
              'All 800 large records reach output processing before drain resolves');
        await fluent.stop();
        const routedYaml = yaml.replace('flush: 0.1', 'flush: 60') + `
    - name: stdout
      match: '*'
      format: json_lines
`;
        await fluent.start({yaml: routedYaml, graceSeconds: 0});
        await fluent.push({input: 'app', records: [{message: 'drain fan-out'}]});
        await fluent.drain();
        check(logs.filter(line => {
            try { return JSON.parse(line).message === 'drain fan-out'; }
            catch (_) { return false; }
        }).length === 2, 'Drain waits for both routes');
        await fluent.stop();
        await fluent.start({yaml: yaml.replace('flush: 0.1', 'flush: 60').replace("match: '*'",
            'match: unmatched'), graceSeconds: 0});
        await fluent.push({input: 'app', records: [{message: 'no matching route'}]});
        await fluent.drain();
        check(!logs.some(line => {
            try { return JSON.parse(line).message === 'no matching route'; }
            catch (_) { return false; }
        }), 'Unmatched records must not reach stdout');
        await fluent.stop();
        await fluent.start({yaml: yaml.replace('name: lib', 'name: dummy'), graceSeconds: 0});
        await rejected(() => fluent.drain(), 'E_UNSUPPORTED');
        await fluent.stop();
        await fluent.start({yaml: yaml.replace('name: stdout',
            'name: http\n      host: 127.0.0.1\n      port: 1'), graceSeconds: 0});
        await rejected(() => fluent.drain(), 'E_UNSUPPORTED');
        await fluent.stop();
        await rejected(() => fluent.start({yaml: 'pipeline: [invalid]'}), 'E_CONFIG');
        await rejected(() => fluent.start({yaml: yaml.replace('      alias: app',
            '      threaded: true\n      alias: app')}), 'E_CONFIG');
        await fluent.writeFile('/config/sparse.lua', `function sparse(tag, ts, record)
            record.values = {[1] = "first", [3] = "third"}
            record.large_index = {[1000000000] = 7}
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
                    JSON.stringify(record.values) === '["first",null,"third"]' &&
                    !Array.isArray(record.large_index) && record.large_index['1000000000'] === 7;
            }
            catch (_) { return false; }
        }));
        await fluent.stop();
        await checkInspection(fluent);
        await checkOtlp(fluent);
        await checkFts(fluent);
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

    // Reentrant application callbacks must not revive a terminated runtime.
    for (const stage of ['starting', 'stopping']) {
        let interrupted;
        interrupted = await createFluentBit({onStateChange(state) {
            if (state === stage) { interrupted.destroy({force: true}); }
        }});
        await rejected(() => stage === 'starting' ? interrupted.start({yaml}) : interrupted.stop(), 'E_STATE');
        check(interrupted.state === 'destroyed', `${stage}: destruction stays terminal`);
    }

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
