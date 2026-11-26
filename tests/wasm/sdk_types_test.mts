import {createFluentBit, FluentBitError, getBrowserSupport} from '../../sdk/browser/fluent-bit.js';
import type {FluentBit, FluentBitState} from '../../sdk/browser/fluent-bit.js';

async function application(): Promise<void> {
    const support: boolean = getBrowserSupport().supported;
    if (!support) {
        throw new FluentBitError('E_UNSUPPORTED', 'Browser lacks required features');
    }
    const fluent: FluentBit = await createFluentBit({
        workerUrl: new URL('./fluent-bit-worker.js', import.meta.url),
        storage: {persistent: true, namespace: 'type-test'}, outputLineLimit: 65536,
        onStateChange: (state: FluentBitState) => { void state; },
        onError: error => { void error.code; },
        onProgress: progress => { const bytes: number = progress.loadedBytes; void bytes; }
    });
    await fluent.writeFile('/config/example.lua', 'function process() end');
    const bytes: Uint8Array = await fluent.readFile('/config/example.lua');
    const result: {engineMs: number} = await fluent.start({yaml: '', graceSeconds: 1});
    const accepted: number = (await fluent.push({input: 'app', records: [{message: 'hello'}]})).acceptedRecords;
    const drained: void = await fluent.drain();
    await fluent.stop();
    await fluent.syncStorage();
    const traced: {engineMs: number} = await fluent.start({yaml: '', trace: true});
    const supported: boolean = fluent.info.features.includes('condition');
    const matched: readonly boolean[] = (await fluent.evaluateCondition({
        condition: {rules: [{field: '$level', op: 'eq', value: 'error'}]},
        records: [{level: 'error'}], metadata: [null]})).matched;
    const status: string = (await fluent.getTopology()).inputs[0].routes[0].outputs[0].status;
    for (const event of (await fluent.takeTrace()).events) {
        if (event.stage === 'route') { const record: number = event.record; void record; }
        if (event.stage === 'filter') { const kept: number = event.recordsOut; void kept; }
    }
    const otlp: number = (await fluent.pushOtlp({input: 'app', signal: 'metrics',
        payload: {resourceMetrics: []}})).acceptedBytes;
    await fluent.pushOtlp({input: 'app', signal: 'traces', payload: '{"resourceSpans":[]}'});
    void [traced, supported, matched, status, otlp];
    const heap: number = (await fluent.getStats()).wasmMemoryBytes;
    await fluent.destroy();
    void [bytes, result, accepted, drained, heap];
    // @ts-expect-error Only JSON object records are accepted.
    await fluent.push({input: 'app', records: ['text']});
    // @ts-expect-error Logs are pushed as records.
    await fluent.pushOtlp({input: 'app', signal: 'logs', payload: {}});
    // @ts-expect-error A condition is an object, not YAML text.
    await fluent.evaluateCondition({condition: 'default: true', records: []});
    // @ts-expect-error Persistent storage requires a namespace.
    await createFluentBit({storage: {persistent: true}});
}

void application;
