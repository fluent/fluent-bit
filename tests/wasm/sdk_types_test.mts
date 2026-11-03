import {createFluentBit, FluentBitError, getBrowserSupport} from '../../sdk/browser/fluent-bit.js';
import type {FluentBit, FluentBitState} from '../../sdk/browser/fluent-bit.js';

async function application(): Promise<void> {
    const support: boolean = getBrowserSupport().supported;
    if (!support) {
        throw new FluentBitError('E_UNSUPPORTED', 'Browser lacks required features');
    }
    const fluent: FluentBit = await createFluentBit({
        workerUrl: new URL('./fluent-bit-worker.js', import.meta.url),
        storage: {persistent: true, namespace: 'type-test'},
        onStateChange: (state: FluentBitState) => { void state; },
        onError: error => { void error.code; },
        onProgress: progress => { const bytes: number = progress.loadedBytes; void bytes; }
    });
    await fluent.writeFile('/config/example.lua', 'function process() end');
    const bytes: Uint8Array = await fluent.readFile('/config/example.lua');
    const result: {engineMs: number} = await fluent.start({yaml: '', graceSeconds: 1});
    const accepted: number = (await fluent.push({input: 'app', records: [{message: 'hello'}]})).acceptedRecords;
    await fluent.stop();
    await fluent.syncStorage();
    const heap: number = (await fluent.getStats()).wasmMemoryBytes;
    await fluent.destroy();
    void [bytes, result, accepted, heap];
    // @ts-expect-error Only JSON object records are accepted.
    await fluent.push({input: 'app', records: ['text']});
    // @ts-expect-error Persistent storage requires a namespace.
    await createFluentBit({storage: {persistent: true}});
}

void application;
