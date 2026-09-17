'use strict';

const params = new URLSearchParams(location.search);
const target = params.get('target');
const phase = params.get('phase') || '';
const token = params.get('token');
let finished = false;
let demoStarted = false;
const startupBegin = performance.now();
let scriptBegin;
let runtimeReady;

function send(type, fields) {
    parent.postMessage({token, type, ...fields}, location.origin);
}
function fail(error) {
    if (finished) { return; }
    finished = true;
    send('done', {ok: false, error: String(error)});
}

window.addEventListener('error', event => fail(event.message));
window.addEventListener('unhandledrejection', event => fail(event.reason));

async function finish(code) {
    if (finished) { return; }
    if (code !== 0) { fail(`C test exited with code ${code}`); return; }
    try {
        if (Module.flbBrowserHttp && Module.flbBrowserHttp.pending() !== 0) {
            throw new Error('HTTP requests were not cancelled during engine shutdown');
        }
        if (target === 'flb-wasm-storage') {
            if (!Module.flbStorage || !Module.flbStorage.persistent) {
                throw new Error('Persistent storage was not mounted');
            }
            // C has closed its chunks and quiesced writers before onExit.
            await Module.flbStorage.sync();
            send('log', {text: 'IndexedDB checkpoint complete.'});
            if (phase === 'empty') {
                const original = IDBDatabase.prototype.transaction;
                let rejected = false;
                IDBDatabase.prototype.transaction = function() {
                    throw new Error('Injected storage transaction failure');
                };
                try { await Module.flbStorage.sync(); }
                catch (error) { rejected = true; }
                finally { IDBDatabase.prototype.transaction = original; }
                if (!rejected) { throw new Error('Storage commit failure was hidden'); }
                await Module.flbStorage.sync();
                send('log', {text: 'Commit failure reported; explicit retry succeeded.'});
            }
        }
        if (!finished) {
            finished = true;
            send('done', {ok: true});
        }
    } catch (error) { fail(error); }
}

async function start() {
    if (!['flb-wasm-yaml', 'flb-wasm-pipeline', 'flb-wasm-storage', 'flb-wasm-demo'].includes(target) ||
        (target === 'flb-wasm-storage' ? !['write', 'restore', 'empty'].includes(phase) : phase !== '')) {
        throw new Error('Invalid test target or phase');
    }
    for (const extension of ['js', 'wasm']) {
        const response = await fetch(`/bin/${target}.${extension}`, {method: 'HEAD'});
        if (!response.ok) {
            throw new Error(`Missing ${target}.${extension}. Run: cmake --build build-wasm --target ${target} -j8`);
        }
    }
    let demo = null;
    if (target === 'flb-wasm-demo') {
        demo = await new Promise(resolve => {
            function receive(event) {
                if (event.origin !== location.origin || event.source !== parent ||
                    !event.data || event.data.token !== token || event.data.type !== 'demo-config') {
                    return;
                }
                window.removeEventListener('message', receive);
                resolve(event.data);
            }
            window.addEventListener('message', receive);
            send('ready', {});
        });
        if (typeof demo.yaml !== 'string' || !demo.yaml.trim() || demo.yaml.includes('\0') ||
            new TextEncoder().encode(demo.yaml).length > 65536 ||
            !Number.isInteger(demo.seconds) || demo.seconds < 1 || demo.seconds > 300) {
            throw new Error('Invalid demo configuration or duration');
        }
        window.addEventListener('message', event => {
            if (event.origin === location.origin && event.source === parent && event.data &&
                event.data.token === token && event.data.type === 'demo-stop' &&
                demoStarted && !finished) {
                Module._flb_wasm_demo_request_stop();
            }
        });
    }
    window.Module = {
        arguments: demo ? [demo.yaml, String(demo.seconds)] : (phase ? [phase] : []),
        flbStoragePersistent: target === 'flb-wasm-storage',
        print: text => send('log', {text}),
        printErr: text => send('log', {text}),
        onAbort: fail,
        onExit: finish,
        onRuntimeInitialized: () => { runtimeReady = performance.now(); },
        onDemoState: (state, engineTiming) => {
            demoStarted = state === 1;
            const now = performance.now();
            const wasm = performance.getEntriesByType('resource').filter(
                entry => new URL(entry.name).pathname === `/bin/${target}.wasm` &&
                    entry.encodedBodySize > 0).pop();
            send(state === 1 ? 'started' : 'stopping', {startup: state === 1 ? {
                total_ms: now - startupBegin,
                preflight_ms: scriptBegin - startupBegin,
                load_runtime_ms: runtimeReady - scriptBegin,
                engine_ms: now - runtimeReady,
                engine_detail: engineTiming || null,
                wasm_download_ms: wasm ? wasm.responseEnd - wasm.startTime : null,
                wasm_bytes: wasm ? wasm.encodedBodySize : null
            } : null});
        }
    };
    const script = document.createElement('script');
    scriptBegin = performance.now();
    script.src = `/bin/${target}.js`;
    script.onerror = () => fail(`Unable to load ${target}.js`);
    document.body.append(script);
}
start().catch(fail);
