'use strict';

const output = document.getElementById('output');
const status = document.getElementById('status');
const buttons = [...document.querySelectorAll('button[data-test]')];
const checks = [
    ['Secure context', window.isSecureContext],
    ['Cross-origin isolation', window.crossOriginIsolated],
    ['WebAssembly', typeof WebAssembly === 'object'],
    ['Workers', typeof Worker === 'function'],
    ['SharedArrayBuffer', typeof SharedArrayBuffer === 'function'],
    ['IndexedDB', typeof indexedDB === 'object']
];
let busy = false;
let stopDemo = null;
let demoClient = null;
let demoExample = null;
let luaExample = null;
let httpExample = null;
let httpCapture = null;
let receiverTimer = null;
const editor = document.getElementById('demo-config');
const duration = document.getElementById('demo-seconds');
const ready = checks.slice(0, 5).every(([, available]) => available);
const storageReady = ready && checks[5][1];

for (const [name, available] of checks) {
    const item = document.createElement('li');
    item.textContent = `${available ? '✓' : '✕'} ${name}`;
    item.dataset.ok = String(Boolean(available));
    document.getElementById('checks').append(item);
}
document.getElementById('requirements-note').textContent = ready ?
    'API availability checked. Each test verifies actual runtime behavior; storage access may still be denied.' :
    'Browser requirements missing. Start browser_server.py and use its HTTPS URL with a trusted certificate in a supported browser.';

function updateButtons() {
    for (const button of buttons) {
        const needsStorage = ['storage', 'recover'].includes(button.dataset.test);
        button.disabled = busy || !(needsStorage ? storageReady : ready);
    }
    document.getElementById('start-demo').disabled = busy || !ready || demoExample === null;
    document.getElementById('stop-demo').disabled = stopDemo === null;
    document.getElementById('release-demo').disabled = busy || demoClient === null;
    document.getElementById('reset-demo').disabled = busy || demoExample === null;
    document.getElementById('load-lua-demo').disabled = busy || luaExample === null;
    document.getElementById('load-http-demo').disabled = busy || httpExample === null;
    editor.disabled = busy || demoExample === null;
    duration.disabled = busy;
}

function log(text) {
    // Treat C output as text, never HTML. Bound the visible log for long/error runs.
    output.textContent = (output.textContent + String(text).replace(/\x1b\[[0-9;]*m/g, '') + '\n').slice(-150000);
    output.scrollTop = output.scrollHeight;
}

function waitForStartup(promise, signal) {
    return new Promise((resolve, reject) => {
        const aborted = () => reject(signal.reason);
        Promise.resolve(promise).then(resolve, reject).finally(() => {
            signal.removeEventListener('abort', aborted);
        });
        if (signal.aborted) { aborted(); return; }
        signal.addEventListener('abort', aborted, {once: true});
    });
}

function runFrame(target, phase = '', demo = null) {
    return new Promise((resolve, reject) => {
        const frame = document.createElement('iframe');
        const token = crypto.randomUUID();
        frame.title = `${target} ${phase}`;
        let timer;
        function finish(error) {
            clearTimeout(timer);
            window.removeEventListener('message', onMessage);
            // Destroy the module and its worker-owning document between phases.
            frame.remove();
            if (demo) { stopDemo = null; }
            if (error) { reject(error); }
            else { resolve(); }
        }
        function onMessage(event) {
            if (event.origin !== location.origin || event.source !== frame.contentWindow ||
                !event.data || event.data.token !== token) {
                return;
            }
            if (event.data.type === 'log') { log(event.data.text); }
            else if (event.data.type === 'ready' && demo) {
                frame.contentWindow.postMessage({token, type: 'demo-config', ...demo}, location.origin);
            }
            else if (event.data.type === 'started' && demo) {
                status.textContent = 'Running demo';
                if (event.data.startup) {
                    const timing = event.data.startup;
                    status.dataset.startupMs = String(timing.total_ms);
                    log(`Startup: ${(timing.total_ms / 1000).toFixed(2)}s ` +
                        `(preflight ${timing.preflight_ms.toFixed(0)}ms, ` +
                        `load/runtime ${timing.load_runtime_ms.toFixed(0)}ms, ` +
                        `engine ${timing.engine_ms.toFixed(0)}ms)`);
                }
                clearTimeout(timer);
                timer = setTimeout(() => finish(new Error('Demo exceeded its runtime and shutdown limit')),
                                   (demo.seconds + 15) * 1000);
                stopDemo = () => {
                    stopDemo = null;
                    status.textContent = 'Stopping…';
                    updateButtons();
                    frame.contentWindow.postMessage({token, type: 'demo-stop'}, location.origin);
                    clearTimeout(timer);
                    timer = setTimeout(() => finish(new Error('Demo did not stop cleanly within 15 seconds')), 15000);
                };
                updateButtons();
            }
            else if (event.data.type === 'stopping' && demo) {
                stopDemo = null;
                status.textContent = 'Stopping…';
                updateButtons();
                clearTimeout(timer);
                timer = setTimeout(() => finish(new Error('Demo did not stop cleanly within 15 seconds')), 15000);
            }
            else if (event.data.type === 'done') {
                finish(event.data.ok ? null : new Error(event.data.error || 'WASM test failed'));
            }
        }
        window.addEventListener('message', onMessage);
        timer = setTimeout(() => finish(new Error('Test timed out after 45 seconds')), 45000);
        frame.src = '/runner.html?' + new URLSearchParams({target, phase, token});
        document.getElementById('runner-host').append(frame);
    });
}

async function runDemo() {
    if (busy) { return; }
    const yaml = editor.value;
    const seconds = Number(duration.value);
    output.textContent = '';
    if (!yaml.trim() || yaml.includes('\0') || new TextEncoder().encode(yaml).length > 65536 ||
        !Number.isInteger(seconds) || seconds < 1 || seconds > 300) {
        status.dataset.state = 'failed';
        status.textContent = 'Invalid settings';
        log('Use nonempty YAML without NUL bytes (max 64 KiB) and 1–300 whole seconds.');
        return;
    }
    busy = true;
    const startup = new AbortController();
    let cancelled = false;
    let started = false;
    let stage = '';
    const begin = performance.now();
    stopDemo = () => {
        cancelled = true;
        startup.abort(new Error('Startup cancelled. You can retry Start.'));
    };
    const startupTimer = setTimeout(() => startup.abort(new Error(
        `Startup timed out after 45 seconds: ${stage}. Check failed or pending requests ` +
        'in browser DevTools (Network/Console), including certificate and worker errors.')),
        45000);
    const progressTimer = setInterval(() => {
        const elapsed = Math.floor((performance.now() - begin) / 1000);
        status.textContent = `${stage}… (${elapsed}s)`;
        if (elapsed === 5) {
            log(`Still waiting: ${stage}. Stop can cancel startup. ` +
                'If this persists, check DevTools Network/Console for blocked SDK assets or worker errors.');
        }
    }, 1000);
    function startupStage(name) {
        if (stage === name) { return; }
        stage = name;
        status.textContent = `${stage}…`;
        log(stage);
    }
    updateButtons();
    status.dataset.state = 'running';
    if (httpCapture) { receiverTimer = setInterval(readReceiver, 750); }
    log('Starting edited YAML through the browser SDK. Stdout/stderr will appear here.');
    log(`Browser: ${navigator.userAgent}`);
    let failed = false;
    try {
        startupStage('Loading SDK JavaScript');
        const {createFluentBit} = await waitForStartup(import('/sdk/fluent-bit.js'), startup.signal);
        const loaded = performance.now();
        if (!demoClient || ['failed', 'destroyed'].includes(demoClient.state)) {
            if (demoClient) { await demoClient.destroy({force: true}); }
            startupStage('Loading WASM and initializing workers');
            demoClient = await createFluentBit({
                workerUrl: new URL('/demo-sdk-worker.js', location.href),
                signal: startup.signal,
                onProgress: progress => {
                    const labels = {
                        'loading-runtime': 'Loading runtime JavaScript',
                        'downloading-wasm': 'Downloading WASM',
                        'compiling-wasm': 'Compiling WASM',
                        'initializing-workers': 'Initializing pthread workers',
                        'starting-command-thread': 'Starting C command thread'
                    };
                    const name = labels[progress.stage];
                    if (progress.stage === 'downloading-wasm') {
                        if (!stage.startsWith(name)) { log(name); }
                        const loaded = (progress.loadedBytes / 1048576).toFixed(1);
                        const total = progress.totalBytes ? ` / ${(progress.totalBytes / 1048576).toFixed(1)}` : '';
                        stage = `${name}: ${loaded}${total} MiB`;
                        status.textContent = stage;
                    }
                    else { startupStage(name); }
                },
                onStdout: log, onStderr: log,
                onError: error => {
                    log(`SDK ${error.code}: ${error.message}`);
                    if (error.message.includes('worker script failed to load')) {
                        log('Check certificate trust, CSP, and missing worker assets. In Chrome, proceeding ' +
                            'past a self-signed certificate warning can load this page while blocking nested ' +
                            'pthread workers. Use a certificate trusted by your browser.');
                    }
                },
                onStateChange: state => {
                    // A runtime failure is not a user pressing Stop. During
                    // startup, let the failing SDK promise retain its error.
                    if (started && state === 'failed' && stopDemo) { stopDemo(); }
                }
            });
        }
        const readyAt = performance.now();
        startupStage('Starting Fluent Bit engine');
        const result = await waitForStartup(demoClient.start({yaml, graceSeconds: 1}), startup.signal);
        started = true;
        clearTimeout(startupTimer);
        clearInterval(progressTimer);
        const now = performance.now();
        const timing = {total_ms: now - begin, preflight_ms: loaded - begin,
            load_runtime_ms: readyAt - loaded, engine_ms: now - readyAt,
            engine_detail: {total_ms: result.engineMs}};
        status.textContent = 'Running demo';
        status.dataset.startupMs = String(timing.total_ms);
        log(`Startup: ${(timing.total_ms / 1000).toFixed(2)}s ` +
            `(preflight ${timing.preflight_ms.toFixed(0)}ms, ` +
            `load/runtime ${timing.load_runtime_ms.toFixed(0)}ms, ` +
            `engine ${timing.engine_ms.toFixed(0)}ms)`);
        window.dispatchEvent(new CustomEvent('fluent-bit-started', {detail: timing}));
        await new Promise(resolve => {
            const timer = setTimeout(() => stopDemo?.(), seconds * 1000);
            stopDemo = () => {
                clearTimeout(timer);
                stopDemo = null;
                status.textContent = 'Stopping…';
                updateButtons();
                resolve();
            };
            updateButtons();
        });
        await demoClient.stop();
        log('Demo stopped cleanly. Edit the YAML and Start to run again.');
    } catch (error) {
        failed = !cancelled;
        log(`${cancelled ? 'Stopped' : 'FAIL'}: ${startup.signal.aborted ? startup.signal.reason.message : error.message}`);
        if (!started && demoClient) {
            await demoClient.destroy({force: true});
            demoClient = null;
        }
    } finally {
        clearTimeout(startupTimer);
        clearInterval(progressTimer);
        clearInterval(receiverTimer);
        receiverTimer = null;
        if (httpCapture) { await readReceiver(); }
        stopDemo = null;
        busy = false;
        status.dataset.state = failed ? 'failed' : 'passed';
        status.textContent = failed ? 'Demo failed' : 'Stopped';
        updateButtons();
    }
}

document.getElementById('start-demo').addEventListener('click', runDemo);
document.getElementById('stop-demo').addEventListener('click', () => { if (stopDemo) { stopDemo(); } });
document.getElementById('release-demo').addEventListener('click', async () => {
    if (busy || !demoClient) { return; }
    busy = true;
    updateButtons();
    try {
        await demoClient.destroy();
        log('SDK runtime and workers released. The next Start will load a fresh instance.');
    }
    catch (error) { status.dataset.state = 'failed'; log(`FAIL: ${error.message}`); }
    finally { demoClient = null; busy = false; updateButtons(); }
});
document.getElementById('reset-demo').addEventListener('click', () => { httpCapture = null; editor.value = demoExample; });
document.getElementById('load-lua-demo').addEventListener('click', () => { httpCapture = null; editor.value = luaExample; });
document.getElementById('load-http-demo').addEventListener('click', () => {
    httpCapture = crypto.randomUUID();
    editor.value = httpExample.replace('__HTTP_URL__', JSON.stringify(`${location.origin}/collect/${httpCapture}`));
    document.getElementById('http-receiver').open = true;
    readReceiver();
});

async function readReceiver() {
    if (!httpCapture) { return; }
    const capture = httpCapture;
    try {
        const response = await fetch(`/received/${capture}`, {signal: AbortSignal.timeout(3000)});
        if (!response.ok) { throw new Error(`HTTP ${response.status}`); }
        const data = await response.json();
        if (capture === httpCapture) {
            document.getElementById('received-output').textContent = JSON.stringify(data, null, 2);
        }
    } catch (error) {
        if (capture === httpCapture) {
            document.getElementById('received-output').textContent = `Receiver unavailable: ${error.message}`;
        }
    }
}
editor.addEventListener('keydown', event => {
    if (event.key === 'Tab') {
        event.preventDefault();
        editor.setRangeText('  ', editor.selectionStart, editor.selectionEnd, 'end');
    }
});

fetch('/demo.yaml').then(response => {
    if (!response.ok) { throw new Error(`HTTP ${response.status}`); }
    return response.text();
}).then(text => {
    demoExample = text;
    editor.value = text;
    updateButtons();
}).catch(error => { editor.value = `Example unavailable: ${error.message}`; });

fetch('/demo-lua.yaml').then(response => {
    if (!response.ok) { throw new Error(`HTTP ${response.status}`); }
    return response.text();
}).then(text => {
    luaExample = text;
    updateButtons();
}).catch(error => { document.getElementById('load-lua-demo').title = `Example unavailable: ${error.message}`; });

fetch('/demo-http.yaml').then(response => {
    if (!response.ok) { throw new Error(`HTTP ${response.status}`); }
    return response.text();
}).then(text => {
    httpExample = text;
    updateButtons();
}).catch(error => { document.getElementById('load-http-demo').title = `Example unavailable: ${error.message}`; });

async function runTest(test) {
    if (busy) { return; }
    busy = true;
    updateButtons();
    output.textContent = '';
    status.dataset.state = 'running';
    status.textContent = 'Running';
    try {
        if (test === 'storage' || test === 'recover') {
            const phases = test === 'storage' ? ['write', 'restore', 'empty'] : ['restore', 'empty'];
            for (const phase of phases) {
                log(`── Storage: ${phase} / fresh test document ──`);
                await runFrame('flb-wasm-storage', phase);
            }
            log('Verified recovery, deletion, and IndexedDB commit failure/retry.');
        } else {
            const target = test === 'yaml' ? 'flb-wasm-yaml' : 'flb-wasm-pipeline';
            log(`── ${target} ──`);
            if (test === 'yaml') { log('The initial malformed-YAML error is expected.'); }
            await runFrame(target);
        }
        status.dataset.state = 'passed';
        status.textContent = 'Passed';
        log('PASS');
    } catch (error) {
        status.dataset.state = 'failed';
        status.textContent = 'Failed';
        log(`FAIL: ${error.message}`);
        if (test === 'storage') {
            log('If a previous run was interrupted, try “Recover & delete interrupted test chunk”.');
        }
    } finally {
        busy = false;
        updateButtons();
    }
}

for (const button of buttons) {
    button.addEventListener('click', () => runTest(button.dataset.test));
}
updateButtons();
fetch('/processors.yaml').then(response => {
    if (!response.ok) { throw new Error(`HTTP ${response.status}`); }
    return response.text();
}).then(text => { document.getElementById('yaml-source').textContent = text; })
    .catch(error => { document.getElementById('yaml-source').textContent = `Fixture unavailable: ${error.message}`; });
