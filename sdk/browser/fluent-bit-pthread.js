/* SPDX-License-Identifier: Apache-2.0 */
/* Private Emscripten 6.0.9 pthread bootstrap. Never run an engine here. */
let failed = false;
function report(stage, message = '') {
    self.postMessage({flbPthread: 1, stage, message});
    if (stage === 'error') {
        failed = true;
        self.close();
    }
}
self.addEventListener('messageerror', () => report('error',
    `Unable to deserialize shared WASM payload (crossOriginIsolated=${self.crossOriginIsolated})`));
self.addEventListener('unhandledrejection', event => {
    event.preventDefault();
    report('error', String(event.reason?.stack || event.reason));
});
self.addEventListener('error', event => report('error', event.message || 'Pthread JavaScript error'));
self.addEventListener('message', event => {
    if (event.data?.flbShutdown === 1) {
        event.stopImmediatePropagation();
        self.postMessage({flbPthread: 1, stage: 'closed'});
        self.close();
        return;
    }
    // CMD_LOAD in the pinned Emscripten 6.0.9 libpthread.js.
    if (event.data?.cmd === 1) { report('load-received'); }
});

report('boot');
try {
    if (failed) { throw new Error('Pthread bootstrap cancelled'); }
    if (!self.crossOriginIsolated || typeof SharedArrayBuffer !== 'function') {
        throw new Error('Pthread worker is not cross-origin isolated');
    }
    // The generated module recognizes the em-pthread name and installs its
    // message handler synchronously. The parent sends load only after this ack.
    // The demo can supply an already fetched blob module. Normal SDK workers
    // continue to load their same-origin runtime asset directly.
    await import(globalThis.flbPthreadRuntimeUrl || './fluent-bit-runtime.js');
    if (typeof self.onmessage !== 'function') {
        throw new Error('Runtime did not install the pthread message handler');
    }
    report('runtime-ready');
}
catch (error) { report('error', String(error.stack || error)); }
