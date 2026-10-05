/* SPDX-License-Identifier: Apache-2.0 */
/* Demo-only adapter: nested workers execute already fetched, same-origin assets. */
const queued = [];
const objectUrls = [];
const capture = event => { queued.push(event); event.stopImmediatePropagation(); };
self.addEventListener('message', capture, true);

function releaseAssets() {
    for (const url of objectUrls) { URL.revokeObjectURL(url); }
    objectUrls.length = 0;
}

async function javascriptAsset(path) {
    const response = await fetch(path, {redirect: 'error', cache: 'no-store'});
    if (!response.ok) { throw new Error(`Demo asset ${path}: HTTP ${response.status}`); }
    if (!/^(text|application)\/javascript(?:;|$)/i.test(response.headers.get('Content-Type') || '')) {
        throw new Error(`Demo asset ${path}: expected JavaScript, not an HTML fallback`);
    }
    const source = await response.text();
    if (source.length > 2 * 1024 * 1024) { throw new Error(`Demo asset ${path} exceeds 2 MiB`); }
    return source;
}

try {
    const [runtime, pthread] = await Promise.all([
        javascriptAsset('/sdk/fluent-bit-runtime.js'),
        javascriptAsset('/sdk/fluent-bit-pthread.js')
    ]);
    const runtimeUrl = URL.createObjectURL(new Blob([runtime], {type: 'text/javascript'}));
    objectUrls.push(runtimeUrl);
    const pthreadUrl = URL.createObjectURL(new Blob([
        `globalThis.flbPthreadRuntimeUrl = ${JSON.stringify(runtimeUrl)};\n`, pthread
    ], {type: 'text/javascript'}));
    objectUrls.push(pthreadUrl);
    const BrowserWorker = self.Worker;
    const entry = new URL('/sdk/fluent-bit-pthread.js', self.location.href).href;
    self.Worker = class extends BrowserWorker {
        constructor(url, options) {
            super(String(url) === entry ? pthreadUrl : url, options);
        }
    };
    await import('/sdk/fluent-bit-worker.js');
    const handleMessage = self.onmessage;
    self.onmessage = async event => {
        try { await handleMessage(event); }
        finally {
            if (event.data?.type === 'request' && event.data.method === 'destroy') { releaseAssets(); }
        }
    };
    self.removeEventListener('message', capture, true);
    for (const event of queued) { self.dispatchEvent(new MessageEvent('message', {data: event.data})); }
    queued.length = 0;
}
catch (error) {
    releaseAssets();
    self.postMessage({abi: 1, type: 'fatal', code: 'E_LOAD', message: error.message});
}
