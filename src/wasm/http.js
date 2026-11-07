/* SPDX-License-Identifier: Apache-2.0 */
/* Fetch owns copies, never pointers into a coroutine's stack or the WASM heap. */
Module['flbBrowserHttp'] = (() => {
    const requests = new Map();
    let sequence = 0;
    const forbidden = /^(accept-charset|accept-encoding|access-control-request-.*|connection|content-length|cookie2?|date|dnt|expect|host|keep-alive|origin|permissions-policy|referer|set-cookie|te|trailer|transfer-encoding|upgrade|user-agent|via|proxy-.*|sec-.*)$/i;
    function validate(url) {
        try {
            const parsed = new URL(url);
            return parsed.protocol === 'https:' && !parsed.username && !parsed.password && !parsed.hash;
        } catch (_) { return false; }
    }
    function cancel(id) {
        const request = requests.get(id);
        if (!request) { return; }
        clearTimeout(request.timer);
        requests.delete(id);
        request.controller.abort();
    }
    return {
        validate,
        begin(owner, url, method, pairs, body, timeout, logResponse) {
            if (!validate(url) || !['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'].includes(method) || requests.size >= 32 ||
                body.byteLength > 8 * 1024 * 1024 || timeout < 1 || timeout > 120000) {
                return -1;
            }
            let headers;
            try {
                headers = new Headers();
                let bytes = 0;
                for (const [key, value] of pairs) {
                    // Existing clients set this header; browsers choose their own value.
                    if (key.toLowerCase() === 'user-agent') { continue; }
                    bytes += key.length + value.length;
                    if (forbidden.test(key) || /[\r\n\0]/.test(value) || bytes > 65536) {
                        throw new Error('Unsupported browser request header');
                    }
                    headers.append(key, value);
                }
            } catch (_) {
                err('[wasm_http] Invalid or browser-controlled request header');
                return -1;
            }
            const id = ++sequence;
            const request = {owner, controller: new AbortController(), status: 0, timer: null};
            requests.set(id, request);
            request.timer = setTimeout(() => request.controller.abort(), timeout);
            (async () => {
                try {
                    const response = await fetch(url, {method, headers,
                        body: ['GET', 'HEAD'].includes(method) ? undefined : body, mode: 'cors',
                        credentials: 'omit', redirect: 'error', cache: 'no-store',
                        referrerPolicy: 'no-referrer', signal: request.controller.signal});
                    const chunks = [];
                    let size = 0;
                    if (response.body) {
                        const reader = response.body.getReader();
                        for (;;) {
                            const part = await reader.read();
                            if (part.done) { break; }
                            size += part.value.byteLength;
                            if (size > 65536) {
                                await reader.cancel();
                                throw new Error('Response exceeds 64 KiB');
                            }
                            chunks.push(part.value);
                        }
                    }
                    if (requests.get(id) !== request) { return; }
                    const data = new Uint8Array(size);
                    let offset = 0;
                    for (const chunk of chunks) { data.set(chunk, offset); offset += chunk.byteLength; }
                    let responseHeaders = `HTTP/1.1 ${response.status}\r\n`;
                    for (const [key, value] of response.headers) {
                        // Fetch has already removed transfer framing and decoded content.
                        if (/^(content-length|content-encoding|transfer-encoding|connection)$/i.test(key)) { continue; }
                        responseHeaders += `${key}: ${value}\r\n`;
                        if (responseHeaders.length > 65536) { throw new Error('Response headers exceed 64 KiB'); }
                    }
                    responseHeaders += `content-length: ${size}\r\n\r\n`;
                    const prefix = new TextEncoder().encode(responseHeaders);
                    if (prefix.length > 65536) { throw new Error('Response headers exceed 64 KiB'); }
                    request.response = new Uint8Array(prefix.length + size);
                    request.response.set(prefix);
                    request.response.set(data, prefix.length);
                    request.headerLength = prefix.length;
                    if (logResponse && size) {
                        out('[wasm_http] response: ' + new TextDecoder().decode(data));
                    }
                    request.status = response.status || -1;
                } catch (error) {
                    if (requests.get(id) !== request) { return; }
                    request.status = -1;
                    err('[wasm_http] Request failed: ' + error.message);
                } finally { clearTimeout(request.timer); }
            })();
            return id;
        },
        poll(id) {
            const request = requests.get(id);
            if (!request) { return -1; }
            if (request.status) { requests.delete(id); }
            return request.status;
        },
        result(id) { return requests.get(id); },
        cancel,
        cancelOwner(owner) {
            for (const [id, request] of requests) { if (request.owner === owner) { cancel(id); } }
        },
        pending() { return requests.size; }
    };
})();
