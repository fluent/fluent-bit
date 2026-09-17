#!/usr/bin/env python3
"""Exercise the public browser SDK against real WebAssembly, not a mocked engine."""
import argparse
import base64
import hashlib
import functools
import io
from pathlib import Path
import subprocess
import ssl
import tempfile
import threading

from playwright.sync_api import sync_playwright
from browser_server import DEFAULT_BUILD_DIR
from browser_server import BrowserHandler, create_server, development_certificate, server_tls_context


class PthreadFaultHandler(BrowserHandler):
    def handle(self):
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError):
            # Expected when a fault terminates workers during asset transfers.
            pass

    def send_head(self):
        if self.path == '/sdk/fluent-bit-pthread.js':
            self.server.pthread_requests += 1
            source = (self.server.pthread_source
                      if self.server.pthread_fail_at in (0, self.server.pthread_requests)
                      else self.server.pthread_bootstrap)
            if source is None:
                self.send_error(404, 'Injected missing pthread script')
                return None
            body = source.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/javascript')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            return io.BytesIO(body)
        return super().send_head()


class StorageFaultHandler(BrowserHandler):
    def send_head(self):
        if self.path == '/sdk/fluent-bit-worker.js':
            source = (self.build_dir / 'sdk/browser/fluent-bit-worker.js').read_text()
            original = 'await runtime.flbStorage.sync();'
            assert source.count(original) == 1
            source = source.replace(original, '''
                if (!self.injectedCheckpointFailure) {
                    self.injectedCheckpointFailure = true;
                    throw new DOMException('Injected quota failure', 'QuotaExceededError');
                }
                await runtime.flbStorage.sync();''')
            body = source.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/javascript')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            return io.BytesIO(body)
        return super().send_head()


def check_storage_failure(page):
    result = page.evaluate('''async () => {
        const {createFluentBit} = await import('/sdk/fluent-bit.js');
        const fluent = await createFluentBit({storage: {
            persistent: true, namespace: 'quota-' + crypto.randomUUID()}});
        const codes = [];
        const yaml = `pipeline:
  inputs:
    - name: lib
      alias: app
  outputs:
    - name: null
      match: '*'
`;
        try {
            await fluent.start({yaml, graceSeconds: 0});
            try { await fluent.stop(); } catch (error) { codes.push(error.code); }
            const failed = await fluent.getStats();
            try { await fluent.start({yaml}); } catch (error) { codes.push(error.code); }
            await fluent.syncStorage();
            const recovered = await fluent.getStats();
            await fluent.start({yaml, graceSeconds: 0});
            await fluent.push({input: 'app', records: [{message: 'after recovery'}]});
            return {codes, failed, recovered};
        }
        finally { await fluent.destroy(); }
    }''')
    assert result['codes'] == ['E_STORAGE', 'E_STORAGE'], result
    assert result['failed']['checkpointRequired'], result
    assert result['failed']['checkpointFailures'] == 1, result
    assert not result['recovered']['checkpointRequired'], result
    assert result['recovered']['lastCheckpointTime'] > 0, result
    print('Checkpoint failure, restart guard and storage recovery passed', flush=True)


def check_pthread_bootstrap(page, server, workers):
    bootstrap = (Path(__file__).resolve().parents[2] / 'sdk/browser/fluent-bit-pthread.js').read_text()
    server.pthread_bootstrap = bootstrap
    cases = [
        ('missing script', None, 'E_RUNTIME'),
        ('rejected payload', bootstrap.replace("report('boot');",
            "self.dispatchEvent(new MessageEvent('messageerror'));\nreport('boot');"), 'E_RUNTIME'),
        ('failed runtime import', bootstrap.replace("'./fluent-bit-runtime.js'",
            "'./missing-runtime.js'"), 'E_RUNTIME'),
        ('missing ready handshake', "self.postMessage({flbPthread: 1, stage: 'boot'});", 'E_TIMEOUT'),
        ('delayed ready handshake', """let readyForLoad = false;
            self.addEventListener('message', () => {
                if (!readyForLoad) self.postMessage({flbPthread: 1, stage: 'error', message: 'EARLY LOAD'});
            });
            await new Promise(resolve => setTimeout(resolve, 200));
            """ + bootstrap.replace("report('runtime-ready');", "readyForLoad = true; report('runtime-ready');"), None)
    ]
    cases = [(name, source, expected, position)
             for name, source, expected in cases
             for position in ([1, 4] if expected else [0])]
    for name, source, expected, position in cases:
        # Nested worker entry requests are not consistently intercepted by
        # Playwright page routing. Inject actual HTTP responses at the server.
        server.pthread_source = source
        server.pthread_fail_at = position
        server.pthread_requests = 0
        name = f'{name} (worker {position or "all"})'
        result = page.evaluate("""async timeout => {
            const {createFluentBit} = await import('/sdk/fluent-bit.js');
            const logs = [];
            const begin = performance.now();
            try {
                const fluent = await createFluentBit({initTimeoutMs: timeout, onStderr: line => logs.push(line)});
                await fluent.destroy();
                return {code: null, elapsed: performance.now() - begin, logs};
            }
            catch (error) { return {code: error.code, message: error.message,
                elapsed: performance.now() - begin, logs}; }
        }""", 500 if expected == 'E_TIMEOUT' else 10000)
        assert result['code'] == expected, (name, result)
        assert result['elapsed'] < 10000, (name, result)
        if name.startswith('rejected payload'):
            assert 'deserialize' in result['message'], result
        assert not any('ERROR: AddressSanitizer' in line or 'ERROR: LeakSanitizer' in line
                       for line in result['logs']), result
        print(f"Pthread bootstrap: {name}: passed ({result['elapsed']:.0f} ms)", flush=True)
        for _ in range(100):
            if not workers:
                break
            page.wait_for_timeout(50)
        assert not workers, f'{name}: workers survived teardown: {[w.url for w in workers]}'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=DEFAULT_BUILD_DIR)
    parser.add_argument('--browser', required=True)
    parser.add_argument('--pthread-only', action='store_true')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='flb-sdk-tls-') as directory:
        cert, key = development_certificate(directory, ['localhost', '127.0.0.1'])
        public = subprocess.run(['openssl', 'x509', '-in', str(cert), '-pubkey', '-noout'],
                                check=True, capture_output=True).stdout
        der = subprocess.run(['openssl', 'pkey', '-pubin', '-outform', 'DER'], input=public,
                             check=True, capture_output=True).stdout
        pin = base64.b64encode(hashlib.sha256(der).digest()).decode()
        with create_server(args.build_dir, 0, tls_context=server_tls_context(cert, key)) as server:
            if args.pthread_only:
                server.RequestHandlerClass = functools.partial(PthreadFaultHandler, build_dir=args.build_dir)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with sync_playwright() as playwright:
                    with playwright.chromium.launch(executable_path=args.browser,
                            args=[f'--ignore-certificate-errors-spki-list={pin}']) as browser:
                        page = browser.new_page()
                        page.set_default_timeout(120000)
                        page.on('console', lambda event: print(event.text, flush=True))
                        errors = []
                        workers = set()
                        def worker_started(worker):
                            workers.add(worker)
                            worker.on('close', lambda: workers.discard(worker))
                        page.on('worker', worker_started)
                        page.on('pageerror', lambda event: errors.append(str(event)))
                        page.goto(f'https://127.0.0.1:{server.server_port}/')
                        if args.pthread_only:
                            for _ in range(3):
                                check_pthread_bootstrap(page, server, workers)
                            assert not errors, errors
                            print('Pthread bootstrap faults and worker cleanup passed', flush=True)
                            return
                        result = page.evaluate(Path(__file__).with_suffix('.js').read_text())
                        assert result['passed'] and not errors, errors
                        server.RequestHandlerClass = functools.partial(StorageFaultHandler, build_dir=args.build_dir)
                        check_storage_failure(page)
                        server.RequestHandlerClass = functools.partial(BrowserHandler, build_dir=args.build_dir)
                        page.route('**/sdk/fluent-bit-runtime.wasm', lambda route: route.abort())
                        failure = page.evaluate("""async () => {
                            const {createFluentBit} = await import('/sdk/fluent-bit.js');
                            try { await createFluentBit(); return null; }
                            catch (error) { return error.code; }
                        }""")
                        assert failure in ('E_LOAD', 'E_RUNTIME', 'E_WORKER'), failure
                        for _ in range(100):
                            if not workers:
                                break
                            page.wait_for_timeout(50)
                        assert not workers, f'{len(workers)} SDK workers survived destroy'
                        print(result)
            finally:
                server.shutdown()
                thread.join()
    print('Browser SDK tests passed', flush=True)


if __name__ == '__main__':
    main()
