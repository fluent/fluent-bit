#!/usr/bin/env python3
"""Run a WASM smoke test in a local headless Chromium browser."""

import argparse
import functools
import http.server
from pathlib import Path
import shutil
import threading
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright
from browser_server import DEFAULT_BUILD_DIR


PAGE = b"""<!doctype html>
<html><head><meta charset="utf-8"><title>Fluent Bit WASM dependency test</title></head>
<body data-result="pending"><pre id="output"></pre>
<script>
const output = document.getElementById('output');
var Module = {
    arguments: new URLSearchParams(location.search).has('phase') ?
        [new URLSearchParams(location.search).get('phase')] : new URLSearchParams(location.search).getAll('arg'),
    print: text => { output.textContent += text + '\\n'; },
    printErr: text => { output.textContent += text + '\\n'; },
    onAbort: reason => {
        document.body.dataset.result = 'failed';
        output.textContent += String(reason);
    },
    onExit: code => {
        const finish = () => {
            if (document.body.dataset.result !== 'failed') {
                document.body.dataset.result = code === 0 ? 'passed' : 'failed';
            }
        };
        if (code === 0 && Module.flbStorage) {
            Module.flbStorage.sync().then(finish, error => {
                document.body.dataset.result = 'failed';
                output.textContent += 'Storage sync failed: ' + error;
            });
        } else {
            finish();
        }
    }
};
window.addEventListener('error', event => {
    document.body.dataset.result = 'failed';
    output.textContent += event.message;
});
</script>
<script src="/bin/flb-wasm-dependencies.js"></script></body></html>
"""


class Handler(http.server.SimpleHTTPRequestHandler):
    page = PAGE

    def end_headers(self):
        # The current profile uses Emscripten's pthread ABI (SharedArrayBuffer).
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
        super().end_headers()

    def do_GET(self):
        if urlsplit(self.path).path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(self.page)))
            self.end_headers()
            self.wfile.write(self.page)
        else:
            super().do_GET()

    def log_message(self, format, *args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=DEFAULT_BUILD_DIR)
    parser.add_argument("--target", choices=("flb-wasm-dependencies", "co-wasm-test",
                                             "flb-wasm-pipeline", "flb-wasm-events", "flb-wasm-event-fiber",
                                             "flb-wasm-storage", "flb-wasm-yaml", "flb-wasm-lua", "flb-wasm-http",
                                             "flb-wasm-http-lifecycle", "flb-wasm-http-ng", "mk-test-wasm-events"),
                        default="flb-wasm-dependencies")
    parser.add_argument("--browser", default=shutil.which("chromium") or shutil.which("google-chrome"))
    args = parser.parse_args()
    if not args.browser:
        parser.error("Chromium not found; set --browser to the browser executable")

    build_dir = args.build_dir.resolve()
    for suffix in ("js", "wasm"):
        if not (build_dir / "bin" / f"{args.target}.{suffix}").is_file():
            parser.error(f"Build the {args.target} target first")

    Handler.page = PAGE.replace(b"flb-wasm-dependencies.js", f"{args.target}.js".encode())
    handler = functools.partial(Handler, directory=str(build_dir))
    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(executable_path=args.browser,
                                                      headless=True)
                page = browser.new_page()
                errors = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                try:
                    phases = ("write", "restore", "empty") if args.target == "flb-wasm-storage" else ("",)
                    passed = True
                    for phase in phases:
                        page.goto(f"http://127.0.0.1:{server.server_port}/?phase={phase}"
                                  if phase else f"http://127.0.0.1:{server.server_port}/" +
                                  ("?arg=--no-exec" if args.target == "flb-wasm-lua" else ""))
                        page.wait_for_function("document.body.dataset.result !== 'pending'",
                                               timeout=45000)
                        passed = passed and page.get_attribute("body", "data-result") == "passed"
                        print(page.locator("#output").inner_text())
                        if not passed:
                            break
                    if passed and args.target == "flb-wasm-storage":
                        # A quota/transaction failure must reject, and a later
                        # explicit retry must not inherit the rejected promise.
                        page.evaluate("""async () => {
                            const original = IDBDatabase.prototype.transaction;
                            let rejected = false;
                            IDBDatabase.prototype.transaction = function() {
                                throw new Error('injected storage transaction failure');
                            };
                            try { await Module.flbStorage.sync(); }
                            catch (error) { rejected = true; }
                            finally { IDBDatabase.prototype.transaction = original; }
                            if (!rejected) { throw new Error('Storage failure was hidden'); }
                            await Module.flbStorage.sync();
                        }""")
                finally:
                    browser.close()
        finally:
            server.shutdown()
            thread.join()

    if not passed or errors:
        print("\n".join(errors))
        raise SystemExit(f"Browser {args.target} smoke test failed")
    print(f"Browser {args.target} smoke test passed")


if __name__ == "__main__":
    main()
