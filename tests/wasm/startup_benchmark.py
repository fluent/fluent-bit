#!/usr/bin/env python3
"""Measure click-to-running startup in fresh Chromium processes over HTTPS."""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import statistics
import subprocess
import tempfile
import threading

from playwright.sync_api import sync_playwright

from browser_server import DEFAULT_BUILD_DIR, create_server, development_certificate, server_tls_context


def measure(build_dir, browser_path, runs, mbps, latency_ms):
    results = []
    with tempfile.TemporaryDirectory(prefix="flb-startup-tls-") as directory:
        cert, key = development_certificate(directory, ["localhost", "127.0.0.1"])
        public_key = subprocess.run(["openssl", "x509", "-in", str(cert), "-pubkey", "-noout"],
                                    check=True, capture_output=True).stdout
        public_der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"],
                                    input=public_key, check=True, capture_output=True).stdout
        pin = base64.b64encode(hashlib.sha256(public_der).digest()).decode()
        with create_server(build_dir, 0, tls_context=server_tls_context(cert, key)) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with sync_playwright() as playwright:
                    for run in range(runs):
                        # A fresh process also avoids the previous run's compiled WASM cache.
                        with playwright.chromium.launch(executable_path=browser_path, args=[
                                f"--ignore-certificate-errors-spki-list={pin}"]) as browser:
                            page = browser.new_page()
                            errors = []
                            page.on("pageerror", lambda error: errors.append(str(error)))
                            page.add_init_script("""window.addEventListener('fluent-bit-started', event => {
                                window.startupSample = event.detail;
                                window.startupSample.click_to_running_ms = performance.now() - window.startupClick;
                            });""")
                            page.goto(f"https://127.0.0.1:{server.server_port}/")
                            page.wait_for_function("!document.getElementById('start-demo').disabled")
                            page.locator('#demo-seconds').fill('30')
                            cdp = page.context.new_cdp_session(page)
                            cdp.send('Network.enable')
                            cdp.send('Network.setCacheDisabled', {'cacheDisabled': True})
                            if mbps:
                                cdp.send('Network.emulateNetworkConditions', {
                                    'offline': False, 'latency': latency_ms,
                                    'downloadThroughput': mbps * 1000000 / 8,
                                    'uploadThroughput': mbps * 1000000 / 8})
                            page.evaluate("window.startupClick = performance.now(); document.getElementById('start-demo').click()")
                            page.wait_for_function("window.startupSample !== undefined", timeout=45000)
                            sample = page.evaluate("window.startupSample")
                            assert all(sample[field] >= 0 for field in (
                                'preflight_ms', 'load_runtime_ms', 'engine_ms', 'click_to_running_ms')), sample
                            page.locator('#stop-demo').click()
                            page.wait_for_function("document.getElementById('status').dataset.state !== 'running'", timeout=20000)
                            assert page.locator('#status').get_attribute('data-state') == 'passed', page.locator('#output').inner_text()
                            assert not errors, errors
                            sample['run'] = run + 1
                            results.append(sample)
            finally:
                server.shutdown()
                thread.join()
    return {
        'build_dir': str(build_dir), 'wasm_file_bytes': (build_dir / 'sdk/browser/fluent-bit-runtime.wasm').stat().st_size,
        'download_mbps': mbps, 'latency_ms': latency_ms if mbps else 0,
        'runs': results,
        'median_ms': {field: statistics.median(sample[field] for sample in results) for field in (
            'click_to_running_ms', 'preflight_ms', 'load_runtime_ms', 'engine_ms')}
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=DEFAULT_BUILD_DIR)
    parser.add_argument('--browser', required=True)
    parser.add_argument('--runs', type=int, default=3)
    parser.add_argument('--download-mbps', type=float, default=0, help='0: unthrottled local HTTPS')
    parser.add_argument('--latency-ms', type=float, default=40)
    args = parser.parse_args()
    if args.runs < 1 or args.download_mbps < 0 or args.latency_ms < 0:
        parser.error('runs must be positive; bandwidth and latency must be nonnegative')
    print(json.dumps(measure(args.build_dir.resolve(), args.browser, args.runs,
                             args.download_mbps, args.latency_ms), indent=2))


if __name__ == '__main__':
    main()
