#!/usr/bin/env python3
"""Exercise the manual test page in Chromium (including visible failure states)."""

import argparse
import base64
from contextlib import ExitStack
import hashlib
import json
import gzip
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
from urllib.error import HTTPError
from urllib.request import urlopen
from urllib.parse import urlsplit

from playwright.sync_api import Error as PlaywrightError, sync_playwright

from browser_server import DEFAULT_BUILD_DIR, create_server, development_certificate, server_tls_context


def assert_no_sanitizer_errors(output):
    # Expected configuration failures must not hide unrelated sanitizer failures.
    markers = ("ERROR: AddressSanitizer", "ERROR: LeakSanitizer",
               "SUMMARY: AddressSanitizer", "AddressSanitizer: CHECK failed",
               "AddressSanitizer:DEADLYSIGNAL", "ASan is ignoring requested")
    assert not any(marker in output for marker in markers), output


def click_test(page, name, expected="passed"):
    page.locator(name).click()
    page.wait_for_function(
        "['passed', 'failed'].includes(document.getElementById('status').dataset.state)",
        timeout=150000,
    )
    output = page.locator("#output").inner_text()
    assert page.locator("#status").get_attribute("data-state") == expected, output
    assert_no_sanitizer_errors(output)
    assert page.locator(name).is_enabled()
    print(f"{name}: {expected}", flush=True)
    return output


def demo_records(output):
    records = []
    for line in output.splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and "message" in value:
            records.append(value)
    return records


def check_certificate_warning(playwright, browser_path, url):
    # Reproduce a human clicking through the warning, without certificate pins
    # or ignore-certificate flags. Verify the demo adapter works in that state.
    with playwright.chromium.launch(executable_path=browser_path) as browser:
        page = browser.new_page()
        try:
            page.goto(url)
        except PlaywrightError as error:
            assert 'ERR_CERT_AUTHORITY_INVALID' in str(error), error
        else:
            raise AssertionError('The temporary test certificate was unexpectedly trusted')
        page.locator('#details-button').click()
        page.locator('#proceed-link').click()
        failure = page.evaluate("""async () => {
            const {createFluentBit} = await import('/sdk/fluent-bit.js');
            try { const fluent = await createFluentBit(); await fluent.destroy(); return null; }
            catch (error) { return error.message; }
        }""")
        assert failure and 'worker script failed to load' in failure, failure
        page.locator('#demo-seconds').fill('2')
        for _ in range(2):
            output = click_test(page, '#start-demo')
            assert demo_records(output), output
        page.locator('#release-demo').click()
        page.wait_for_function('!busy')
        assert_no_sanitizer_errors(page.locator('#output').inner_text())
        assert page.evaluate('demoClient === null')
        assert demo_records(click_test(page, '#start-demo'))
        page.locator('#release-demo').click()
        page.wait_for_function('!busy')
        assert_no_sanitizer_errors(page.locator('#output').inner_text())
        print('Certificate warning: direct nested workers fail; demo runs, restarts and releases cleanly', flush=True)


def check_startup_failures(browser, url):
    for asset, timeout in (("fluent-bit.js", False), ("fluent-bit.js", True),
                           ("fluent-bit-runtime.wasm", False)):
        page = browser.new_page()
        errors = []
        held = []
        page.on('pageerror', lambda error: errors.append(str(error)))
        if timeout:
            # Accelerate only the UI startup deadline, not browser/network clocks.
            page.add_init_script("""const originalTimeout = window.setTimeout;
                window.setTimeout = (callback, delay, ...args) =>
                    originalTimeout(callback, delay === 45000 ? 300 : delay, ...args);""")
        page.route('**/sdk/' + asset, lambda route: held.append(route))
        try:
            page.goto(url)
            page.locator('#start-demo').click()
            for _ in range(50):
                if held:
                    break
                page.wait_for_timeout(100)
            assert held, f'Did not intercept {asset}'
            if not timeout:
                assert page.locator('#stop-demo').is_enabled()
                page.locator('#stop-demo').click()
            page.wait_for_function("!busy", timeout=5000)
            output = page.locator('#output').inner_text()
            expected = 'failed' if timeout else 'passed'
            assert page.locator('#status').get_attribute('data-state') == expected, output
            assert ('Startup timed out' if timeout else 'Startup cancelled') in output, output
            assert page.locator('#start-demo').is_enabled()
            assert page.locator('#stop-demo').is_disabled()
            # A delayed import completing after cancellation must not start an engine.
            for route in held:
                try:
                    route.continue_()
                except Exception:
                    pass  # Worker termination can cancel the held request.
            page.wait_for_timeout(200)
            assert page.evaluate('demoClient === null')
            assert not errors, errors
        finally:
            page.close()
    print('Startup faults passed: stalled SDK import, full startup deadline, cancelled WASM load', flush=True)


def check_demo(page):
    page.wait_for_function("!document.getElementById('start-demo').disabled")
    example = page.locator("#demo-config").input_value()
    page.locator("#demo-seconds").fill("3")
    records = demo_records(click_test(page, "#start-demo"))
    assert records and all(record["runtime"] == "browser" for record in records)
    edited = example.replace("Hello from WASM", "Edited café ☃").replace("value: browser", "value: playground")
    page.locator("#demo-config").fill(edited)
    page.locator("#demo-seconds").fill("30")
    page.locator("#start-demo").click()
    try:
        page.wait_for_function(r"""() => document.getElementById('output').textContent.split('\n').some(line => {
            try { return JSON.parse(line).message === 'Edited café ☃'; }
            catch (_) { return false; }
        })""", timeout=45000)
    except Exception as error:
        raise AssertionError(page.locator("#output").inner_text()) from error
    assert page.locator("#demo-config").is_disabled()
    assert page.locator("#run-yaml").is_disabled()
    page.locator("#stop-demo").click()
    page.wait_for_function("document.getElementById('status').dataset.state !== 'running'", timeout=20000)
    assert page.locator("#status").get_attribute("data-state") == "passed", page.locator("#output").inner_text()
    records = demo_records(page.locator("#output").inner_text())
    assert records and all(record["message"] == "Edited café ☃" and
                           record["runtime"] == "playground" for record in records)
    assert page.locator("iframe").count() == 0
    assert page.locator("#stop-demo").is_disabled()
    page.locator("#demo-config").fill("pipeline: [\n")
    click_test(page, "#start-demo", "failed")
    page.locator("#demo-config").fill(example.replace("name: dummy", "name: unavailable_plugin"))
    click_test(page, "#start-demo", "failed")
    page.locator("#demo-seconds").fill("2")
    page.locator("#demo-config").fill(example.replace("'info'", "'warn'"))
    assert not demo_records(click_test(page, "#start-demo"))
    page.locator("#reset-demo").click()
    assert page.locator("#demo-config").input_value() == example
    assert demo_records(click_test(page, "#start-demo"))
    page.locator("#demo-config").fill("x" * 65537)
    click_test(page, "#start-demo", "failed")
    assert page.locator("iframe").count() == 0
    page.locator("#reset-demo").click()
    print("Editable demo passed: stdout, UTF-8 edits, manual/automatic stop, SQL drop, invalid config, restart")


def check_lua(page):
    page.wait_for_function("!document.getElementById('load-lua-demo').disabled")
    page.locator('#load-lua-demo').click()
    example = page.locator('#demo-config').input_value()
    page.locator('#demo-seconds').fill('2')
    records = demo_records(click_test(page, '#start-demo'))
    assert records and all(record['runtime'] == 'Lua 5.4' and record['total'] == 6 and
                           record['values'] == [1, 2, 3] and record['optional'] is None for record in records)
    edited = example.replace('in the browser', 'café ☃').replace('record.total + value', 'record.total + value * 2')
    page.locator('#demo-config').fill(edited)
    records = demo_records(click_test(page, '#start-demo'))
    assert records and all(record['message'] == 'Hello from Lua café ☃' and record['total'] == 12 for record in records)
    # The same Lua filter can execute as a five-argument processor callback.
    extended = example.replace('enrich(tag, timestamp, record)', 'enrich(tag, timestamp, group, metadata, record)')
    extended = extended.replace('return 2, timestamp, record', 'return 2, timestamp, metadata, record')
    page.locator('#demo-config').fill(extended)
    assert demo_records(click_test(page, '#start-demo'))
    # And as a traditional matching filter, rather than an input processor.
    code = '\n'.join(line[14:] for line in example.splitlines() if line.startswith('              '))
    ordinary = ('service:\n  flush: 0.5\npipeline:\n  inputs:\n    - name: dummy\n'
                '      tag: lua.test\n      dummy: \'{"message":"filter","values":[1,2,3]}\'\n'
                '  filters:\n    - name: lua\n      match: "*"\n      call: enrich\n      code: |\n' +
                '\n'.join('        ' + line for line in code.splitlines()) +
                '\n  outputs:\n    - name: stdout\n      match: "*"\n      format: json_lines\n')
    page.locator('#demo-config').fill(ordinary)
    assert demo_records(click_test(page, '#start-demo'))
    page.locator('#demo-config').fill(example.replace('return 2, timestamp, record', 'return -1, timestamp, record'))
    assert not demo_records(click_test(page, '#start-demo'))
    # Protected Lua errors must not terminate the engine or corrupt the input.
    page.locator('#demo-config').fill(example.replace('record.total = 0', 'error("lua-protected-test")'))
    output = click_test(page, '#start-demo')
    assert 'lua-protected-test' in output and demo_records(output), output
    page.locator('#demo-config').fill(example.replace('function enrich(', 'function broken!('))
    click_test(page, '#start-demo', 'failed')
    page.locator('#demo-config').fill(example.replace('call: enrich', 'call: missing'))
    click_test(page, '#start-demo', 'failed')
    page.locator('#demo-config').fill(example.replace('function enrich(', 'error("lua-initializer-test")\n              function enrich('))
    click_test(page, '#start-demo', 'failed')
    page.locator('#load-lua-demo').click()
    assert demo_records(click_test(page, '#start-demo'))
    page.locator('#reset-demo').click()
    print('Lua browser passed: edits, arrays/nulls, 3/5 arguments, filter/processor, drop, errors, restart', flush=True)


def check_http(page, cross_url, cross_receiver):
    page.wait_for_function("!document.getElementById('load-http-demo').disabled")
    def fixture():
        page.locator('#load-http-demo').click()
        return page.locator('#demo-config').input_value()

    def received():
        return page.evaluate('fetch(`/received/${httpCapture}`).then(r => r.json())')

    example = fixture()
    page.locator('#demo-seconds').fill('3')
    output = click_test(page, '#start-demo')
    requests = received()['requests']
    assert requests and all(r['status'] == 200 and r['method'] == 'POST' and r['tag'] == 'browser.http' for r in requests)
    records = [json.loads(line) for request in requests for line in request['body'].splitlines()]
    assert records and all(r['runtime'] == 'browser' for r in records)
    assert 'HTTP status=200' in output and demo_records(output)
    example = fixture().replace('format: json_lines', 'format: msgpack', 1)
    page.locator('#demo-config').fill(example)
    click_test(page, '#start-demo')
    requests = received()['requests']
    assert requests and all(r['content_type'] == 'application/msgpack' for r in requests)
    binary = base64.b64decode(requests[0]['base64'])
    assert binary[0] == 0x92 and b'Hello over HTTPS' in binary and b'runtime' in binary
    example = fixture().replace('{"message":"Hello over HTTPS"}',
                                '{"payload":"raw browser payload","headers":{"Content-Type":"text/plain","X-Demo":"per-record"}}')
    example = example.replace('      header_tag:', '      body_key: $payload\n      headers_key: $headers\n      header_tag:')
    page.locator('#demo-config').fill(example)
    click_test(page, '#start-demo')
    requests = received()['requests']
    assert requests and all(r['body'] == 'raw browser payload' and r['demo_header'] == 'per-record' for r in requests)
    # A finite input makes the second request unambiguously an engine retry.
    example = fixture().replace('      rate: 1', '      rate: 1\n      samples: 1')
    example = example.replace('"\n      format:', '?fail=1"\n      format:')
    page.locator('#demo-config').fill(example)
    page.locator('#demo-seconds').fill('6')
    click_test(page, '#start-demo')
    requests = received()['requests']
    assert len(requests) == 2 and [r['status'] for r in requests] == [503, 200], requests
    assert requests[0]['body'] == requests[1]['body']
    example = fixture().replace('"\n      format:', '?status=400"\n      format:')
    example = example.replace('      rate: 1', '      rate: 1\n      samples: 1')
    page.locator('#demo-config').fill(example)
    page.locator('#demo-seconds').fill('4')
    click_test(page, '#start-demo')
    assert received()['attempts'] == 1
    example = fixture().replace('"\n      format:', '?auth=1"\n      format:')
    example = example.replace('      header_tag:', '      compress: gzip\n      http_method: PUT\n      http_user: demo\n      http_passwd: demo\n      header_tag:')
    page.locator('#demo-config').fill(example)
    page.locator('#demo-seconds').fill('3')
    click_test(page, '#start-demo')
    requests = received()['requests']
    assert requests and all(r['method'] == 'PUT' and r['encoding'] == 'gzip' and r['authorization_present'] for r in requests)
    assert json.loads(gzip.decompress(base64.b64decode(requests[0]['base64'])).splitlines()[0])['runtime'] == 'browser'
    # A different HTTPS port is a different origin, requiring a real preflight.
    example = fixture().replace(page.url.rstrip('/'), cross_url)
    token = page.evaluate('httpCapture')
    page.locator('#demo-config').fill(example)
    click_test(page, '#start-demo')
    assert cross_receiver.read(token)['attempts'] > 0
    allowed = cross_receiver.cors_origins
    cross_receiver.cors_origins = frozenset()
    try:
        example = fixture().replace(page.url.rstrip('/'), cross_url)
        token = page.evaluate('httpCapture')
        page.locator('#demo-config').fill(example)
        output = click_test(page, '#start-demo')
        assert 'Request failed' in output and cross_receiver.read(token)['attempts'] == 0
    finally:
        cross_receiver.cors_origins = allowed
    example = fixture().replace('"\n      format:', '?delay=2"\n      format:')
    example = example.replace('http.response_timeout: 5s', 'http.response_timeout: 1s')
    page.locator('#demo-config').fill(example)
    output = click_test(page, '#start-demo')
    assert 'Request failed' in output and received()['attempts'] > 0
    # Unsupported URL/options must fail before any request is sent.
    for setting in ('      proxy: http://localhost:8080\n', '      workers: 1\n', '      oauth2.enable: true\n'):
        example = fixture().replace('      header_tag:', setting + '      header_tag:')
        page.locator('#demo-config').fill(example)
        click_test(page, '#start-demo', 'failed')
        assert received()['attempts'] == 0
    example = fixture().replace('https://', 'http://')
    page.locator('#demo-config').fill(example)
    click_test(page, '#start-demo', 'failed')
    # Abort while Fetch is outstanding; runner checks that all requests were cancelled.
    example = fixture().replace('"\n      format:', '?delay=2"\n      format:')
    page.locator('#demo-config').fill(example)
    page.locator('#demo-seconds').fill('30')
    page.locator('#start-demo').click()
    page.wait_for_function('document.getElementById("received-output").textContent.includes("Hello over HTTPS")', timeout=45000)
    page.locator('#stop-demo').click()
    page.wait_for_function('document.getElementById("status").dataset.state !== "running"', timeout=20000)
    assert page.locator('#status').get_attribute('data-state') == 'passed', page.locator('#output').inner_text()
    page.locator('#reset-demo').click()
    print('HTTP output passed: JSON/MessagePack, retry, permanent error, gzip/PUT/auth, CORS, timeout, invalid options, pending Stop', flush=True)


def check_shared_http(page):
    origin = urlsplit(page.url)
    def fixture(query='', standard=False):
        page.locator('#load-http-demo').click()
        token = page.evaluate('httpCapture')
        destination = f'https://{origin.netloc}/collect/{token}{query}'
        config = ('service:\n  flush: 0.5\n  scheduler.base: 1\n  scheduler.cap: 2\n'
                  'pipeline:\n  inputs:\n    - name: dummy\n      tag: shared.http\n'
                  '      samples: 1\n      dummy: \'{"message":"Unchanged Loki"}\'\n'
                  '  outputs:\n    - name: loki\n      match: "*"\n'
                  '      labels: job=wasm\n      line_format: json\n')
        if standard:
            config += (f'      host: {origin.hostname}\n      port: {origin.port}\n'
                       f'      uri: /collect/{token}{query}\n      tls: on\n')
        else:
            config += f'      browser.url: {json.dumps(destination)}\n'
        config += ('      processors:\n        logs:\n          - name: content_modifier\n'
                   '            action: insert\n            key: runtime\n            value: browser\n'
                   '    - name: stdout\n      match: "*"\n      format: json_lines\n')
        return config, token

    for query, standard, expected in (('', False, [200]), ('?status=204', True, [204]),
                                      ('?fail=1', False, [503, 200])):
        config, token = fixture(query, standard)
        page.locator('#demo-config').fill(config)
        page.locator('#demo-seconds').fill('6' if query == '?fail=1' else '3')
        output = click_test(page, '#start-demo')
        capture = page.evaluate('fetch(`/received/${httpCapture}`).then(r => r.json())')
        assert [r['status'] for r in capture['requests']] == expected, capture
        for request in capture['requests']:
            stream = json.loads(request['body'])['streams'][0]
            assert stream['stream']['job'] == 'wasm'
            assert json.loads(stream['values'][0][1])['runtime'] == 'browser'
        assert demo_records(output)
    # Two plugins suspended in different HTTP requests must both unwind on Stop.
    config, token = fixture('?delay=2')
    config += ('    - name: http\n      match: "*"\n      format: json_lines\n'
               f'      browser.url: "https://{origin.netloc}/collect/{token}?delay=2"\n')
    page.locator('#demo-config').fill(config)
    page.locator('#demo-seconds').fill('30')
    page.locator('#start-demo').click()
    page.wait_for_function('document.getElementById("received-output").textContent.includes("Unchanged Loki")', timeout=45000)
    page.locator('#stop-demo').click()
    page.wait_for_function('document.getElementById("status").dataset.state !== "running"', timeout=20000)
    assert page.locator('#status').get_attribute('data-state') == 'passed', page.locator('#output').inner_text()
    page.locator('#reset-demo').click()
    print('Shared HTTP passed: unchanged Loki, host/port/uri/TLS, output processor, 204, retry, HTTP/Loki Stop', flush=True)


def check_otel_http(page):
    origin = urlsplit(page.url)

    def fixture(http2='on', query='', extra=''):
        page.locator('#load-http-demo').click()
        token = page.evaluate('httpCapture')
        query = '?auth=1' + ('&' + query[1:] if query else '')
        config = ('service:\n  flush: 0.5\n  scheduler.base: 1\n  scheduler.cap: 2\n'
                  'pipeline:\n  inputs:\n    - name: dummy\n      tag: browser.otel\n'
                  '      samples: 1\n      dummy: \'{"message":"Browser OTLP"}\'\n'
                  '  outputs:\n    - name: opentelemetry\n      match: "*"\n'
                  f'      http2: {http2}\n      host: {origin.hostname}\n      port: {origin.port}\n'
                  f'      logs_uri: /collect/{token}{query}\n      tls: on\n'
                  '      logs_body_key_attributes: true\n'
                  '      http_user: demo\n      http_passwd: demo\n' + extra +
                  '      processors:\n        logs:\n          - name: content_modifier\n'
                  '            action: insert\n            key: runtime\n            value: browser\n')
        return config, token

    for http2, query, extra, expected in (
            ('off', '', '', [200]), ('on', '', '', [200]),
            ('on', '', '      header: content-type application/x-protobuf\n', [200]),
            ('on', '?status=204', '', [204]),
            ('on', '?fail=1', '      compress: gzip\n', [503, 200])):
        config, token = fixture(http2, query, extra)
        page.locator('#demo-config').fill(config)
        page.locator('#demo-seconds').fill('6' if query == '?fail=1' else '3')
        click_test(page, '#start-demo')
        capture = page.evaluate('fetch(`/received/${httpCapture}`).then(r => r.json())')
        assert [r['status'] for r in capture['requests']] == expected, capture
        bodies = []
        for request in capture['requests']:
            assert request['method'] == 'POST' and request['content_type'] == 'application/x-protobuf', request
            assert request['authorization_present'], request
            body = base64.b64decode(request['base64'])
            if 'compress: gzip' in extra:
                assert request['encoding'] == 'gzip', request
                body = gzip.decompress(body)
            assert b'Browser OTLP' in body and b'runtime' in body and b'browser' in body, body
            bodies.append(body)
        assert all(body == bodies[0] for body in bodies)
    for signal, marker in (('metrics', b'kubernetes_network'), ('traces', b'do-work')):
        config, token = fixture()
        config = config.replace(
            '    - name: dummy\n      tag: browser.otel\n'
            '      samples: 1\n      dummy: \'{"message":"Browser OTLP"}\'\n',
            f'    - name: event_type\n      type: {signal}\n      threaded: false\n'
            '      interval_sec: 1\n      tag: browser.otel\n')
        config = config.replace('      logs_uri:', f'      {signal}_uri:')
        page.locator('#demo-config').fill(config)
        page.locator('#demo-seconds').fill('3')
        click_test(page, '#start-demo')
        capture = page.evaluate('fetch(`/received/${httpCapture}`).then(r => r.json())')
        assert capture['requests'], capture
        for request in capture['requests']:
            assert request['status'] == 200 and request['content_type'] == 'application/x-protobuf', request
            assert marker in base64.b64decode(request['base64']), request
    config, token = fixture(query='?delay=2')
    page.locator('#demo-config').fill(config)
    page.locator('#demo-seconds').fill('30')
    page.locator('#start-demo').click()
    page.wait_for_function(
        'document.getElementById("received-output").textContent.includes("Browser OTLP")', timeout=45000)
    page.locator('#stop-demo').click()
    page.wait_for_function('document.getElementById("status").dataset.state !== "running"', timeout=20000)
    assert page.locator('#status').get_attribute('data-state') == 'passed', page.locator('#output').inner_text()
    for http2, extra, message in (
            ('force', '', 'cannot force'),
            ('on', '      grpc: on\n', 'does not support native gRPC')):
        config, token = fixture(http2, extra=extra)
        page.locator('#demo-config').fill(config)
        assert message in click_test(page, '#start-demo', 'failed')
        assert page.evaluate('fetch(`/received/${httpCapture}`).then(r => r.json())')['attempts'] == 0
    page.locator('#reset-demo').click()
    print('OTLP browser passed: unchanged plugin, legacy and NG, logs/metrics/traces, processor, auth, gzip, retry, 204, pending Stop, unsupported modes', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=DEFAULT_BUILD_DIR)
    parser.add_argument("--browser", required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--storage-only", action="store_true")
    mode.add_argument("--demo-only", action="store_true")
    mode.add_argument("--startup-only", action="store_true")
    mode.add_argument("--certificate-only", action="store_true")
    mode.add_argument("--lua-only", action="store_true")
    mode.add_argument("--http-only", action="store_true")
    mode.add_argument("--otel-only", action="store_true")
    parser.add_argument("--screenshot", type=Path)
    parser.add_argument("--test-host", default="127.0.0.1",
                        help="Local machine IP to exercise HTTPS (including a non-loopback address)")
    args = parser.parse_args()
    with ExitStack() as resources:
        directory = resources.enter_context(tempfile.TemporaryDirectory(prefix="flb-page-tls-"))
        cert, key = development_certificate(directory, [args.test_host, "localhost", "127.0.0.1"])
        server = resources.enter_context(create_server(
            args.build_dir, 0, host="0.0.0.0", tls_context=server_tls_context(cert, key)))
        client_context = ssl.create_default_context(cafile=str(cert))
        # Trust only this test certificate's public key in the ephemeral browser;
        # do not disable certificate verification globally or change a trust store.
        public_key = subprocess.run(["openssl", "x509", "-in", str(cert), "-pubkey", "-noout"],
                                    check=True, capture_output=True).stdout
        public_der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"],
                                    input=public_key, check=True, capture_output=True).stdout
        pin = base64.b64encode(hashlib.sha256(public_der).digest()).decode()
        assert server.server_address[0] == "0.0.0.0"
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"https://{args.test_host}:{server.server_port}"
        cross_server = resources.enter_context(create_server(
            args.build_dir, 0, host="0.0.0.0", tls_context=server_tls_context(cert, key), cors_origins=[url]))
        cross_thread = threading.Thread(target=cross_server.serve_forever, daemon=True)
        cross_thread.start()
        resources.callback(cross_thread.join)
        resources.callback(cross_server.shutdown)
        try:
            with urlopen(url, context=client_context) as response:
                assert response.headers["Cross-Origin-Opener-Policy"] == "same-origin"
                assert response.headers["Cross-Origin-Embedder-Policy"] == "require-corp"
            for path in ("/CMakeCache.txt", "/bin/", "/../CMakeLists.txt", "/%2e%2e/CMakeLists.txt"):
                try:
                    urlopen(url + path, context=client_context)
                except HTTPError as error:
                    assert error.code == 404
                else:
                    raise AssertionError(f"Unexpectedly served {path}")
            with sync_playwright() as playwright:
                if args.certificate_only:
                    check_certificate_warning(playwright, args.browser, url)
                browser = playwright.chromium.launch(executable_path=args.browser, headless=True,
                    args=[f"--ignore-certificate-errors-spki-list={pin}"])
                try:
                    page = browser.new_page(viewport={"width": 1280, "height": 1050})
                    errors = []
                    page.on("pageerror", lambda error: errors.append(str(error)))
                    page.on("requestfailed", lambda request: print(
                        f"Browser request failed: {request.url}: {request.failure}", flush=True))
                    page.goto(url)
                    assert page.locator('#checks li[data-ok="false"]').count() == 0
                    page.wait_for_function("document.getElementById('yaml-source').textContent.includes('service:')")
                    if args.certificate_only:
                        page.locator('#demo-seconds').fill('2')
                        assert demo_records(click_test(page, '#start-demo'))
                        assert not errors, errors
                        print('Trusted certificate: engine starts and emits records', flush=True)
                        return
                    if args.startup_only:
                        check_startup_failures(browser, url)
                        check_demo(page)
                        assert not errors, errors
                        print('Startup and editable demo checks passed', flush=True)
                        return
                    if args.otel_only:
                        check_otel_http(page)
                        assert not errors, errors
                        return
                    if not args.storage_only:
                        check_http(page, f"https://{args.test_host}:{cross_server.server_port}", cross_server.receiver)
                        check_shared_http(page)
                        check_otel_http(page)
                        if args.http_only:
                            assert not errors, errors
                            print('HTTPS output browser checks passed', flush=True)
                            return
                        check_lua(page)
                        if not args.lua_only:
                            check_startup_failures(browser, url)
                            check_demo(page)
                        if args.demo_only or args.lua_only:
                            assert not errors, errors
                            if args.screenshot:
                                click_test(page, "#start-demo")
                                page.screenshot(path=str(args.screenshot), full_page=True)
                            print("HTTPS editable browser demo passed", flush=True)
                            return
                        click_test(page, "#run-yaml")
                        click_test(page, "#run-pipeline")
                    for _ in range(2):
                        output = click_test(page, "#run-storage")
                        assert "Storage: write" in output and "Storage: restore" in output
                        assert "Storage: empty" in output and "explicit retry succeeded" in output
                        page.reload()
                    assert page.locator("iframe").count() == 0
                    # Leave a committed chunk behind, as if the page closed
                    # between write and restore, then use the recovery button.
                    page.evaluate("runFrame('flb-wasm-storage', 'write')")
                    page.reload()
                    click_test(page, "#recover-storage")
                    if args.screenshot:
                        click_test(page, "#run-storage")
                        page.screenshot(path=str(args.screenshot), full_page=True)
                    assert not errors, errors

                    # A nonexistent WASM binary must report failure, never pass.
                    page.route("**/bin/flb-wasm-storage.wasm",
                               lambda route: route.fulfill(status=404, body="missing"))
                    output = click_test(page, "#run-storage", "failed")
                    assert "Missing flb-wasm-storage.wasm" in output
                    page.unroute("**/bin/flb-wasm-storage.wasm")
                    click_test(page, "#run-storage")

                    # Test failure without aborting a WASM runtime: invalid runner input.
                    result = page.evaluate("""() => new Promise(resolve => {
                        const frame = document.createElement('iframe');
                        const receive = event => {
                            if (event.source === frame.contentWindow && event.data.type === 'done') {
                                window.removeEventListener('message', receive);
                                frame.remove();
                                resolve(event.data);
                            }
                        };
                        window.addEventListener('message', receive);
                        frame.src = '/runner.html?target=invalid&token=negative';
                        document.body.append(frame);
                    })""")
                    assert not result["ok"] and "Invalid test" in result["error"]

                    unavailable = browser.new_page()
                    unavailable.add_init_script("Object.defineProperty(window, 'SharedArrayBuffer', {value: undefined});")
                    unavailable.goto(url)
                    assert unavailable.locator("#run-yaml").is_disabled()
                    assert unavailable.locator("#run-storage").is_disabled()
                    assert "requirements missing" in unavailable.locator("#requirements-note").inner_text()
                    page.set_viewport_size({"width": 390, "height": 844})
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                finally:
                    try:
                        # Stop alone retains the SDK module for reuse. Destroy it
                        # explicitly so ASan/LSan exit checks actually execute.
                        if not page.is_closed():
                            page.evaluate("""async () => {
                                if (typeof demoClient !== 'undefined' && demoClient) {
                                    await demoClient.destroy();
                                    demoClient = null;
                                }
                            }""")
                            assert_no_sanitizer_errors(page.locator('#output').inner_text())
                    finally:
                        browser.close()
        finally:
            server.shutdown()
            thread.join()
    # Starting the server without a build still serves a useful page, with 404 assets.
    with tempfile.TemporaryDirectory(prefix="flb-page-missing-") as directory:
        with create_server(directory, 0) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                try:
                    urlopen(f"http://127.0.0.1:{server.server_port}/bin/flb-wasm-yaml.js")
                except HTTPError as error:
                    assert error.code == 404
                else:
                    raise AssertionError("Missing build asset was served")
            finally:
                server.shutdown()
                thread.join()
    print("HTTPS browser test page passed: UI, reload persistence, failures, readiness, and server isolation")


if __name__ == "__main__":
    main()
