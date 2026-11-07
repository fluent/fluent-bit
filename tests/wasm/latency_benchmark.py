#!/usr/bin/env python3
"""Compare browser SDK latency against a separately built previous implementation."""

import argparse
import base64
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import statistics
import subprocess
import tempfile
import threading

from playwright.sync_api import sync_playwright

from browser_page_test import assert_no_sanitizer_errors
from browser_server import create_server, development_certificate, server_tls_context


WORKLOAD = r"""async ({mode, rounds, records}) => {
    const {createFluentBit} = await import('/sdk/fluent-bit.js');
    const samples = [];
    const errors = [];
    let received = [];
    let outputDone;
    let outputAt;
    const begin = performance.now();
    const fluent = await createFluentBit({
        onError: error => errors.push(error.message),
        onStdout: line => {
            let record;
            try { record = JSON.parse(line); } catch (_) { return; }
            if (typeof record.benchmark_id !== 'string') { return; }
            received.push(record);
            if (received.length === records) {
                outputAt = performance.now();
                outputDone();
            }
        }
    });
    const createMs = performance.now() - begin;
    const yaml = `service:
  flush: 0.5
  log_level: error
pipeline:
  inputs:
    - name: lib
      alias: app
      tag: app
      processors:
        logs:
          - name: fts
            script: /config/benchmark.lua
  outputs:
    - name: stdout
      match: '*'
      format: json_lines
`;
    try {
        await fluent.writeFile('/config/benchmark.lua', `local fb = require('fluentbit')
            function process(record)
                record.body:set('benchmark_processed', true)
                return fb.KEEP
            end`);
        for (let round = 0; round < rounds; round++) {
            received = [];
            const complete = new Promise(resolve => { outputDone = resolve; });
            const batch = Array.from({length: records}, (_, index) => ({
                benchmark_id: `${round}:${index}`, message: 'x'.repeat(128)
            }));
            const start = performance.now();
            const startup = await fluent.start({yaml, graceSeconds: 0});
            const push = performance.now();
            const accepted = await fluent.push({input: 'app', records: batch});
            const pushed = performance.now();
            if (mode === 'drain') {
                await fluent.drain();
            }
            else if (mode === 'sleep600') {
                await new Promise(resolve => setTimeout(resolve, 600));
            }
            else {
                let timer;
                try {
                    await Promise.race([complete, new Promise((_, reject) => {
                        timer = setTimeout(() => reject(new Error('Output deadline exceeded')), 5000);
                    })]);
                }
                finally { clearTimeout(timer); }
            }
            const done = performance.now();
            if (accepted.acceptedRecords !== records || received.length !== records ||
                received.some((record, index) => record.benchmark_id !== batch[index].benchmark_id ||
                    record.message !== batch[index].message || record.benchmark_processed !== true)) {
                throw new Error(`Output mismatch: ${received.length}/${records}`);
            }
            await fluent.stop();
            const stopped = performance.now();
            samples.push({round, start_ms: push - start, engine_ms: startup.engineMs,
                push_accept_ms: pushed - push, push_to_output_ms: outputAt - push,
                push_to_completion_ms: done - push, stop_ms: stopped - done,
                total_ms: stopped - start, output_records: received.length});
        }
    }
    finally {
        await fluent.destroy();
    }
    if (errors.length) { throw new Error(errors.join('\n')); }
    return {create_ms: createMs, samples};
}"""


def summarize(values):
    ordered = sorted(values)
    return {"median": statistics.median(values), "min": min(values), "max": max(values),
            "p95": ordered[min(len(ordered) - 1, int((len(ordered) - 1) * 0.95 + 0.5))]}


def benchmark(before, after, browser_path, trials, rounds, records):
    cases = [("before_observed", before, "observe"), ("after_observed", after, "observe"),
             ("after_drain", after, "drain"), ("before_sleep600", before, "sleep600")]
    raw = {name: [] for name, _, _ in cases}
    with tempfile.TemporaryDirectory(prefix="flb-latency-tls-") as directory, ExitStack() as stack:
        cert, key = development_certificate(directory, ["localhost", "127.0.0.1"])
        public = subprocess.run(["openssl", "x509", "-in", str(cert), "-pubkey", "-noout"],
                                check=True, capture_output=True).stdout
        der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"], input=public,
                             check=True, capture_output=True).stdout
        pin = base64.b64encode(hashlib.sha256(der).digest()).decode()
        servers = {}
        for build in (before, after):
            server = stack.enter_context(create_server(build, 0,
                tls_context=server_tls_context(cert, key)))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            stack.callback(thread.join)
            stack.callback(server.shutdown)
            servers[build] = server
        with sync_playwright() as playwright:
            for trial in range(trials):
                # Reverse order every other trial to reduce systematic order bias.
                for name, build, mode in cases[::1 if trial % 2 == 0 else -1]:
                    with playwright.chromium.launch(executable_path=browser_path,
                            args=[f"--ignore-certificate-errors-spki-list={pin}"]) as browser:
                        page = browser.new_page()
                        page.set_default_timeout(120000)
                        diagnostics = []
                        page.on("console", lambda event: diagnostics.append(event.text))
                        page.goto(f"https://127.0.0.1:{servers[build].server_port}/")
                        result = page.evaluate(WORKLOAD, {"mode": mode,
                            "rounds": rounds if mode != "sleep600" else 3, "records": records})
                        assert_no_sanitizer_errors("\n".join(diagnostics))
                        result["trial"] = trial + 1
                        result["browser_version"] = browser.version
                        raw[name].append(result)
                        print(f"{name} trial {trial + 1}/{trials} passed", flush=True)
    summary = {}
    for name, _, _ in cases:
        # Separate the first engine cycle from subsequent warm engine cycles.
        warm = [sample for run in raw[name] for sample in run["samples"][1:]]
        summary[name] = {
            "cold_create_ms": summarize([run["create_ms"] for run in raw[name]]),
            "first_engine_cycle_ms": summarize([run["samples"][0]["total_ms"] for run in raw[name]]),
            "warm_sample_count": len(warm),
            "warm_ms": {field: summarize([sample[field] for sample in warm]) for field in (
                "start_ms", "push_accept_ms", "push_to_output_ms", "push_to_completion_ms",
                "stop_ms", "total_ms")}}
    return {"conditions": {"browser": browser_path, "trials": trials, "rounds": rounds,
        "records_per_batch": records, "message_bytes": 128, "flush_seconds": 0.5,
        "grace_seconds": 0, "pipeline": "lib -> FTS (add boolean) -> stdout",
        "network": "unthrottled local HTTPS, no-store; fresh Chromium process per case/trial",
        "before_build": str(before), "after_build": str(after),
        "before_wasm_bytes": (before / "sdk/browser/fluent-bit-runtime.wasm").stat().st_size,
        "after_wasm_bytes": (after / "sdk/browser/fluent-bit-runtime.wasm").stat().st_size},
        "summary": summary, "raw": raw}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before-build-dir", required=True, type=Path)
    parser.add_argument("--after-build-dir", required=True, type=Path)
    parser.add_argument("--browser", required=True)
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument("--rounds", type=int, default=6)
    parser.add_argument("--records", type=int, default=20)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.trials < 1 or args.rounds < 2 or not 1 <= args.records <= 100:
        parser.error("trials >= 1, rounds >= 2, and 1 <= records <= 100 are required")
    result = benchmark(args.before_build_dir.resolve(), args.after_build_dir.resolve(),
                       args.browser, args.trials, args.rounds, args.records)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["summary"], indent=2))


if __name__ == "__main__":
    main()
