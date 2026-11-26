#!/usr/bin/env python3
"""Bounded Linux OTLP/HTTP benchmarks with retained evidence. See README.md."""

import argparse
import concurrent.futures
import csv
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import threading
import time

import compare_fluent_bit_otelcol as otlp


SCHEMA_VERSION = 1


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")
    temporary.replace(path)


def fingerprint(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def required_counter(mapping, key):
    value = mapping.get(key)
    if (not isinstance(value, (int, float)) or isinstance(value, bool) or
            not math.isfinite(value) or value < 0):
        raise ValueError(f"missing or invalid counter: {key}")
    return value


def metrics(port, input_instance, output_instance):
    data = json.loads(otlp.scrape(f"http://127.0.0.1:{port}/api/v1/metrics"))
    incoming = data.get("input", {}).get(input_instance, {})
    outgoing = data.get("output", {}).get(output_instance, {})
    return {
        "accepted": required_counter(incoming, "records"),
        "completed": required_counter(outgoing, "proc_records"),
        "dropped": required_counter(outgoing, "dropped_records"),
        "errors": required_counter(outgoing, "errors"),
        "retries": required_counter(outgoing, "retries"),
    }


def reconcile(counters, expected):
    if counters["accepted"] != expected or counters["completed"] != expected:
        raise ValueError(f"record accounting mismatch: expected {expected}, got {counters}")
    if counters["dropped"] or counters["errors"]:
        raise ValueError(f"output reported drops or errors: {counters}")


def wait_count(process, port, args, expected, deadline):
    last_error = "metrics not yet available"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Fluent Bit exited with {process.returncode}")
        try:
            counters = metrics(port, args.input_instance, args.output_instance)
            last_error = str(counters)
        except (OSError, ValueError) as exc:
            last_error = str(exc)
            time.sleep(0.1)
            continue
        if counters["completed"] >= expected:
            reconcile(counters, expected)
            return counters
        time.sleep(0.1)
    raise TimeoutError(f"completion deadline: {last_error}")


def send(port, payload, batch_records, records, clients, rate, deadline):
    """Interleave clients on an absolute schedule; never retry ambiguous requests."""
    start = time.monotonic() + 0.05
    stop = threading.Event()
    requests = records // batch_records

    def client(index):
        latencies = []
        lags = []
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        try:
            for request in range(index, requests, clients):
                scheduled = start + request * batch_records / rate if rate else start
                delay = scheduled - time.monotonic()
                if delay > 0 and stop.wait(delay):
                    break
                if stop.is_set():
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError("load generation deadline")
                lags.append(max(0, time.monotonic() - scheduled))
                started = time.monotonic()
                connection.request("POST", "/v1/logs", payload,
                                   {"Content-Type": send.content_type})
                response = connection.getresponse()
                body = response.read(65537)
                if response.status not in (200, 201) or len(body) > 65536:
                    raise RuntimeError(f"HTTP {response.status}; request not retried")
                if body:
                    if send.content_type == "application/json":
                        partial = json.loads(body).get("partialSuccess", {})
                        if partial:
                            raise RuntimeError(f"OTLP partial success: {partial}")
                    else:
                        from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import (
                            ExportLogsServiceResponse,
                        )
                        reply = ExportLogsServiceResponse.FromString(body)
                        if reply.HasField("partial_success"):
                            raise RuntimeError("OTLP partial success")
                latencies.append((time.monotonic() - started) * 1e6)
            return latencies, lags
        except BaseException:
            stop.set()
            raise
        finally:
            connection.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=clients) as pool:
        results = list(pool.map(client, range(clients)))
    return ([value for latencies, _ in results for value in latencies],
            [value for _, lags in results for value in lags],
            max(time.monotonic() - start, 0.000001))


def run_trial(binary, directory, args, payload, batch_records):
    directory.mkdir()
    input_port, metrics_port = otlp.free_port(), otlp.free_port()
    while input_port == metrics_port:
        metrics_port = otlp.free_port()
    storage = directory / "storage"
    storage.mkdir()
    environment = dict(os.environ, BENCH_INPUT_PORT=str(input_port),
                       BENCH_HTTP_PORT=str(metrics_port), BENCH_STORAGE_PATH=str(storage))
    if args.config:
        configuration = args.config.read_text()
    else:
        configuration = otlp.fluent_config(
            input_port, metrics_port, args.pipeline == "modified", args.flush,
            str(storage) if args.storage == "filesystem" else "", args.workers)
        configuration = configuration.replace("      match: '*'\n",
                                              "      match: '*'\n      storage.total_limit_size: 128M\n")
    config = directory / "config.yaml"
    config.write_text(configuration)
    command = [str(binary), "-c", str(config)]
    if args.cpu_set:
        command = ["taskset", "-c", args.cpus, *command]
    write_json(directory / "invocation.json", {
        "command": command,
        "config_sha256": fingerprint(config),
        "benchmark_environment": {key: value for key, value in environment.items()
                                  if key.startswith("BENCH_")},
    })
    deadline = time.monotonic() + args.max_seconds
    process = None
    stop = threading.Event()
    monitor = None
    samples = []
    status = "invalid"
    row = {"status": status}
    with (directory / "server.log").open("w") as log:
        try:
            process = subprocess.Popen(command, stdout=log, stderr=log, env=environment)
            wait_count(process, metrics_port, args, 0, min(deadline, time.monotonic() + 20))
            if args.warmup_records:
                send(input_port, payload, batch_records, args.warmup_records, args.clients, 0, deadline)
                wait_count(process, metrics_port, args, args.warmup_records, deadline)
            initial = metrics(metrics_port, args.input_instance, args.output_instance)
            cpu_start = otlp.process_cpu_seconds(process.pid)
            start = time.monotonic()

            def sample():
                with (directory / "samples.jsonl").open("w") as stream:
                    while not stop.is_set():
                        item = {"seconds": time.monotonic() - start}
                        try:
                            item.update(cpu_seconds=otlp.process_cpu_seconds(process.pid),
                                        rss_bytes=otlp.process_rss_bytes(process.pid))
                            item.update(metrics(metrics_port, args.input_instance, args.output_instance))
                        except (OSError, ValueError) as exc:
                            item["sampling_error"] = str(exc)
                        samples.append(item)
                        stream.write(json.dumps(item) + "\n")
                        stream.flush()
                        stop.wait(0.25)

            monitor = threading.Thread(target=sample, daemon=True)
            monitor.start()
            generator_start = time.process_time()
            latencies, lags, send_seconds = send(input_port, payload, batch_records,
                                                args.records, args.clients, args.rate, deadline)
            generator_cpu = time.process_time() - generator_start
            final = wait_count(process, metrics_port, args,
                               args.warmup_records + args.records, deadline)
            elapsed = time.monotonic() - start
            cpu = otlp.process_cpu_seconds(process.pid) - cpu_start
            rss = otlp.process_rss_bytes(process.pid)
            stop.set()
            monitor.join()
            for key in final:
                if final[key] < initial[key]:
                    raise ValueError(f"counter reset: {key}")
            counters = {key: final[key] - initial[key] for key in final}
            reconcile(counters, args.records)
            if time.monotonic() + args.cooldown > deadline:
                raise TimeoutError("insufficient remaining time for cooldown")
            time.sleep(args.cooldown)
            cooldown_rss = otlp.process_rss_bytes(process.pid)
            rss_values = [item["rss_bytes"] for item in samples if "rss_bytes" in item]
            achieved = args.records / max(send_seconds, args.records / args.rate if args.rate else 0)
            status = "valid"
            if args.rate and achieved < args.rate * 0.95:
                status = "inconclusive"
            row = {
                "status": status, "records": args.records,
                "completed_records_per_second": args.records / elapsed,
                "cpu_seconds_per_million_records": cpu / args.records * 1e6,
                "completion_seconds": elapsed, "send_seconds": send_seconds,
                "achieved_offered_records_per_second": achieved,
                "generator_and_monitor_cpu_seconds": generator_cpu,
                "sampled_peak_rss_mib": max([rss, *rss_values]) / 1048576,
                "post_drain_rss_mib": rss / 1048576,
                "cooldown_rss_mib": cooldown_rss / 1048576,
                "request_ack_p99_us": otlp.percentile(latencies, 0.99),
                "schedule_lag_p95_ms": otlp.percentile(lags, 0.95) * 1000 if args.rate else None,
                "peak_observed_backlog_records": max(
                    [0, *[item["accepted"] - item["completed"] for item in samples
                           if "completed" in item]]),
                "sampling_errors": sum("sampling_error" in item for item in samples),
                **counters,
            }
            if row["sampling_errors"]:
                row["status"] = "inconclusive"
        except Exception as exc:
            row = {"status": "invalid", "error": f"{type(exc).__name__}: {exc}"}
        finally:
            stop.set()
            if monitor:
                monitor.join(timeout=3)
            if process:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    row.update(status="invalid", error=row.get("error", "forced shutdown"),
                               forced_shutdown=True)
                if process.returncode:
                    row.update(status="invalid", error=row.get("error", "unexpected shutdown exit"),
                               shutdown_exit=process.returncode)
            write_json(directory / "result.json", row)
    return row


def summarize(rows):
    result = {}
    for label in dict.fromkeys(row["system"] for row in rows):
        selected = [row for row in rows if row["system"] == label]
        valid = [row for row in selected if row["status"] == "valid"]
        summary = {"runs": len(selected), "valid_runs": len(valid)}
        for key in ("cpu_seconds_per_million_records", "completed_records_per_second",
                    "sampled_peak_rss_mib", "cooldown_rss_mib", "request_ack_p99_us"):
            values = [row[key] for row in valid]
            if values:
                summary[key] = {"median": statistics.median(values),
                                "min": min(values), "max": max(values)}
        result[label] = summary
    return result


def report(root, rows):
    lines = ["# Fluent Bit benchmark", "",
             "Local workload measurements; no universal release performance claim.", "",
             "CPU and completion cover send plus drain, excluding startup, warmup and cooldown.",
             "RSS is a sampled peak. Latency is HTTP acknowledgement, not delivery latency.",
             "Count reconciliation does not verify payload identity or exactly-once delivery.", "",
             "Values are medians; summary.json retains min/max for every valid group.", "",
             "| System | Valid / attempted | CPU s / million | Completed records/s | Peak RSS MiB |",
             "| --- | ---: | ---: | ---: | ---: |"]
    for label, summary in summarize(rows).items():
        values = [summary.get(key, {}).get("median") for key in (
            "cpu_seconds_per_million_records", "completed_records_per_second", "sampled_peak_rss_mib")]
        cells = [f"{value:.3f}" if value is not None else "unavailable" for value in values]
        lines.append(f"| {label} | {summary['valid_runs']} / {summary['runs']} | " + " | ".join(cells) + " |")
    lines += ["", "Paired comparisons (candidate minus baseline):"]
    for label, comparison in compare(rows).items():
        changes = comparison["changes"]
        cpu = changes.get("cpu_seconds_per_million_records", {}).get("median_change_percent")
        change = f"{cpu:+.1f}% CPU cost" if cpu is not None else "CPU change unavailable"
        lines.append(f"- {label} versus {comparison['baseline']}: {change}, "
                     f"{comparison['valid_pairs']} valid pairs ({comparison['status']}).")
    lines += ["", "Inspect every trial's result.json and samples.jsonl, including failures.",
              "Inconclusive trials missed the offered-rate target or had sampling failures.",
              "A finite saturation run does not establish sustainable capacity or a memory leak.",
              "All medians exclude invalid/inconclusive trials; a comparison with exclusions needs review."]
    (root / "report.md").write_text("\n".join(lines) + "\n")


def compare(rows):
    labels = list(dict.fromkeys(row["system"] for row in rows))
    baseline = labels[0]
    comparisons = {}
    for candidate in labels[1:]:
        pairs = []
        for before in rows:
            if before["system"] != baseline or before["status"] != "valid":
                continue
            after = next((row for row in rows if row["system"] == candidate and
                          row["repetition"] == before["repetition"] and row["status"] == "valid"), None)
            if after:
                pairs.append((before, after))
        changes = {}
        for key in ("cpu_seconds_per_million_records", "completed_records_per_second",
                    "sampled_peak_rss_mib", "cooldown_rss_mib"):
            values = [(after[key] / before[key] - 1) * 100 for before, after in pairs if before[key] > 0]
            if values:
                changes[key] = {"median_change_percent": statistics.median(values),
                                "min_change_percent": min(values), "max_change_percent": max(values)}
        comparisons[candidate] = {"baseline": baseline, "valid_pairs": len(pairs),
                                  "status": "descriptive" if len(pairs) >= 3 else "insufficient_repetitions",
                                  "changes": changes}
    return comparisons


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--system", action="append", required=True, metavar="NAME=BINARY")
    parser.add_argument("--output", type=Path, required=True, help="new result directory")
    parser.add_argument("--records", type=int, default=100000)
    parser.add_argument("--batch-records", type=int, default=100)
    parser.add_argument("--warmup-records", type=int, default=1000)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--clients", type=int, default=4)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--rate", type=float, default=10000, help="aggregate records/s; 0 saturates")
    parser.add_argument("--max-seconds", type=float, default=180, help="per-trial work deadline")
    parser.add_argument("--cooldown", type=float, default=2)
    parser.add_argument("--flush", type=float, default=0.5)
    parser.add_argument("--cpus", help="optional Fluent Bit CPU affinity; generator remains unpinned")
    parser.add_argument("--encoding", choices=("json", "protobuf"), default="json")
    parser.add_argument("--pipeline", choices=("ingest", "modified"), default="ingest")
    parser.add_argument("--storage", choices=("memory", "filesystem"), default="memory")
    parser.add_argument("--payload", type=Path, help="sanitized OTLP JSON request; repeated unchanged")
    parser.add_argument("--config", type=Path, help="custom BENCH_* template; see README")
    parser.add_argument("--input-instance", default="opentelemetry.0")
    parser.add_argument("--output-instance", default="null.0")
    args = parser.parse_args(argv)
    if sys.platform != "linux":
        parser.error("this runner requires Linux /proc; Fluent Bit itself supports other platforms")
    if any(value < 1 for value in (args.records, args.batch_records, args.runs, args.clients, args.workers)):
        parser.error("record counts, runs, clients and workers must be positive")
    if args.batch_records > 4096 or args.clients > 64 or args.workers > 64 or args.runs > 100:
        parser.error("limits: 4096 synthetic records/batch, 64 clients/workers, 100 runs")
    if len(args.system) > 16:
        parser.error("at most 16 systems per campaign")
    if (args.warmup_records < 0 or not math.isfinite(args.rate) or args.rate < 0 or
            not 0 < args.flush <= 60 or not 0 <= args.cooldown <= 60 or
            not 1 <= args.max_seconds <= 3600):
        parser.error("invalid rate, flush, cooldown or deadline")
    args.cpu_set = otlp.parse_cpus(args.cpus) if args.cpus else set()
    if args.cpu_set and not args.cpu_set <= os.sched_getaffinity(0):
        parser.error("requested CPUs are outside this process's allowed affinity")
    if args.config and (args.pipeline != "ingest" or args.storage != "memory"):
        parser.error("--config owns processor and storage settings; omit --pipeline/--storage")
    if args.payload:
        if args.payload.stat().st_size > 16 * 1024 * 1024:
            parser.error("payload exceeds 16 MiB")
        document = json.loads(args.payload.read_bytes())
        batch_records = sum(len(scope.get("logRecords", []))
                            for resource in document.get("resourceLogs", [])
                            for scope in resource.get("scopeLogs", []))
        payload = json.dumps(document, separators=(",", ":")).encode()
        if args.encoding == "protobuf":
            from google.protobuf.json_format import ParseDict
            from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
            payload = ParseDict(document, ExportLogsServiceRequest()).SerializeToString()
    else:
        batch_records = args.batch_records
        payload = otlp.make_payloads(batch_records, (args.encoding,))[args.encoding]
    if not batch_records or args.records % batch_records or args.warmup_records % batch_records:
        parser.error("measured and warmup counts must be multiples of the payload's nonzero record count")
    if len(payload) > 16 * 1024 * 1024:
        parser.error("encoded request exceeds 16 MiB")
    if args.rate and args.records / args.rate + args.cooldown >= args.max_seconds:
        parser.error("offered-load duration plus cooldown exceeds trial deadline")
    binaries = {}
    for system in args.system:
        label, path = system.split("=", 1)
        if not label or not all(char.isalnum() or char in "-_" for char in label) or label in binaries:
            parser.error("system labels must be unique and contain only letters, numbers, - or _")
        binary = Path(path).resolve(strict=True)
        if not binary.is_file() or not os.access(binary, os.X_OK):
            parser.error(f"binary is not executable: {binary}")
        binaries[label] = binary
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    manifest = {
        "schema_version": SCHEMA_VERSION, "status": "running", "platform": platform.platform(),
        "started_unix": time.time(),
        "cpu_affinity": sorted(os.sched_getaffinity(0)), "page_size": os.sysconf("SC_PAGE_SIZE"),
        "arguments": {key: str(value) if isinstance(value, (Path, set)) else value
                      for key, value in vars(args).items()},
        "binaries": {label: {"path": str(binary), "sha256": fingerprint(binary)}
                     for label, binary in binaries.items()},
        "runner_sha256": fingerprint(Path(__file__)),
        "helper_sha256": fingerprint(Path(otlp.__file__)),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "batch_records": batch_records,
        "allocator_environment": {key: os.environ.get(key) for key in ("MALLOC_CONF", "LD_PRELOAD")},
        "limitations": ["Linux only", "count verification, not payload identity",
                        "local HTTP/1 without TLS", "sampled RSS, not allocated disk bytes",
                        "generator and monitor share host resources", "build optimization flags unverified"],
    }
    write_json(args.output / "manifest.json", manifest)
    (args.output / "payload.bin").write_bytes(payload)
    send.content_type = "application/json" if args.encoding == "json" else "application/x-protobuf"
    rows = []
    try:
        for repetition in range(args.runs):
            labels = list(binaries)
            offset = repetition % len(labels)
            for label in labels[offset:] + labels[:offset]:
                row = run_trial(binaries[label], args.output / f"{repetition + 1:02d}-{label}",
                                args, payload, batch_records)
                row.update(system=label, repetition=repetition + 1)
                rows.append(row)
                write_json(args.output / "results.json", rows)
                write_json(args.output / "summary.json", summarize(rows))
                write_json(args.output / "comparison.json", compare(rows))
                report(args.output, rows)
                print(json.dumps(row), flush=True)
        manifest["status"] = "complete" if all(row["status"] == "valid" for row in rows) else "needs_review"
    finally:
        if manifest["status"] == "running":
            manifest["status"] = "interrupted"
        manifest["finished_unix"] = time.time()
        write_json(args.output / "manifest.json", manifest)
        if rows:
            fields = sorted(set().union(*(row.keys() for row in rows)))
            with (args.output / "results.csv").open("w") as stream:
                writer = csv.DictWriter(stream, fieldnames=fields)
                writer.writeheader()
                writer.writerows(rows)
    return 0 if manifest["status"] == "complete" else 2


if __name__ == "__main__":
    raise SystemExit(main())
