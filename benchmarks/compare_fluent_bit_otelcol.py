#!/usr/bin/env python3
"""Compare Fluent Bit and Collector OTLP/HTTP log ingestion to null sinks.

Measurement model:

- The load generator runs as one process per client so it is not limited by
  the Python GIL. Its own CPU use is reported so a generator ceiling is
  visible in the results.
- Server and generator CPU sets must not share a physical core; the harness
  checks the SMT sibling map and refuses to run otherwise. It also refuses to
  start while other processes keep those CPUs busy.
- Fluent Bit refreshes its metrics endpoints once per second, the Collector
  serves live counters. To measure both the same way, throughput is the
  slope of the completed-records counter over a steady-state window
  (by default 10% to 90% of the measured records), using the time at which
  each new counter value was first observed. End-to-end completion time is
  still reported, but it is quantized to one second for Fluent Bit.
"""

import argparse
import csv
import hashlib
import http.client
import json
import math
import multiprocessing
import os
from pathlib import Path
import re
import socket
import statistics
import subprocess
import tempfile
import threading
import time
import urllib.request


ENCODINGS = ("json", "protobuf")
PIPELINES = ("ingest", "modified")
SAMPLE_INTERVAL = 0.05
CLIENT_DEADLINE = 900
CLIENT_MAX_CONSECUTIVE_FAILURES = 200


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def parse_cpus(text):
    cpus = set()
    for item in text.split(","):
        if "-" in item:
            low, high = item.split("-")
            cpus.update(range(int(low), int(high) + 1))
        else:
            cpus.add(int(item))
    return cpus


def physical_core(cpu):
    path = Path(f"/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list")
    return min(parse_cpus(path.read_text().strip()))


def check_topology(server_cpus, generator_cpus):
    server_cores = {physical_core(cpu) for cpu in server_cpus}
    generator_cores = {physical_core(cpu) for cpu in generator_cpus}
    shared = server_cores & generator_cores
    if shared:
        raise SystemExit(f"server and generator CPUs share physical cores {sorted(shared)}")


def cpu_busy_fraction(cpus, interval=1.0):
    def read():
        values = {}
        for line in Path("/proc/stat").read_text().splitlines():
            if line.startswith("cpu") and line[3:4].isdigit():
                fields = line.split()
                numbers = [int(value) for value in fields[1:]]
                values[int(fields[0][3:])] = (numbers[3] + numbers[4], sum(numbers))
        return values

    before = read()
    time.sleep(interval)
    after = read()
    idle = sum(after[cpu][0] - before[cpu][0] for cpu in cpus)
    total = sum(after[cpu][1] - before[cpu][1] for cpu in cpus)
    return 1.0 - idle / total if total else 0.0


def wait_quiet(cpus, limit=0.10, attempts=30):
    for _ in range(attempts):
        busy = cpu_busy_fraction(cpus)
        if busy <= limit:
            return busy
    raise RuntimeError(f"benchmark CPUs stayed busy ({busy:.0%}); stop other workloads first")


def percentile(values, percentile_value):
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(percentile_value * len(ordered)) - 1))
    return ordered[index]


def process_cpu_seconds(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    ticks = os.sysconf("SC_CLK_TCK")
    return (int(fields[11]) + int(fields[12])) / ticks


def thread_cpu_ticks(pid):
    threads = {}
    for task in Path(f"/proc/{pid}/task").iterdir():
        try:
            fields = (task / "stat").read_text().rsplit(")", 1)[1].split()
            name = (task / "comm").read_text().strip()
        except (FileNotFoundError, ProcessLookupError):
            continue
        threads[int(task.name)] = (name, int(fields[11]) + int(fields[12]))
    return threads


def process_rss_bytes(pid):
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) * 1024
    raise RuntimeError("VmRSS was absent")


def scrape(url):
    with urllib.request.urlopen(url, timeout=2) as response:
        return response.read().decode()


def prometheus_value(text, metric):
    pattern = re.compile(rf"^{re.escape(metric)}(?:\{{[^}}]*\}})?\s+([0-9.eE+-]+)$", re.MULTILINE)
    values = [float(match.group(1)) for match in pattern.finditer(text)]
    return sum(values)


def fluent_metrics(port):
    data = json.loads(scrape(f"http://127.0.0.1:{port}/api/v1/metrics"))
    output = data.get("output", {}).get("null.0", {})
    input_metrics = data.get("input", {}).get("opentelemetry.0", {})
    return {
        "accepted": int(input_metrics.get("records", 0)),
        "completed": int(output.get("proc_records", 0)),
        "dropped": int(output.get("dropped_records", 0)),
        "errors": int(output.get("errors", 0)),
        "retries": int(output.get("retries", 0)),
        "queue": 0,
    }


def collector_metrics(port):
    text = scrape(f"http://127.0.0.1:{port}/metrics")
    return {
        "accepted": int(prometheus_value(text, "otelcol_receiver_accepted_log_records")),
        "completed": int(prometheus_value(text, "otelcol_null_discarded_log_records")),
        "dropped": int(prometheus_value(text, "otelcol_exporter_enqueue_failed_log_records")),
        "errors": int(prometheus_value(text, "otelcol_receiver_refused_log_records")),
        "retries": int(prometheus_value(text, "otelcol_exporter_send_failed_log_records")),
        "queue": int(prometheus_value(text, "otelcol_exporter_queue_size")),
    }


def wait_ready(metrics_function, port, process):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("server exited during startup")
        try:
            metrics_function(port)
            return
        except Exception:
            time.sleep(0.05)
    raise TimeoutError("metrics endpoint did not become ready")


def wait_completed(metrics_function, port, process, expected, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("server exited before drain")
        try:
            current = metrics_function(port)
        except Exception:
            # Fluent Bit answers 404 while no metrics snapshot is published
            time.sleep(0.01)
            continue
        if current["completed"] >= expected and current["queue"] == 0:
            if current["completed"] != expected:
                raise RuntimeError(f"completion exceeded expected count: {current}")
            return current
        time.sleep(0.01)
    raise TimeoutError(f"completion did not reach {expected}")


def make_payloads(batch_records):
    attributes = [
        {"key": f"field{index}", "value": {"stringValue": "representative attribute"}}
        for index in range(10)
    ]
    log_record = {
        "timeUnixNano": "1700000000000000000",
        "severityNumber": 9,
        "severityText": "INFO",
        "body": {"stringValue": "representative benchmark log message"},
        "attributes": attributes,
    }
    request = {
        "resourceLogs": [{
            "resource": {"attributes": [
                {"key": "service.name", "value": {"stringValue": "benchmark"}}
            ]},
            "scopeLogs": [{
                "scope": {"name": "benchmark", "version": "1.0"},
                "logRecords": [log_record] * batch_records,
            }],
        }]
    }
    json_payload = json.dumps(request, separators=(",", ":")).encode()
    from google.protobuf.json_format import ParseDict
    from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
    protobuf_payload = ParseDict(request, ExportLogsServiceRequest()).SerializeToString()
    return {"json": json_payload, "protobuf": protobuf_payload}


def system_kind(name):
    if "otelcol" in name:
        return "collector"
    return "fluent-bit"


def fluent_config(input_port, metrics_port, modified, flush_seconds):
    processor = ""
    if modified:
        processor = """      processors:
        logs:
          - name: content_modifier
            context: otel_log_attributes
            action: upsert
            key: bench.added
            value: yes
"""
    return f"""service:
  flush: {flush_seconds}
  grace: 30
  log_level: error
  http_server: on
  http_listen: 127.0.0.1
  http_port: {metrics_port}
pipeline:
  inputs:
    - name: opentelemetry
      tag: benchmark
      listen: 127.0.0.1
      port: {input_port}
      http2: off
      tls: off
      threaded: true
      http_server.workers: 4
{processor}  outputs:
    - name: null
      match: '*'
"""


def collector_config(input_port, metrics_port, modified, flush_seconds):
    processor_definition = ""
    pipeline_processor = ""
    if modified:
        processor_definition = """processors:
  transform/add_attribute:
    error_mode: propagate
    log_statements:
      - context: log
        statements:
          - set(attributes[\"bench.added\"], \"yes\")

"""
        pipeline_processor = "      processors: [transform/add_attribute]\n"
    return f"""receivers:
  otlp:
    protocols:
      http:
        endpoint: 127.0.0.1:{input_port}

{processor_definition}exporters:
  null/fluent_bit:
    sending_queue:
      enabled: true
      num_consumers: 1
      queue_size: 1000000
      sizer: items
      batch:
        enabled: true
        flush_timeout: {flush_seconds}s
        min_size: 8192
        sizer: items

service:
  telemetry:
    logs:
      level: error
    metrics:
      level: detailed
      readers:
        - pull:
            exporter:
              prometheus:
                host: 127.0.0.1
                port: {metrics_port}
  pipelines:
    logs:
      receivers: [otlp]
{pipeline_processor}      exporters: [null/fluent_bit]
"""


def send_requests(task):
    """Generator process body: one keep-alive connection, bounded retries."""
    port, payload, requests, content_type = task
    latencies = []
    retries = 0
    failures = 0
    cpu_start = time.process_time()
    deadline = time.monotonic() + CLIENT_DEADLINE
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        for _ in range(requests):
            started = time.monotonic_ns()
            while True:
                if time.monotonic() > deadline:
                    raise TimeoutError("client deadline exceeded")
                try:
                    connection.request("POST", "/v1/logs", payload,
                                       {"Content-Type": content_type})
                    response = connection.getresponse()
                    body = response.read()
                    if response.status in (200, 201):
                        failures = 0
                        break
                    if response.status not in (429, 503):
                        raise RuntimeError(f"HTTP {response.status}: {body!r}")
                except (ConnectionError, TimeoutError, http.client.HTTPException, OSError):
                    connection.close()
                    failures += 1
                    if failures >= CLIENT_MAX_CONSECUTIVE_FAILURES:
                        raise
                    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
                retries += 1
                time.sleep(0.0005)
            latencies.append((time.monotonic_ns() - started) / 1000)
    finally:
        connection.close()
    return latencies, retries, time.process_time() - cpu_start


def run_clients(pool, clients, port, payload, requests_per_client, content_type):
    tasks = [(port, payload, requests_per_client, content_type)] * clients
    return pool.map(send_requests, tasks, chunksize=1)


def sample_process(pid, done, samples, metrics_function, metrics_port):
    def take():
        samples.append((time.monotonic(), process_cpu_seconds(pid),
                        process_rss_bytes(pid), metrics_function(metrics_port),
                        thread_cpu_ticks(pid)))

    while not done.is_set():
        try:
            take()
        except FileNotFoundError:
            return
        except Exception:
            pass
        done.wait(SAMPLE_INTERVAL)
    try:
        take()
    except Exception:
        pass


def peak_cpu_cores(samples):
    peak = 0.0
    for start_index, start in enumerate(samples):
        for end in samples[start_index + 1:]:
            elapsed = end[0] - start[0]
            if elapsed >= 1.0:
                peak = max(peak, (end[1] - start[1]) / elapsed)
                break
    return peak


def change_points(samples, key):
    """Samples where the counter first shows a new value."""
    points = []
    previous = None
    for sample in samples:
        value = sample[3][key]
        if value != previous:
            points.append(sample)
            previous = value
    return points


def steady_window(samples, key, base, records, low, high):
    points = change_points(samples, key)
    lower = base + records * low
    upper = base + records * high
    start = next((point for point in points if point[3][key] >= lower), None)
    end = next((point for point in reversed(points) if point[3][key] <= upper), None)
    if start is None or end is None or end[0] - start[0] < 2.0:
        raise RuntimeError(f"steady-state window for {key} is too short; raise --records")
    return start, end


def thread_profile(start, end, top=4):
    ticks = os.sysconf("SC_CLK_TCK")
    elapsed = end[0] - start[0]
    usage = {}
    for tid, (name, value) in end[4].items():
        before = start[4].get(tid, (name, 0))[1]
        usage[(tid, name)] = (value - before) / ticks / elapsed
    ordered = sorted(usage.items(), key=lambda item: item[1], reverse=True)
    busiest = ordered[0][1] if ordered else 0.0
    text = "|".join(f"{name}:{value:.2f}" for (tid, name), value in ordered[:top])
    return busiest, text


def run_once(system, binary, encoding, pipeline, repetition, args, payload, pool):
    records = args.records
    clients = args.clients
    batch_records = args.batch_records
    warmup_records = args.warmup_records
    input_port = free_port()
    metrics_port = free_port()
    modified = pipeline == "modified"
    kind = system_kind(system)
    is_fluent_bit = kind != "collector"
    metrics_function = fluent_metrics if is_fluent_bit else collector_metrics
    if is_fluent_bit:
        config_text = fluent_config(input_port, metrics_port, modified, args.flush_seconds)
    else:
        config_text = collector_config(input_port, metrics_port, modified, args.flush_seconds)
    content_type = "application/json" if encoding == "json" else "application/x-protobuf"
    quiet_busy = wait_quiet(args.server_cpu_set | args.generator_cpu_set)
    with tempfile.TemporaryDirectory(prefix="otel-compare-") as directory:
        config_path = Path(directory) / "config.yaml"
        log_path = Path(directory) / "server.log"
        config_path.write_text(config_text)
        environment = os.environ.copy()
        if not is_fluent_bit:
            environment["GOMAXPROCS"] = str(len(args.server_cpu_set))
        with log_path.open("w+") as log:
            process = subprocess.Popen(
                ["taskset", "-c", args.server_cpus, str(binary), "--config", str(config_path)],
                stdout=log, stderr=log, env=environment,
            )
            try:
                wait_ready(metrics_function, metrics_port, process)
                run_clients(pool, clients, input_port, payload,
                            warmup_records // batch_records // clients, content_type)
                wait_completed(metrics_function, metrics_port, process, warmup_records, 120)
                idle_rss = process_rss_bytes(process.pid)
                start_cpu = process_cpu_seconds(process.pid)
                start = time.monotonic()
                done = threading.Event()
                samples = []
                monitor = threading.Thread(target=sample_process,
                                           args=(process.pid, done, samples,
                                                 metrics_function, metrics_port), daemon=True)
                monitor.start()
                client_results = run_clients(pool, clients, input_port, payload,
                                             records // batch_records // clients,
                                             content_type)
                send_end = time.monotonic()
                final_metrics = wait_completed(metrics_function, metrics_port, process,
                                               warmup_records + records, 600)
                end = time.monotonic()
                end_cpu = process_cpu_seconds(process.pid)
                done.set()
                monitor.join()

                accepted_delta = final_metrics["accepted"] - warmup_records
                completed_delta = final_metrics["completed"] - warmup_records
                if accepted_delta != records or completed_delta != records:
                    raise RuntimeError(f"accounting mismatch: {final_metrics}")
                if final_metrics["dropped"] or final_metrics["errors"]:
                    raise RuntimeError(f"loss/refusal counters are nonzero: {final_metrics}")

                latencies = [latency for result in client_results for latency in result[0]]
                retries = sum(result[1] for result in client_results)
                generator_cpu = sum(result[2] for result in client_results)
                samples = [sample for sample in samples if sample[3] is not None]
                rss_values = [sample[2] for sample in samples]
                peak_rss_sample = max(samples, key=lambda sample: sample[2])
                peak_backlog = max(sample[3]["accepted"] - sample[3]["completed"]
                                   for sample in samples)

                completed_start, completed_end = steady_window(
                    samples, "completed", warmup_records, records,
                    args.window_low, args.window_high)
                steady_seconds = completed_end[0] - completed_start[0]
                steady_records = completed_end[3]["completed"] - completed_start[3]["completed"]
                steady_cpu = completed_end[1] - completed_start[1]
                busiest_thread, threads_text = thread_profile(completed_start, completed_end)

                accepted_start, accepted_end = steady_window(
                    samples, "accepted", warmup_records, records,
                    args.window_low, args.window_high)
                steady_accepted_rate = (
                    (accepted_end[3]["accepted"] - accepted_start[3]["accepted"]) /
                    (accepted_end[0] - accepted_start[0]))

                elapsed = end - start
                send_elapsed = send_end - start
                cpu = end_cpu - start_cpu
                return {
                    "system": system,
                    "repetition": repetition,
                    "pipeline": pipeline,
                    "encoding": encoding,
                    "workers_or_gomaxprocs": len(args.server_cpu_set),
                    "clients": clients,
                    "batch_records": batch_records,
                    "payload_bytes": len(payload),
                    "payload_sha256": hashlib.sha256(payload).hexdigest(),
                    "offered_records": records,
                    "accepted_records": accepted_delta,
                    "completed_records": completed_delta,
                    "client_retries": retries,
                    "dropped_records": final_metrics["dropped"],
                    "refused_records": final_metrics["errors"],
                    "pre_run_cpu_busy": quiet_busy,
                    "send_seconds": send_elapsed,
                    "completion_seconds": elapsed,
                    "steady_window_seconds": steady_seconds,
                    "steady_completed_records_per_second": steady_records / steady_seconds,
                    "steady_accepted_records_per_second": steady_accepted_rate,
                    "steady_cpu_cores": steady_cpu / steady_seconds,
                    "steady_records_per_cpu_second": steady_records / steady_cpu,
                    "busiest_thread_cpu": busiest_thread,
                    "top_threads": threads_text,
                    "end_to_end_records_per_second": records / elapsed,
                    "payload_mib_per_second": (steady_records / batch_records * len(payload) /
                                               steady_seconds / 1048576),
                    "cpu_seconds": cpu,
                    "cpu_seconds_per_million_records": cpu / records * 1_000_000,
                    "average_cpu_cores": cpu / elapsed,
                    "peak_cpu_cores_1s": peak_cpu_cores(samples),
                    "records_per_cpu_second": records / cpu,
                    "generator_cpu_seconds": generator_cpu,
                    "generator_cpu_utilization": (generator_cpu / send_elapsed /
                                                  len(args.generator_cpu_set)),
                    "idle_rss_mib": idle_rss / 1048576,
                    "steady_rss_mib": statistics.median(rss_values) / 1048576,
                    "peak_rss_mib": max(rss_values) / 1048576,
                    "peak_processing_backlog_records": peak_backlog,
                    "backlog_at_peak_rss_records": (
                        peak_rss_sample[3]["accepted"] -
                        peak_rss_sample[3]["completed"]),
                    "latency_p50_us": percentile(latencies, 0.50),
                    "latency_p95_us": percentile(latencies, 0.95),
                    "latency_p99_us": percentile(latencies, 0.99),
                    "final_queue_items": final_metrics["queue"],
                }
            except Exception:
                log.flush()
                log.seek(0)
                print(log.read(), flush=True)
                raise
            finally:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


SUMMARY_FIELDS = (
    "steady_completed_records_per_second", "steady_accepted_records_per_second",
    "steady_cpu_cores", "steady_records_per_cpu_second", "busiest_thread_cpu",
    "end_to_end_records_per_second", "payload_mib_per_second",
    "cpu_seconds_per_million_records", "records_per_cpu_second", "average_cpu_cores",
    "peak_cpu_cores_1s", "generator_cpu_utilization",
    "idle_rss_mib", "steady_rss_mib", "peak_rss_mib", "peak_processing_backlog_records",
    "latency_p50_us", "latency_p95_us", "latency_p99_us",
)


def summarize(rows, systems):
    summary = []
    for pipeline in PIPELINES:
        for encoding in ENCODINGS:
            for system in systems:
                selected = [row for row in rows if row["pipeline"] == pipeline
                            and row["encoding"] == encoding and row["system"] == system]
                if not selected:
                    continue
                output = {
                    "pipeline": pipeline,
                    "encoding": encoding,
                    "system": system,
                    "repetitions": len(selected),
                }
                for field in SUMMARY_FIELDS:
                    values = [float(row[field]) for row in selected]
                    output[f"median_{field}"] = statistics.median(values)
                    output[f"min_{field}"] = min(values)
                    output[f"max_{field}"] = max(values)
                output["total_retries"] = sum(int(row["client_retries"]) for row in selected)
                output["total_dropped"] = sum(int(row["dropped_records"]) for row in selected)
                output["total_refused"] = sum(int(row["refused_records"]) for row in selected)
                summary.append(output)
    return summary


def write_csv(path, rows):
    with path.open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def output_path(prefix, suffix):
    return Path(f"{prefix}{suffix}")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--system", action="append", required=True, metavar="NAME=PATH",
                        help="binary to measure; names containing 'otelcol' run as the "
                             "Collector, any other name as Fluent Bit")
    parser.add_argument("--output-prefix", type=Path, required=True)
    parser.add_argument("--records", type=int, default=30_000_000)
    parser.add_argument("--warmup-records", type=int, default=320_000)
    parser.add_argument("--batch-records", type=int, default=100)
    parser.add_argument("--clients", type=int, default=16)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--flush-seconds", type=float, default=0.5)
    parser.add_argument("--server-cpus", default="0-3")
    parser.add_argument("--generator-cpus", default="4-7,12-15")
    parser.add_argument("--window-low", type=float, default=0.10)
    parser.add_argument("--window-high", type=float, default=0.90)
    parser.add_argument("--pipelines", default=",".join(PIPELINES))
    parser.add_argument("--encodings", default=",".join(ENCODINGS))
    args = parser.parse_args()
    divisor = args.batch_records * args.clients
    if args.records % divisor or args.warmup_records % divisor:
        parser.error("record and warm-up counts must divide evenly across batches and clients")

    args.server_cpu_set = parse_cpus(args.server_cpus)
    args.generator_cpu_set = parse_cpus(args.generator_cpus)
    check_topology(args.server_cpu_set, args.generator_cpu_set)
    os.sched_setaffinity(0, args.generator_cpu_set)

    binaries = {}
    for item in args.system:
        name, path = item.split("=", 1)
        binaries[name] = Path(path).resolve()
    systems = tuple(binaries)
    pipelines = tuple(args.pipelines.split(","))
    encodings = tuple(args.encodings.split(","))

    payloads = make_payloads(args.batch_records)
    manifest = {
        "created_unix": time.time(),
        "server_cpus": sorted(args.server_cpu_set),
        "generator_cpus": sorted(args.generator_cpu_set),
        "arguments": {key: str(value) for key, value in vars(args).items()},
        "binaries": {system: str(path) for system, path in binaries.items()},
        "binary_sha256": {
            system: hashlib.sha256(path.read_bytes()).hexdigest()
            for system, path in binaries.items()
        },
        "payloads": {
            encoding: {"bytes": len(payload),
                       "sha256": hashlib.sha256(payload).hexdigest()}
            for encoding, payload in payloads.items()
        },
        "transformation": "upsert log attribute bench.added as string yes",
    }
    args.output_prefix.parent.mkdir(parents=True, exist_ok=True)
    output_path(args.output_prefix, ".manifest.json").write_text(
        json.dumps(manifest, indent=2, default=str) + "\n")

    rows = []
    context = multiprocessing.get_context("fork")
    with context.Pool(args.clients) as pool:
        for repetition in range(1, args.runs + 1):
            for pipeline in pipelines:
                for encoding in encodings:
                    offset = (repetition - 1) % len(systems)
                    order = systems[offset:] + systems[:offset]
                    for system in order:
                        row = run_once(system, binaries[system], encoding, pipeline,
                                       repetition, args, payloads[encoding], pool)
                        rows.append(row)
                        write_csv(output_path(args.output_prefix, ".raw.csv"), rows)
                        print(json.dumps(row, sort_keys=True), flush=True)
    write_csv(output_path(args.output_prefix, ".summary.csv"), summarize(rows, systems))


if __name__ == "__main__":
    main()
