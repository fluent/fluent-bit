#!/usr/bin/env python3
"""Measure completed HTTP/Forward/OTLP -> body content_modifier -> null pipelines.

OTLP protobuf requires the Python dependencies in tests/integration/requirements.txt.
OTLP logs include resource/scope groups, which retain the CFL processing path.

Linux only. Uses equal CPU affinity, fresh processes, alternating run order,
10,000 warm-up records, four clients, and exact output-counter checks. CPU
seconds count only Fluent Bit; wall time ends after output completion. The
Forward workload uses PackedForward with V2 events and no compression/acks.
Field counts represent body width. Compare each input and width separately.
"""

import argparse
import concurrent.futures
import csv
import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import socket
import struct
import subprocess
import tempfile
import time


WARMUP_RECORDS = 10000
BATCH_RECORDS = 1000
CLIENTS = 4


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


class MetricsNotReady(RuntimeError):
    pass


def get_metrics(port):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request("GET", "/api/v1/metrics")
        response = connection.getresponse()
        if response.status == 404:
            raise MetricsNotReady("Metrics snapshot is not available yet")
        if response.status != 200:
            raise RuntimeError(f"Metrics HTTP status: {response.status}")
        return json.loads(response.read())
    finally:
        connection.close()


def wait_for_count(port, expected, process):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Fluent Bit exited before output completion")
        try:
            metrics = get_metrics(port)
        except MetricsNotReady:
            time.sleep(0.01)
            continue
        output = metrics.get("output", {}).get("null.0", {})
        count = output.get("proc_records", 0)
        if count >= expected:
            if count != expected or output.get("dropped_records", 0) != 0:
                raise RuntimeError(f"Unexpected output counters: {output}")
            return
        time.sleep(0.01)
    raise TimeoutError(f"Output did not reach {expected} records")


def cpu_seconds(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


def send_http(port, payload, batches, path="/bench", content_type="application/json"):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        for _ in range(batches):
            connection.request("POST", path, payload, {"Content-Type": content_type})
            response = connection.getresponse()
            body = response.read()
            if response.status != 201:
                raise RuntimeError(f"Input response: {response.status} {body!r}")
    finally:
        connection.close()


def pack_string(value):
    value = value.encode()
    return b"\xdb" + struct.pack(">I", len(value)) + value


def send_forward(port, payload, batches):
    with socket.create_connection(("127.0.0.1", port), timeout=30) as connection:
        for _ in range(batches):
            connection.sendall(payload)


def make_payload(input_name, fields):
    record = {f"field{index}": "representative log attribute" for index in range(fields)}
    if input_name == "http":
        return json.dumps([record] * BATCH_RECORDS, separators=(",", ":")).encode()
    if input_name.startswith("otlp-"):
        log = {"timeUnixNano": "1700000000000000000",
               "body": {"kvlistValue": {"values": [
                   {"key": key, "value": {"stringValue": value}} for key, value in record.items()
               ]}}}
        request = {"resourceLogs": [{"resource": {"attributes": [
            {"key": "service.name", "value": {"stringValue": "perf"}}]},
            "scopeLogs": [{"scope": {"name": "benchmark"}, "logRecords": [log] * BATCH_RECORDS}]}]}
        if input_name == "otlp-json":
            return json.dumps(request, separators=(",", ":")).encode()
        from google.protobuf.json_format import ParseDict
        from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
        return ParseDict(request, ExportLogsServiceRequest()).SerializeToString()
    body = b"\xde" + struct.pack(">H", len(record))
    body += b"".join(pack_string(key) + pack_string(value) for key, value in record.items())
    entry = b"\x92\x92\xce" + struct.pack(">I", 1700000000) + b"\x80" + body
    entries = entry * BATCH_RECORDS
    return b"\x92" + pack_string("bench") + b"\xc6" + struct.pack(">I", len(entries)) + entries


def run(binary, records, fields, cpu, input_name, modifiers, mixed, location):
    input_port = free_port()
    metrics_port = free_port()
    payload = make_payload(input_name, fields)
    if input_name.startswith("otlp-"):
        content_type = "application/x-protobuf" if input_name == "otlp-protobuf" else "application/json"
        def sender(port, data, batches):
            return send_http(port, data, batches, "/v1/logs", content_type)
    else:
        sender = send_http if input_name == "http" else send_forward
    plugin_name = "opentelemetry" if input_name.startswith("otlp-") else input_name
    actions = "".join(
        "          - name: content_modifier\n"
        "            context: body\n"
        "            action: upsert\n"
        f"            key: environment{index}\n"
        "            value: production\n"
        for index in range(modifiers)
    )
    if mixed:
        actions += ("          - name: content_modifier\n"
                    "            context: body\n"
                    "            action: hash\n"
                    "            key: environment0\n")
    processor_config = ""
    if actions:
        processor_config = "      processors:\n        logs:\n" + actions
    input_processors = processor_config if location == "input" else ""
    output_processors = processor_config if location == "output" else ""
    config = f"""service:
  flush: 0.1
  grace: 1
  log_level: error
  http_server: on
  http_listen: 127.0.0.1
  http_port: {metrics_port}
pipeline:
  inputs:
    - name: {plugin_name}
      listen: 127.0.0.1
      port: {input_port}
      tag: bench
      buffer_max_size: 16M
{input_processors}  outputs:
    - name: null
      match: '*'
{output_processors}"""
    with tempfile.TemporaryDirectory(prefix="flb-pipeline-perf-") as directory:
        path = Path(directory)
        config_path = path / "fluent-bit.yaml"
        config_path.write_text(config)
        with (path / "stderr.log").open("w+") as log:
            process = subprocess.Popen(
                ["taskset", "-c", str(cpu), str(binary), "-c", str(config_path)],
                stdout=log, stderr=log,
            )
            try:
                deadline = time.monotonic() + 15
                while True:
                    try:
                        get_metrics(metrics_port)
                        break
                    except (OSError, ValueError, RuntimeError):
                        if time.monotonic() > deadline or process.poll() is not None:
                            log.seek(0)
                            raise RuntimeError(log.read())
                        time.sleep(0.05)
                sender(input_port, payload, WARMUP_RECORDS // BATCH_RECORDS)
                wait_for_count(metrics_port, WARMUP_RECORDS, process)
                start_cpu = cpu_seconds(process.pid)
                start = time.monotonic()
                with concurrent.futures.ThreadPoolExecutor(max_workers=CLIENTS) as pool:
                    tasks = [pool.submit(sender, input_port, payload,
                                         records // (CLIENTS * BATCH_RECORDS))
                             for _ in range(CLIENTS)]
                    for task in tasks:
                        task.result()
                wait_for_count(metrics_port, records + WARMUP_RECORDS, process)
                elapsed = time.monotonic() - start
                cpu_used = cpu_seconds(process.pid) - start_cpu
                return {"input": input_name, "records": records, "fields": fields,
                        "modifiers": modifiers, "mixed": mixed, "location": location,
                        "elapsed_s": elapsed, "cpu_s": cpu_used,
                        "records_per_second": records / elapsed,
                        "cpu_s_per_million": cpu_used * 1e6 / records,
                        "payload_sha256": hashlib.sha256(payload).hexdigest(),
                        "output_records": records}
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--records", type=int, default=1000000)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--input", choices=("http", "forward", "otlp-json", "otlp-protobuf"), default="http")
    parser.add_argument("--fields", type=int, nargs="+", default=[12, 128])
    parser.add_argument("--modifiers", type=int, default=1)
    parser.add_argument("--location", choices=("input", "output"), default="input")
    parser.add_argument("--mixed", action="store_true", help="Append a CFL-only hash operation")
    args = parser.parse_args()
    if args.records <= 0 or args.records % (CLIENTS * BATCH_RECORDS) or args.runs <= 0:
        parser.error("records must be a positive multiple of 4000; runs must be positive")
    if args.modifiers < 0 or (args.mixed and args.modifiers == 0):
        parser.error("modifiers must be nonnegative; mixed requires at least one modifier")
    if any(fields < 1 or fields > 128 for fields in args.fields):
        parser.error("fields must be between 1 and 128 (16M maximum batch size)")
    cpu = min(os.sched_getaffinity(0))
    binaries = {"baseline": args.baseline.resolve(), "candidate": args.candidate.resolve()}
    hashes = {name: hashlib.sha256(binary.read_bytes()).hexdigest()
              for name, binary in binaries.items()}
    manifest = {"created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "platform": platform.platform(), "cpu": cpu,
                "cpu_info": Path("/proc/cpuinfo").read_text(),
                "arguments": {key: str(value) if isinstance(value, Path) else value
                              for key, value in vars(args).items()},
                "binaries": {name: str(binary) for name, binary in binaries.items()},
                "binary_sha256": hashes, "warmup_records": WARMUP_RECORDS,
                "batch_records": BATCH_RECORDS, "clients": CLIENTS,
                "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    args.output.with_suffix(".manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    with args.output.open("w") as output:
        writer = None
        for fields in args.fields:
            for repetition in range(1, args.runs + 1):
                order = ("baseline", "candidate") if repetition % 2 else ("candidate", "baseline")
                for system in order:
                    if hashlib.sha256(binaries[system].read_bytes()).hexdigest() != hashes[system]:
                        raise RuntimeError(f"The {system} binary changed during the campaign")
                    row = run(binaries[system], args.records, fields, cpu, args.input,
                              args.modifiers, args.mixed, args.location)
                    row.update(system=system, repetition=repetition, cpu=cpu,
                               binary_sha256=hashes[system])
                    if writer is None:
                        writer = csv.DictWriter(output, fieldnames=list(row))
                        writer.writeheader()
                    writer.writerow(row)
                    output.flush()
                    print(json.dumps(row), flush=True)


if __name__ == "__main__":
    main()
