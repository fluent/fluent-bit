#!/usr/bin/env python3
"""Linux tail overload benchmark; Python standard library only."""

import argparse
import csv
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request


def fetch(port, endpoint):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/{endpoint}", timeout=0.5) as response:
        return json.load(response)


def resources(pid):
    # /proc stat starts with PID and a parenthesized command that may contain spaces.
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    ticks = int(fields[11]) + int(fields[12])
    rss = int(fields[21]) * os.sysconf("SC_PAGE_SIZE")
    return ticks / os.sysconf("SC_CLK_TCK"), rss


def write_load(path, phases, record, stop, state):
    try:
        with path.open("ab", buffering=0) as stream:
            for phase, (rate, duration) in enumerate(phases):
                state["phase"] = phase
                start = time.monotonic()
                initial_bytes = state["written_bytes"]
                sent = 0
                while not stop.is_set():
                    elapsed = time.monotonic() - start
                    if elapsed >= duration:
                        break
                    target = int(rate * 1_000_000 * elapsed / len(record))
                    count = min(max(0, target - sent), max(1, 65536 // len(record)))
                    if count:
                        payload = memoryview(record * count)
                        while payload:
                            written = stream.write(payload)
                            payload = payload[written:]
                            state["written_bytes"] += written
                        sent += count
                    else:
                        stop.wait(0.01)
                state["phase_stats"].append({
                    "written_bytes": state["written_bytes"] - initial_bytes,
                    "duration_seconds": time.monotonic() - start,
                })
            state["done"] = True
    except Exception as exc:
        state["error"] = repr(exc)
        state["done"] = True


def make_config(root, parser_count):
    parsers = root / "parsers.conf"
    parsers.write_text(r'''[MULTILINE_PARSER]
    name benchmark_lines
    type regex
    flush_timeout 1000
    rule "start_state" "/^START /" "continuation"
    rule "continuation" "/^ /" "continuation"

[PARSER]
    Name benchmark_fields
    Format regex
    Regex ^START id=(?<id>[0-9]+) level=(?<level>[A-Z]+) message=(?<message>[\s\S]*)$
''')
    filters = """    - name: multiline
      match: '*'
      multiline.key_content: log
      multiline.parser: benchmark_lines
      buffer: on
      flush_ms: 1000
"""
    filters += """    - name: parser
      match: '*'
      key_name: log
      parser: benchmark_fields
      reserve_data: true
      preserve_key: true
""" * parser_count
    config = root / "fluent-bit.yaml"
    config.write_text(f"""service:
  flush: 1
  grace: 3
  log_level: warn
  http_server: on
  http_listen: 127.0.0.1
  http_port: ${{BENCH_HTTP_PORT}}
  storage.path: ${{BENCH_STORAGE_PATH}}
  storage.metrics: on
  storage.max_chunks_up: 8
  parsers_file: {json.dumps(str(parsers))}
pipeline:
  inputs:
    - name: tail
      path: ${{BENCH_LOG_PATH}}
      tag: benchmark
      read_from_head: true
      threaded: true
      storage.type: filesystem
      storage.pause_on_chunks_overlimit: off
  filters:
{filters}
  outputs:
    - name: 'null'
      match: '*'
      workers: 1
      storage.total_limit_size: 128M
      retry_limit: false
""")
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("build/bin/fluent-bit"))
    parser.add_argument("--output", type=Path, required=True, help="new directory for logs and results")
    parser.add_argument("--rates", default="2,2.5,3,3.5,4", help="comma-separated decimal MB/s")
    parser.add_argument("--phase-seconds", type=float, default=60)
    parser.add_argument("--drain-seconds", type=float, default=60)
    parser.add_argument("--parser-count", type=int, default=8)
    parser.add_argument("--record-bytes", type=int, default=1024)
    parser.add_argument("--stall-seconds", type=float, default=10)
    parser.add_argument("--config", type=Path, help="optional config using BENCH_* environment variables")
    args = parser.parse_args()
    try:
        rates = [float(rate) for rate in args.rates.split(",")]
    except ValueError:
        parser.error("rates must be comma-separated numbers")
    if (not rates or any(not 0 < rate < 100000 for rate in rates)
            or not 0 < args.phase_seconds < 86400 or not 0 < args.drain_seconds < 86400
            or not 0 < args.stall_seconds < 86400 or args.parser_count < 0
            or not 128 <= args.record_bytes <= 30000):
        parser.error("invalid rate, duration, parser count, or record size (128..30000)")
    if not Path("/proc/self/stat").exists():
        parser.error("this benchmark requires Linux /proc")
    binary = args.binary.resolve(strict=True)
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    log_path = root / "input.log"
    log_path.touch()
    config = args.config.resolve(strict=True) if args.config else make_config(root, args.parser_count)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    env = dict(os.environ, BENCH_LOG_PATH=str(log_path), BENCH_HTTP_PORT=str(port),
               BENCH_STORAGE_PATH=str(root / "storage"))
    phases = [(rate, args.phase_seconds) for rate in rates] + [(0, args.drain_seconds)]
    prefix = b"START id=123456 level=ERROR message="
    suffix = b"\n  at benchmark.work(worker.c:123)\n"
    record = prefix + b"x" * (args.record_bytes - len(prefix) - len(suffix)) + suffix
    metadata = {"arguments": {key: str(value) if isinstance(value, Path) else value
                              for key, value in vars(args).items()},
                "binary": str(binary), "config": str(config), "phases": phases,
                "platform": list(os.uname()), "cpu_count": os.cpu_count(),
                "version": subprocess.run([str(binary), "--version"], capture_output=True,
                                          text=True, check=True).stdout}
    (root / "metadata.json").write_text(json.dumps(metadata, indent=2))
    stop = threading.Event()
    state = {"phase": 0, "written_bytes": 0, "done": False, "phase_stats": []}
    samples = []
    writer = None
    forced_shutdown = False
    with (root / "fluent-bit.log").open("w") as logs:
        process = subprocess.Popen([str(binary), "-c", str(config)], env=env,
                                   stdout=logs, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 20
            while True:
                if process.poll() is not None:
                    raise RuntimeError(f"Fluent Bit exited: see {root / 'fluent-bit.log'}")
                try:
                    fetch(port, "metrics")
                    break
                except (OSError, ValueError):
                    if time.monotonic() >= deadline:
                        raise RuntimeError("metrics endpoint did not become ready")
                    time.sleep(0.1)
            start = time.monotonic()
            previous_time = start
            previous_cpu, _ = resources(process.pid)
            writer = threading.Thread(target=write_load, args=(log_path, phases, record, stop, state))
            writer.start()
            with (root / "samples.jsonl").open("w") as raw:
                while True:
                    now = time.monotonic()
                    cpu, rss = resources(process.pid)
                    sample = {"seconds": round(now - start, 3), "phase": state["phase"],
                              "target_mb_s": phases[state["phase"]][0],
                              "written_bytes": state["written_bytes"], "rss_bytes": rss,
                              "cpu_percent": 100 * (cpu - previous_cpu) / max(now - previous_time, 0.001)}
                    previous_cpu, previous_time = cpu, now
                    for endpoint in ("metrics", "storage"):
                        try:
                            sample[endpoint] = fetch(port, endpoint)
                        except (OSError, ValueError) as exc:
                            sample[endpoint + "_error"] = str(exc)
                    output = sample.get("metrics", {}).get("output", {})
                    sample["storage_chunks"] = sample.get("storage", {}).get("storage_layer", {}).get("chunks", {}).get("total_chunks")
                    for key in ("proc_records", "dropped_records", "errors", "retries"):
                        sample[key] = sum(item.get(key, 0) for item in output.values()) if output else None
                    raw.write(json.dumps(sample) + "\n")
                    raw.flush()
                    samples.append(sample)
                    if state["done"]:
                        break
                    if process.poll() is not None:
                        raise RuntimeError("Fluent Bit exited during the ramp")
                    stop.wait(1)
            if "error" in state:
                raise RuntimeError(state["error"])
        finally:
            stop.set()
            if writer:
                writer.join(timeout=5)
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                forced_shutdown = True
                process.kill()
                process.wait()
    # Missing metrics are unknown, never zero; stale counters count as no progress.
    last_progress = 0
    last_count = 0
    stalls = []
    unavailable = 0
    for sample in samples:
        count = sample["proc_records"]
        if count is None:
            unavailable += 1
            continue
        if count > last_count:
            last_progress = sample["seconds"]
        last_count = count
        if sample["target_mb_s"] > 0 and sample["seconds"] - last_progress >= args.stall_seconds:
            stalls.append(sample["seconds"])
    fields = ["seconds", "phase", "target_mb_s", "written_bytes", "cpu_percent", "rss_bytes",
              "proc_records", "dropped_records", "errors", "retries", "storage_chunks"]
    with (root / "samples.csv").open("w") as handle:
        table = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        table.writeheader()
        table.writerows(samples)
    summary = {"output_stall_samples": stalls, "missing_output_metric_samples": unavailable,
               "forced_shutdown": forced_shutdown, "exit_code": process.returncode,
               "written_bytes": state["written_bytes"], "final_proc_records": last_count,
               "results": str(root)}
    phase_summary = []
    previous = samples[0]
    for index, (rate, duration) in enumerate(phases):
        selected = [sample for sample in samples if sample["phase"] == index]
        if not selected:
            continue
        final = selected[-1]
        load = state["phase_stats"][index]
        row = {"phase": index, "target_mb_s": rate,
               "achieved_mb_s": load["written_bytes"] / load["duration_seconds"] / 1_000_000,
               "cpu_percent_avg": sum(sample["cpu_percent"] for sample in selected) / len(selected),
               "rss_bytes_end": final["rss_bytes"], "storage_chunks_end": final["storage_chunks"]}
        for key in ("proc_records", "dropped_records"):
            row[key + "_delta"] = (final[key] - previous[key]
                                   if final[key] is not None and previous[key] is not None else None)
        phase_summary.append(row)
        previous = final
    summary["phases"] = phase_summary
    (root / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    return 2 if stalls or unavailable or forced_shutdown or process.returncode else 0


if __name__ == "__main__":
    raise SystemExit(main())
