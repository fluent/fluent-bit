#!/usr/bin/env python3
"""Compare end-to-end rewrite_tag paths; reject samples with missing records.

Requires Linux /usr/bin/time, PyYAML, and release builds with tail/counter enabled.
All variants use the same input file, parser, output, and downstream processors.
"""
import argparse
import csv
import json
import os
from pathlib import Path
import random
import selectors
import signal
import time
import statistics
import subprocess
import tempfile

import yaml


ROOT = Path(__file__).resolve().parents[2]


def configuration(path, placement, batch_size, keep):
    rewrite = {"name": "rewrite_tag", "rule": f"$kind ^emit$ routed.$destination {str(keep).lower()}"}
    downstream = [
        {"name": "content_modifier", "action": "insert", "key": "processed", "value": "yes"},
        {"name": "content_modifier", "action": "insert", "key": "region", "value": "test"},
    ]
    input_config = {
        "name": "tail", "path": str(path), "tag": "source", "parser": "json",
        "read_from_head": True,
        "buffer_chunk_size": "128K", "buffer_max_size": "128K", "static_batch_size": "128K",
    }
    filters = []
    if placement == "filter":
        rewrite.update({"match": "source", "emitter_mem_buf_limit": "256M"})
        filters = [rewrite]
        input_config["processors"] = {"logs": downstream}
    else:
        if batch_size:
            rewrite["batch_size"] = batch_size
        input_config["processors"] = {"logs": [rewrite, *downstream]}
    return {
        "service": {"flush": 0.05, "grace": 1, "log_level": "error",
                    "parsers_file": str(ROOT / "conf/parsers.conf")},
        "pipeline": {"inputs": [input_config], "filters": filters,
                     "outputs": [{"name": "counter", "match": "*", "workers": 0}]},
    }


def run_sample(binary, config, timing, errors, expected):
    # Wait for verified delivery before shutdown. EOF-triggered shutdown in the
    # original filter can discard its pending queue, invalidating comparisons.
    command = ["/usr/bin/time", "-f", "%e,%U,%S,%M", "-o", str(timing),
               "stdbuf", "-oL", str(binary), "-c", str(config)]
    delivered = 0
    pending = b""
    deadline = time.monotonic() + 180
    with errors.open("w") as stderr:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=stderr,
                                   env={**os.environ, "LC_ALL": "C"})
        child = None
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while delivered < expected:
                    if time.monotonic() > deadline:
                        raise RuntimeError(f"delivery timeout: got {delivered}, expected {expected}")
                    if child is None:
                        children = Path(f"/proc/{process.pid}/task/{process.pid}/children").read_text().split()
                        if children:
                            child = int(children[0])
                    for key, _ in selector.select(timeout=0.1):
                        block = os.read(key.fileobj.fileno(), 65536)
                        if not block:
                            raise RuntimeError(f"premature exit: got {delivered}, expected {expected}")
                        pending += block
                        lines = pending.split(b"\n")
                        pending = lines.pop()
                        for line in lines:
                            try:
                                delivered += json.loads(line).get("log_records", 0)
                            except (ValueError, AttributeError):
                                pass
            if child is None:
                raise RuntimeError("could not locate Fluent Bit child process")
            os.kill(child, signal.SIGTERM)
            remainder, _ = process.communicate(timeout=15)
            for line in (pending + remainder).splitlines():
                try:
                    delivered += json.loads(line).get("log_records", 0)
                except (ValueError, AttributeError):
                    pass
            if process.returncode or delivered != expected:
                raise RuntimeError(f"exit={process.returncode}, delivered={delivered}, expected={expected}")
        finally:
            if process.poll() is None:
                if child is not None:
                    os.kill(child, signal.SIGKILL)
                process.kill()
                process.wait()
            process.stdout.close()
    return delivered


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--poc", type=Path, required=True)
    parser.add_argument("--records", type=int, default=500000)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--tags", type=int, nargs="+", default=[1, 16, 1024])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cpu", type=int, help="Pin the driver and Fluent Bit to this CPU")
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--no-match", action="store_true")
    args = parser.parse_args()
    if args.cpu is not None:
        os.sched_setaffinity(0, {args.cpu})
    if args.records < 1 or args.repetitions < 1 or min(args.tags) < 1:
        parser.error("records, repetitions, and tags must be positive")
    variants = [
        ("baseline-filter", args.baseline.resolve(), "filter", 0),
        ("baseline-processor", args.baseline.resolve(), "processor", 0),
        ("poc-processor-off", args.poc.resolve(), "processor", 0),
        ("poc-processor-batch", args.poc.resolve(), "processor", 4096),
    ]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    with tempfile.TemporaryDirectory(prefix="rewrite-tag-bench-") as temporary:
        directory = Path(temporary)
        for tag_count in args.tags:
            source = directory / "records.jsonl"
            with source.open("w") as handle:
                for index in range(args.records):
                    handle.write(json.dumps({
                        "kind": "pass" if args.no_match else "emit",
                        "destination": str(index % tag_count), "id": index,
                        "message": "x" * 96,
                    }, separators=(",", ":")) + "\n")
            # Warm the page cache; all samples use this identical source.
            with source.open("rb") as handle:
                while handle.read(1024 * 1024):
                    pass
            for repetition in range(args.repetitions):
                order = variants.copy()
                random.Random(1000 + repetition).shuffle(order)
                for name, binary, placement, batch_size in order:
                    config = directory / "config.yaml"
                    config.write_text(yaml.safe_dump(configuration(
                        source, placement, batch_size, args.keep)))
                    timing = directory / "time.txt"
                    expected = args.records * (2 if args.keep and not args.no_match else 1)
                    delivered = run_sample(binary, config, timing, directory / "stderr.log", expected)
                    wall, user, system, rss = map(float, timing.read_text().strip().split(","))
                    row = dict(variant=name, tags=tag_count, repetition=repetition,
                               records=args.records, delivered=delivered, keep=args.keep,
                               no_match=args.no_match, wall_s=wall, cpu_s=user + system,
                               peak_rss_kib=int(rss), input_records_per_cpu_s=args.records / (user + system))
                    rows.append(row)
                    print(json.dumps(row), flush=True)
    with args.output.open("w") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    for tag_count in args.tags:
        for name, *_ in variants:
            samples = [row for row in rows if row["tags"] == tag_count and row["variant"] == name]
            print(f"{name:24s} tags={tag_count:4d} "
                  f"median_cpu={statistics.median(row['cpu_s'] for row in samples):.3f}s "
                  f"median_rss={statistics.median(row['peak_rss_kib'] for row in samples):.0f}KiB")


if __name__ == "__main__":
    main()
