#!/usr/bin/env python3
"""Compare two instrumented Fluent Bit binaries using the ChunkIO pipeline harness.

Build each revision with FLB_RELEASE=On and FLB_IPO=Off. Before rebuilding the
candidate, use --link-build BUILD --variant base to preserve the baseline binary.
Repeat with --variant head after rebuilding, then use --measure. Artifacts are
written outside the checkout to --output; existing run directories are refused.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shlex
import statistics
import subprocess

REPO = Path(__file__).resolve().parents[2]
HARNESS = REPO / "lib/chunkio/tools/benchmarks/fluent_bit"


def link(build, output, variant):
    build = build.resolve()
    binary_dir = output / "bin"
    binary_dir.mkdir(parents=True, exist_ok=True)
    observer = binary_dir / "observer.o"
    subprocess.run(["cc", "-O2", "-c", str(HARNESS / "observer.c"),
                    "-o", str(observer)], check=True)
    command = shlex.split((build / "src/CMakeFiles/fluent-bit-bin.dir/link.txt").read_text())
    command[command.index("-o") + 1] = str(binary_dir / f"fluent-bit-{variant}")
    command.append(str(observer))
    for symbol in ["cio_file_native_remap", "cio_file_native_resize",
                   "cio_file_native_map", "flb_input_log_append_records"]:
        command.append("-Wl,--wrap=" + symbol)
    subprocess.run(command, cwd=build / "src", check=True)
    cache = (build / "CMakeCache.txt").read_text().splitlines()
    source = Path(next(line.split("=", 1)[1] for line in cache
                       if line.startswith("CMAKE_HOME_DIRECTORY:INTERNAL=")))
    metadata = {"link": command,
                "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip(),
                "diff": subprocess.check_output(["git", "diff", "HEAD", "--", "src/flb_input_chunk.c"], cwd=source, text=True),
                "source_sha256": hashlib.sha256((source / "src/flb_input_chunk.c").read_bytes()).hexdigest(),
                "compile_flags": (build / "src/CMakeFiles/fluent-bit-static.dir/flags.make").read_text(),
                "sha256": hashlib.sha256((binary_dir / f"fluent-bit-{variant}").read_bytes()).hexdigest()}
    (output / f"build-{variant}.json").write_text(json.dumps(metadata, indent=2) + "\n")


def measure(output, cpu, repeats, cases):
    os.environ["CIO_FLB_BENCH_ROOT"] = str(output)
    os.environ["CIO_FLB_BENCH_CPU"] = str(cpu)
    spec = importlib.util.spec_from_file_location("chunkio_pipeline", HARNESS / "run.py")
    harness = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(harness)
    samples = []
    for case in cases:
        for iteration in range(repeats + 1):
            variants = ("base", "head") if iteration % 2 == 0 else ("head", "base")
            for variant in variants:
                label = "warmup" if iteration == 0 else f"sample-{iteration}"
                samples.append(harness.run(case, variant, label))
                (output / "samples.json").write_text(json.dumps(samples, indent=2) + "\n")
    metrics = ["cpu_seconds", "ingest_mib_per_second", "peak_allocated_bytes", "remaps", "max_rss_kib"]
    summary = {}
    for case in cases:
        summary[case] = {}
        for metric in metrics:
            values = {}
            for variant in ("base", "head"):
                data = [s[metric] for s in samples if s["case"] == case
                        and s["variant"] == variant and s["label"] != "warmup"]
                values[variant] = {"median": statistics.median(data), "min": min(data), "max": max(data)}
            baseline = values["base"]["median"]
            values["change_percent"] = (values["head"]["median"] / baseline - 1) * 100 if baseline else None
            summary[case][metric] = values
    result = {"platform": platform.platform(), "cpu_affinity": cpu,
              "page_size": os.sysconf("SC_PAGESIZE"), "repeats": repeats,
              "summary": summary}
    (output / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--link-build", type=Path)
    parser.add_argument("--variant", choices=["base", "head"])
    parser.add_argument("--measure", action="store_true")
    parser.add_argument("--cpu", type=int, default=min(os.sched_getaffinity(0)))
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--cases", nargs="+", default=["many_tags", "steady_fs", "steady_crc", "memory"])
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    if args.link_build:
        if not args.variant:
            parser.error("--link-build requires --variant")
        link(args.link_build, args.output, args.variant)
    if args.measure:
        if args.repeats < 1:
            parser.error("--repeats must be positive")
        measure(args.output, args.cpu, args.repeats, args.cases)
