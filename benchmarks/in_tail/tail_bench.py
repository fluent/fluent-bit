#!/usr/bin/env python3
"""in_tail benchmark harness.

Measures CPU time, wall time and (optionally, through strace) system calls of
a Fluent Bit binary for two workloads:

  static  one or many files that already exist are read from the head
  live    N files are monitored while a paced writer appends lines to them

Every run verifies that the number of ingested records matches the number of
lines written, so a result is only meaningful when "ok" is true.

Examples:

  ./tail_bench.py static --bin build/bin/fluent-bit --size 2048
  ./tail_bench.py static --bin build/bin/fluent-bit --base /var/tmp --db
  ./tail_bench.py live --bin build/bin/fluent-bit --files 10000 --idle 6
  ./tail_bench.py live --bin build/bin/fluent-bit --files 2000 --strace
"""

import argparse
import json
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.request

PARSERS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "parsers.conf")

LINE = ("2026-11-15T10:00:00.000000Z stdout F {seq:012d} " + "x" * 104 + "\n")
CLK = os.sysconf("SC_CLK_TCK")


def proc_cpu(pid):
    with open(f"/proc/{pid}/stat") as f:
        parts = f.read().rsplit(")", 1)[1].split()
    return int(parts[11]) / CLK, int(parts[12]) / CLK


def metrics(port):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/metrics",
                                timeout=5) as r:
        return json.load(r)


def records(port):
    try:
        return metrics(port)["input"]["tail.0"]["records"]
    except Exception:
        return -1


def write_conf(path, logdir, args, extra="", http_port=0, output="null"):
    db = f"    db {args.workdir}/tail.db\n" if args.db else ""
    if args.db and args.db_extra:
        db += "".join(f"    {l}\n" for l in args.db_extra.split(","))
    inotify = "" if args.inotify else "    inotify_watcher false\n"
    advise = "" if args.advise else "    file_cache_advise false\n"
    opts = "".join(f"    {l}\n" for l in args.opt)
    http = ""
    if http_port:
        http = f"    http_server on\n    http_listen 127.0.0.1\n    http_port {http_port}\n"
    out = "    name null\n    match *\n"
    if output != "null":
        out = (f"    name file\n    match *\n    file {output}\n"
               "    format template\n    template {log}\n")
    with open(path, "w") as f:
        f.write(f"""[SERVICE]
    flush 0.2
    log_level {args.log_level}
    grace 1
    parsers_file {PARSERS}
{http}
[INPUT]
    name tail
    path {logdir}/*.log
    refresh_interval {args.refresh}
    mem_buf_limit 8G
{db}{inotify}{advise}{opts}{extra}
[OUTPUT]
{out}""")


def launch(args, conf, strace_out=None):
    cmd = [args.bin, "-c", conf]
    if strace_out:
        cmd = ["strace", "-f", "-c", "-o", strace_out] + cmd
    log = open(os.path.join(args.workdir, "flb.log"), "w")
    return subprocess.Popen(cmd, stdout=log, stderr=log)


def parse_strace(path):
    res = {}
    total = 0
    if not os.path.exists(path):
        return res, total
    for line in open(path):
        m = re.match(r"\s*[\d.]+\s+[\d.]+\s+\d+\s+(\d+)\s+(?:\d+\s+)?(\w+)$", line)
        if m and m.group(2) != "total":
            res[m.group(2)] = int(m.group(1))
            total += int(m.group(1))
    return res, total


JSON_PARSERS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "parsers.conf")

LINE = ('{{"time":"2026-11-15T10:00:00.000000Z","level":"info","seq":{seq},'
             '"status":200,"dur":1.25,"msg":"request served ' + "x" * 60 + '"}}\n')
CORPUS = "cri"


def gen_file(path, size):
    tpl = JSON_LINE if CORPUS == "json" else LINE
    block = "".join(tpl.format(seq=i) for i in range(4000)).encode()
    n = 0
    lines = 0
    with open(path, "wb") as f:
        while n < size:
            f.write(block)
            n += len(block)
            lines += 4000
    return lines


def scenario_static(args):
    logdir = os.path.join(args.workdir, "logs")
    os.makedirs(logdir)
    per = args.size * 1024 * 1024 // args.files
    lines = 0
    for i in range(args.files):
        lines += gen_file(os.path.join(logdir, f"f{i:05d}.log"), per)
    os.sync()
    conf = os.path.join(args.workdir, "flb.conf")
    port = args.port
    write_conf(conf, logdir, args, "    read_from_head true\n", http_port=port)
    st = os.path.join(args.workdir, "strace.txt") if args.strace else None
    t0 = time.monotonic()
    p = launch(args, conf, st)
    got = -1
    while True:
        time.sleep(0.02)
        got = records(port)
        if got >= lines or time.monotonic() - t0 > args.timeout:
            break
    wall = time.monotonic() - t0
    pid = p.pid
    if args.strace:
        kids = subprocess.run(["pgrep", "-P", str(pid)], capture_output=True,
                              text=True).stdout.split()
        pid = int(kids[0]) if kids else pid
    u, s = proc_cpu(pid)
    os.kill(pid, signal.SIGTERM)
    p.wait()
    sc, total = parse_strace(st) if st else ({}, 0)
    return dict(scenario="static", lines=lines, got=got, wall=round(wall, 3),
                user=u, sys=s, mb_s=round(args.size / wall, 1),
                syscalls=total, top=top(sc))


def top(sc, n=9):
    return dict(sorted(sc.items(), key=lambda kv: -kv[1])[:n])


def scenario_live(args):
    """N watched files, a paced writer appends lines to random files."""
    logdir = os.path.join(args.workdir, "logs")
    os.makedirs(logdir)
    fds = []
    for i in range(args.files):
        fds.append(os.open(os.path.join(logdir, f"f{i:05d}.log"),
                           os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644))
    conf = os.path.join(args.workdir, "flb.conf")
    port = args.port
    write_conf(conf, logdir, args, "    read_from_head true\n", http_port=port)
    st = os.path.join(args.workdir, "strace.txt") if args.strace else None
    p = launch(args, conf, st)
    pid = p.pid
    time.sleep(1.0)
    if args.strace:
        kids = subprocess.run(["pgrep", "-P", str(pid)], capture_output=True,
                              text=True).stdout.split()
        pid = int(kids[0]) if kids else pid
    # wait until all files are promoted to event mode / watched
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            m = metrics(port)["input"]["tail.0"]
            if m.get("files_opened", 0) >= args.files:
                break
        except Exception:
            pass
        time.sleep(0.2)
    time.sleep(args.settle)
    u0, s0 = proc_cpu(pid)
    rnd = random.Random(42)
    active = fds
    if args.active and args.active < len(fds):
        active = rnd.sample(fds, args.active)
    seq = 0
    t0 = time.monotonic()
    ticks = int(args.duration / args.tick)
    per_tick = max(1, int(args.rate * args.tick))
    for t in range(ticks):
        for _ in range(per_tick // args.burst):
            fd = active[rnd.randrange(len(active))]
            buf = "".join(LINE.format(seq=seq + k) for k in range(args.burst))
            os.write(fd, buf.encode())
            seq += args.burst
        nxt = t0 + (t + 1) * args.tick
        d = nxt - time.monotonic()
        if d > 0:
            time.sleep(d)
    wend = time.monotonic()
    got = -1
    while time.monotonic() - wend < args.timeout:
        got = records(port)
        if got >= seq:
            break
        time.sleep(0.05)
    drain = time.monotonic() - wend
    u1, s1 = proc_cpu(pid)
    # idle cost: CPU used while nothing is being written
    idle_u = idle_s = 0.0
    if args.idle:
        time.sleep(args.idle)
        u2, s2 = proc_cpu(pid)
        idle_u, idle_s = u2 - u1, s2 - s1
    os.kill(pid, signal.SIGTERM)
    p.wait()
    for fd in fds:
        os.close(fd)
    sc, total = parse_strace(st) if st else ({}, 0)
    return dict(scenario="live", files=args.files, lines=seq, got=got,
                write_s=round(wend - t0, 2), drain_s=round(drain, 2),
                user=round(u1 - u0, 2), sys=round(s1 - s0, 2),
                cpu_us_per_line=round((u1 - u0 + s1 - s0) * 1e6 / max(seq, 1), 2),
                idle_cpu=round(idle_u + idle_s, 2),
                syscalls=total, top=top(sc))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario", choices=["static", "live"])
    ap.add_argument("--bin", required=True)
    ap.add_argument("--base", default="/dev/shm")
    ap.add_argument("--files", type=int, default=1)
    ap.add_argument("--size", type=int, default=1024, help="MB (static)")
    ap.add_argument("--db", action="store_true")
    ap.add_argument("--db-extra", default="")
    ap.add_argument("--no-inotify", dest="inotify", action="store_false")
    ap.add_argument("--no-advise", dest="advise", action="store_false")
    ap.add_argument("--opt", action="append", default=[])
    ap.add_argument("--strace", action="store_true")
    ap.add_argument("--rate", type=int, default=20000, help="lines/s (live)")
    ap.add_argument("--burst", type=int, default=1, help="lines per write")
    ap.add_argument("--active", type=int, default=0, help="files written")
    ap.add_argument("--duration", type=float, default=10)
    ap.add_argument("--tick", type=float, default=0.01)
    ap.add_argument("--settle", type=float, default=3)
    ap.add_argument("--idle", type=float, default=0)
    ap.add_argument("--refresh", default="60")
    ap.add_argument("--timeout", type=float, default=120)
    ap.add_argument("--port", type=int, default=22020)
    ap.add_argument("--log-level", default="error")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--label", default="")
    ap.add_argument("--corpus", default="cri")
    args = ap.parse_args()
    global CORPUS
    CORPUS = args.corpus
    args.workdir = os.path.join(args.base, f"tailbench-{os.getpid()}")
    shutil.rmtree(args.workdir, ignore_errors=True)
    os.makedirs(args.workdir)
    try:
        res = scenario_static(args) if args.scenario == "static" else scenario_live(args)
    finally:
        if not args.keep:
            shutil.rmtree(args.workdir, ignore_errors=True)
    res["label"] = args.label or os.path.basename(args.bin)
    res["ok"] = res["got"] == res["lines"]
    print(json.dumps(res))


if __name__ == "__main__":
    main()
