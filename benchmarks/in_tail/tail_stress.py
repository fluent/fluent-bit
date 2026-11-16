#!/usr/bin/env python3
"""Correctness stress for in_tail: many files written while they are rotated
(rename + create), copy-truncated, deleted and re-created. Every line carries
a unique id; the run passes when every id is delivered at least once.
Duplicates are reported per operation (copytruncate is at-least-once by
nature)."""
import argparse, json, os, random, shutil, signal, subprocess, sys, time
import urllib.request


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--base", default="/dev/shm")
    ap.add_argument("--files", type=int, default=200)
    ap.add_argument("--duration", type=float, default=20)
    ap.add_argument("--rate", type=int, default=20000)
    ap.add_argument("--ops", default="rotate,copytruncate,delete")
    ap.add_argument("--op-rate", type=float, default=20, help="ops/s")
    ap.add_argument("--no-inotify", dest="inotify", action="store_false")
    ap.add_argument("--db", action="store_true")
    ap.add_argument("--opt", action="append", default=[])
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--port", type=int, default=22030)
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()

    wd = os.path.join(args.base, f"tailstress-{os.getpid()}")
    shutil.rmtree(wd, ignore_errors=True)
    logs = os.path.join(wd, "logs")
    os.makedirs(logs)
    out = os.path.join(wd, "out.txt")
    opts = "".join(f"    {o}\n" for o in args.opt)
    if not args.inotify:
        opts += "    inotify_watcher false\n"
    if args.db:
        opts += f"    db {wd}/tail.db\n"
    conf = os.path.join(wd, "flb.conf")
    open(conf, "w").write(f"""[SERVICE]
    flush 0.2
    grace 2
    log_level warn
    http_server on
    http_listen 127.0.0.1
    http_port {args.port}
[INPUT]
    name tail
    path {logs}/*.log
    read_from_head true
    refresh_interval 1
    rotate_wait 3
    mem_buf_limit 1G
{opts}
[OUTPUT]
    name file
    match *
    file {out}
    format template
    template {{log}}
""")
    rnd = random.Random(args.seed)
    paths = [os.path.join(logs, f"f{i:04d}.log") for i in range(args.files)]
    fds = [os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644) for p in paths]
    flb_log = open(os.path.join(wd, "flb.log"), "w")
    p = subprocess.Popen([args.bin, "-c", conf], stdout=flb_log, stderr=flb_log)
    time.sleep(2)

    ops = [o for o in args.ops.split(",") if o]
    written = {}          # id -> last op applied to the file before the write
    last_op = ["none"] * args.files
    gen = [0] * args.files
    counts = {o: 0 for o in ops}
    seq = 0
    tick = 0.01
    t0 = time.monotonic()
    nticks = int(args.duration / tick)
    per_tick = max(1, int(args.rate * tick))
    op_acc = 0.0
    for t in range(nticks):
        for _ in range(per_tick):
            i = rnd.randrange(args.files)
            line = f"id={seq:010d} f={i} " + "x" * rnd.randrange(20, 160) + "\n"
            os.write(fds[i], line.encode())
            written[seq] = last_op[i]
            seq += 1
        op_acc += args.op_rate * tick
        while ops and op_acc >= 1:
            op_acc -= 1
            i = rnd.randrange(args.files)
            op = rnd.choice(ops)
            counts[op] += 1
            if op == "rotate":
                gen[i] += 1
                os.rename(paths[i], paths[i] + f".{gen[i]}")
                # the writer keeps the old descriptor for a while, like an
                # application that reopens its log later
                old = fds[i]
                fds[i] = os.open(paths[i], os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
                os.write(old, f"id={seq:010d} f={i} late-write-after-rotate\n".encode())
                written[seq] = "rotate-late"
                seq += 1
                os.close(old)
            elif op == "copytruncate":
                # give the reader the chance to consume, then truncate
                shutil.copyfile(paths[i], paths[i] + ".copy")
                os.truncate(paths[i], 0)
            elif op == "delete":
                os.close(fds[i])
                os.unlink(paths[i])
                fds[i] = os.open(paths[i], os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
            last_op[i] = op
        d = t0 + (t + 1) * tick - time.monotonic()
        if d > 0:
            time.sleep(d)

    # let everything drain
    time.sleep(8)
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(timeout=30)
    except subprocess.TimeoutExpired:
        p.kill()
    seen = {}
    if os.path.exists(out):
        with open(out, errors="replace") as f:
            for line in f:
                if line.startswith("id="):
                    try:
                        k = int(line[3:13])
                    except ValueError:
                        continue
                    seen[k] = seen.get(k, 0) + 1
    missing = [k for k in written if k not in seen]
    miss_by = {}
    for k in missing:
        miss_by[written[k]] = miss_by.get(written[k], 0) + 1
    dups = sum(v - 1 for v in seen.values() if v > 1)
    flb_log.close()
    errs = sum(1 for l in open(os.path.join(wd, "flb.log")) if "[error]" in l)
    res = dict(bin=os.path.basename(args.bin), inotify=args.inotify, db=args.db,
               ops=counts, written=len(written), delivered=len(seen),
               missing=len(missing), missing_by_last_op=miss_by,
               duplicates=dups, errors_logged=errs, rc=p.returncode)
    print(json.dumps(res))
    if not args.keep:
        shutil.rmtree(wd, ignore_errors=True)


if __name__ == "__main__":
    main()
