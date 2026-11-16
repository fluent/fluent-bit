#!/usr/bin/env python3
"""Differential check for the CRI multiline path: two binaries must produce
the same raw msgpack, timestamps included, for a corpus made of valid lines,
partial sequences and malformed variations of the layout. Records stamped
with the current time (lines without a usable timestamp) get their timestamp
masked.

usage: tail_cri_diff.py REFERENCE_BINARY NEW_BINARY [LINES]

Set CRI_VALID_TIMES=1 to leave out the lines with a timestamp that cannot be
used for a record."""
import os, random, struct, subprocess, sys, tempfile, time
import msgpack


def corpus(rnd, n, weird=True):
    out = []
    streams = [b"stdout", b"stderr"]

    def ts():
        y = rnd.choice([1970, 1999, 2000, 2016, 2020, 2024, 2025])
        mo = rnd.randrange(1, 13)
        d = rnd.randrange(1, 29 if rnd.random() < 0.8 else 32)
        frac = "".join(rnd.choice("0123456789") for _ in range(rnd.choice([1, 2, 3, 6, 9, 9, 9, 9])))
        tz = rnd.choice(["Z", "Z", "Z", "+00:00", "-07:00", "+05:30", "+14:00", "-00:30"])
        return ("%04d-%02d-%02dT%02d:%02d:%02d.%s%s" % (
            y, mo, d, rnd.randrange(24), rnd.randrange(60), rnd.randrange(60), frac, tz)).encode()

    weird_times = [
        b"2020-01-02T03:04:05Z", b"2020-01-02T03:04:05.Z", b"2020-01-02T03:04:05.1234567890Z",
        b"2020-01-02T03:04:05.123z", b"2020-01-02T03:04:60.5Z", b"2020-02-31T03:04:05.5Z",
        b"1969-12-31T23:59:59.5Z", b"0001-01-01T00:00:00.5Z", b"9999-12-31T23:59:59.999999999Z",
        b"2020-01-02T03:04:05.5+0200", b"2020-01-02T03:04:05.5+02", b"2020-01-02T03:04:05.5 +02:00",
        b"2020-01-02T03:04:05.5Zjunk", b"2020-1-2T3:4:5.5Z", b"2020-01-02 03:04:05.5Z",
        b"garbage", b"a b c", b"2020-13-02T03:04:05.5Z", b"2020-01-02T25:04:05.5Z",
        b"2020-01-02T03:04:05.5+99:99", b"2020-01-02T03:04:05,5Z", b"2020-01-02T03:04:05.1e2Z",
        b"2020-01-02T03:04:05.5UTC", b"2020-01-02T03:04:05.5GMT", b"2020-01-02T03:04:05.5EST",
        b"2020-01-02T03:04:05.5-08:00", b"x" * 70, b"2020-01-02T03:04:05." + b"1" * 60 + b"Z",
        b"\xe4\xb8\xad\xe6\x96\x87", b"\xff\xfe", b"2020-01-02T03:04:05.000000000Z",
        b"2020-01-02T03:04:05.999999999+23:59", b"2020-01-02T03:04:05.5-", b"2020-01-02T03:04:05.5+0",
        b"2020-01-02T03:04:05.5+1:00", b" ", b"  ", b"1970-01-01T00:00:00.0Z", b"1970-01-01T00:00:00.000000001Z",
    ]
    for i in range(n):
        k = rnd.randrange(40)
        if not weird and k in (18, 19, 27, 38):
            k = 0
        body = b"msg %d " % i + b"x" * rnd.randrange(120)
        if k < 14:
            out.append(ts() + b" " + rnd.choice(streams) + b" F " + body)
        elif k < 18:
            # partial sequence, sometimes interleaved with the other stream
            s = rnd.choice(streams)
            for j in range(rnd.randrange(1, 4)):
                out.append(ts() + b" " + s + b" P " + b"part%d-%d " % (i, j))
                if rnd.random() < 0.3:
                    o = streams[1 - streams.index(s)]
                    out.append(ts() + b" " + o + b" " + rnd.choice([b"F", b"P"]) + b" other %d" % i)
            if rnd.random() < 0.9:
                out.append(ts() + b" " + s + b" F " + b"end%d" % i)
        elif k == 18:
            out.append(rnd.choice(weird_times) + b" " + rnd.choice(streams) + b" " + rnd.choice([b"F", b"P"]) + b" " + body)
        elif k == 19:
            out.append(rnd.choice(weird_times) + b" stdout F " + body)
        elif k == 20:
            out.append(b"plain text line %d without the layout" % i)
        elif k == 21:
            out.append(ts() + b" stdout F")              # no log delimiter
        elif k == 22:
            out.append(ts() + b" stdout F ")             # empty log
        elif k == 23:
            out.append(ts() + b" stdxxx F " + body)
        elif k == 24:
            out.append(ts() + b" stdout X " + body)
        elif k == 25:
            out.append(b" stdout F " + body)             # empty time
        elif k == 26:
            out.append(ts() + b" stdout F " + b"inner stderr P text stdout F " + body)
        elif k == 27:
            out.append(b"first second stdout F third stderr P " + body)
        elif k == 28:
            out.append(ts() + b" stderr F " + bytes(rnd.randrange(1, 256) if rnd.random() < .9 else 0 for _ in range(rnd.randrange(1, 80))).replace(b"\n", b"?"))
        elif k == 29:
            out.append(ts() + b" stdout F " + ("utf8 áé中文 %d" % i).encode() + rnd.choice([b"", b"\xe4", b"\xe4\xb8", b"\xf0\x9f", b"\xc3"]))
        elif k == 30:
            out.append(ts() + b" stdout F " + b"y" * rnd.choice([31, 32, 255, 256, 65535, 65536, 70000]))
        elif k == 31:
            out.append(ts() + b" stdout F crlf %d\r" % i)
        elif k == 32:
            out.append(b"")
        elif k == 33:
            out.append(ts() + b"  stdout F double space")
        elif k == 34:
            out.append(ts() + b" stdout  F double space")
        elif k == 35:
            out.append(ts() + b" stdout P " + b"q" * rnd.choice([10, 3000, 70000]))
        elif k == 36:
            out.append(b'{"log":"docker msg %d\\n","stream":"stderr","time":"2020-11-15T10:00:00.%06dZ"}' % (i, i))
        elif k == 37:
            out.append(ts() + b"\tstdout F tab")
        elif k == 38:
            out.append(b"\xe4 stdout F after lone lead byte")
        else:
            out.append(ts() + b" STDOUT F upper")
    return b"\n".join(out) + b"\n"


def run(binary, logfile, outdir, extra, service=""):
    conf = os.path.join(outdir, "flb.conf")
    open(conf, "w").write(f"""[SERVICE]
    flush 0.2
    log_level error
    grace 1
{service}
[INPUT]
    name tail
    path {logfile}
    read_from_head true
    exit_on_eof true
    buffer_chunk_size 32k
    buffer_max_size 512k
{extra}
[OUTPUT]
    name file
    match *
    path {outdir}
    file out.mp
    format msgpack
""")
    now = time.time()
    r = subprocess.run([binary, "-c", conf], stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=300)
    path = os.path.join(outdir, "out.mp")
    if not os.path.exists(path):
        print("NO OUTPUT from", binary, "rc", r.returncode, r.stdout.decode()[-800:])
        sys.exit(2)
    data = open(path, "rb").read()
    out = bytearray(data)
    up = msgpack.Unpacker(raw=True, max_buffer_size=0)
    up.feed(data)
    pos = n = masked = 0
    for _ in up:
        assert data[pos:pos + 4] == b"\x92\x92\xd7\x00", data[pos:pos + 4]
        sec = struct.unpack(">I", data[pos + 4:pos + 8])[0]
        if abs(sec - now) < 600:
            out[pos + 4:pos + 12] = b"\0" * 8
            masked += 1
        pos = up.tell()
        n += 1
    assert pos == len(data)
    return bytes(out), n, masked


def main():
    base, new = sys.argv[1], sys.argv[2]
    lines = int(sys.argv[3]) if len(sys.argv) > 3 else 60000
    weird = os.environ.get('CRI_VALID_TIMES') is None
    ok = True
    with tempfile.TemporaryDirectory(dir="/dev/shm") as d:
        for seed in (1, 2, 3):
            logfile = os.path.join(d, f"in{seed}.log")
            open(logfile, "wb").write(corpus(random.Random(seed), lines, weird))
            for name, extra, service in [
                    ("cri", "    multiline.parser cri\n", ""),
                    ("cri-keys", "    multiline.parser cri\n    path_key file\n    offset_key off\n", ""),
                    ("docker,cri", "    multiline.parser docker, cri\n", ""),
                    ("cri,docker", "    multiline.parser cri, docker\n    path_key file\n", ""),
                    ("cri-limit", "    multiline.parser cri\n", "    multiline_buffer_limit 2k\n"),
                    ("cri-limit-keys", "    multiline.parser cri\n    offset_key off\n", "    multiline_buffer_limit 100\n"),
                    ("cri-skip-long", "    multiline.parser cri\n    skip_long_lines on\n", ""),
                    ]:
                res = []
                for b in (base, new):
                    o = os.path.join(d, f"{seed}-{name}-{os.path.basename(b)}".replace(",", "_"))
                    os.makedirs(o)
                    res.append(run(b, logfile, o, extra, service))
                same = res[0][0] == res[1][0] and res[0][2] == res[1][2]
                ok &= same
                print(f"seed={seed} {name:15s} records={res[0][1]}/{res[1][1]} "
                      f"bytes={len(res[0][0])}/{len(res[1][0])} now-stamped={res[0][2]}/{res[1][2]} identical={same}")
    sys.exit(0 if ok else 1)


main()
