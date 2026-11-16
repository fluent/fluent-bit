# in_tail benchmarks

Tools to measure and to verify `plugins/in_tail`. They drive a Fluent Bit
binary as a separate process, so two builds can be compared on the same
workload. Use release builds (`-DFLB_RELEASE=On`), the default build has no
compiler optimizations.

| Tool | Purpose |
| --- | --- |
| `tail_bench.py static` | CPU and wall time to read files that already exist |
| `tail_bench.py live` | CPU per line while a paced writer appends to N monitored files, plus the CPU used once the writer stops |
| `tail_stress.py` | delivery check (by unique line id) while files are rotated, copy-truncated and deleted |
| `tail_encoding_diff.py` | byte level comparison of the records two binaries generate for the same corpus |
| `tail_cri_diff.py` | byte level comparison, timestamps included, of the records two binaries generate for a corpus of valid, partial and malformed CRI lines |

Every benchmark run checks that the number of ingested records matches the
number of lines written and reports it as `"ok"`.

```shell
# 2GB static file on tmpfs, then on a real file system and with a database
./tail_bench.py static --bin build/bin/fluent-bit --size 2048
./tail_bench.py static --bin build/bin/fluent-bit --size 2048 --base /var/tmp
./tail_bench.py static --bin build/bin/fluent-bit --size 2048 --db

# parser and multiline paths
./tail_bench.py static --bin build/bin/fluent-bit --size 1024 \
    --corpus json --opt "parser json"
./tail_bench.py static --bin build/bin/fluent-bit --size 512 \
    --opt "multiline.parser cri" --opt "path_key file"

# 20k lines/s across 10000 files, then 6 seconds of idle time
./tail_bench.py live --bin build/bin/fluent-bit --files 10000 --idle 6

# system calls (strace -f -c)
./tail_bench.py static --bin build/bin/fluent-bit --size 256 --strace

# correctness
./tail_stress.py --bin build/bin/fluent-bit --ops rotate --db
./tail_encoding_diff.py /path/to/reference/fluent-bit build/bin/fluent-bit
```

`tail_encoding_diff.py` and `tail_cri_diff.py` require the `msgpack` Python
module, `--strace` requires `strace`.

## Results: event mode, read path and serialization changes

Measured on Linux 7.0 (x86_64, 16 cores, NVMe + ext4, tmpfs for `/dev/shm`),
release builds, CPU time is user + system of the whole process. "Before" is
the commit the series is based on.

### Live appends (20k lines/s, one line per write)

CPU per ingested line, and CPU used during 6 seconds without writes right
after the burst:

| Monitored files | Before | After | Idle before | Idle after |
| --- | --- | --- | --- | --- |
| 100 | 54.6 us | 7.2 us | 0.20 s | 0.01 s |
| 1000 | 56.1 us | 8.3 us | 6.0 s | 0.04 s |
| 5000 | 55.6 us | 9.2 us | 6.0 s | 0.11 s |
| 10000 | 55.3 us | 10.1 us | 6.0 s | 0.20 s |
| 5000, `inotify_watcher off` | 39.6 us | 4.3 us | 4.1 s | 0.23 s |
| 5000, with `db` | 55.4 us | 11.9 us | 6.0 s | 0.12 s |
| 1000, 100k lines/s | 11.1 us | 1.5 us | 4.0 s | 0.02 s |
| 20 busy of 2000, 200k lines/s | 5.6 us | 0.6 us | 4.0 s | 0.02 s |

Before, the process was saturating one core in every row: the event queue was
not drained while the writers were active, and it kept the core busy after
they stopped.

### Static files (CPU seconds for the whole run)

| Workload | Before | After | Ratio |
| --- | --- | --- | --- |
| 2GB, tmpfs | 2.80 | 1.48 | 1.9x |
| 2GB, ext4 (`file_cache_advise` default) | 7.96 | 1.53 | 5.2x |
| 2GB, ext4, `file_cache_advise off` | 2.87 | 1.45 | 2.0x |
| 2GB, tmpfs, `db` | 3.31 | 1.94 | 1.7x |
| 2GB, `path_key` + `offset_key` | 3.81 | 2.06 | 1.8x |
| 2GB in 2000 files | 4.49 | 2.82 | 1.6x |
| 2GB in 2000 files, `db` | 5.36 | 2.91 | 1.8x |
| 1GB, `parser json` | 6.15 | 3.95 | 1.6x |
| 1GB, `parser json` + keys | 6.70 | 4.23 | 1.6x |
| 512MB, `multiline.parser cri` | 7.23 | 6.56 | 1.1x |
| 512MB, `multiline.parser cri` + keys | 9.67 | 7.67 | 1.3x |

### Other measurements

| Measurement | Before | After |
| --- | --- | --- |
| System calls to read a 256MB file | 70345 | 28878 |
| Instructions per record, plain line (callgrind) | 2753 | 930 |
| Instructions per record, `parser json` | 17503 | 11844 |
| Instructions per record, `multiline.parser cri` | 35600 | 34403 |
| Startup with 20000 files and `db`, first start | 5.2 s | 1.4 s |
| Startup with 20000 files and `db`, restart | 4.9 s | 1.0 s |

The `multiline.parser cri` path is dominated by the regular expression of the
core multiline engine (more than half of the instructions), which is outside
of this plugin.

### Verification

- `tail_encoding_diff.py`: identical output in the 13 configurations it covers.
- Persisted offsets and offset markers: identical database rows for a mixed
  corpus (partial lines, skipped long lines, gzip, empty files).
- `tail_stress.py --ops rotate`, 300k lines over 200 files with 300 rotations:
  no missing and no duplicated lines with inotify, with and without database,
  before and after. With `inotify_watcher off` both versions miss the same
  lines: a file rotated twice within one polling interval is never seen under
  a name that matches the path.

## Results: native decoder for `multiline.parser cri`

Same environment. "Before" is the series without the native decoder, which
uses a regular expression for every line.

Static files with CRI lines (512MB, 3.4M lines of 148 bytes):

| Configuration | CPU before | CPU after | Throughput before | Throughput after |
| --- | --- | --- | --- | --- |
| `multiline.parser cri` | 6.56 s | 0.50 s | 76 MB/s | ~700 MB/s |
| + `path_key`, `offset_key` | 7.67 s | 0.70 s | 66 MB/s | ~690 MB/s |
| `multiline.parser docker, cri` | 6.60 s | 0.52 s | 73 MB/s | ~890 MB/s |
| 2000 files (8M lines) | 29.5 s | 1.71 s | 17.5 MB/s | ~214 MB/s |

Instructions per line (callgrind, 300k lines): 34,400 before, 1,515 after;
with `path_key` and `offset_key` 38,900 before, 2,356 after.

Live appends, 20k lines/s, CPU per line:

| Monitored files | Before | After |
| --- | --- | --- |
| 500 | 10.8 us | 8.3 us |
| 5000 | 21.3 us | 9.8 us |

```shell
./tail_cri_diff.py /path/to/reference/fluent-bit build/bin/fluent-bit
```
