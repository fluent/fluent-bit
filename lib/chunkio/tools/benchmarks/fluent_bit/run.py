import argparse
import http.server
import json
import os
from pathlib import Path
import signal
import resource
import socket
import subprocess
import threading
import time
import urllib.request

ROOT = Path(os.environ.get('CIO_FLB_BENCH_ROOT', '.')).resolve()
CPU = os.environ.get('CIO_FLB_BENCH_CPU', '2')

def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def dataset(name, files, records_per_file):
    target = ROOT / 'data' / name
    target.mkdir(parents=True, exist_ok=True)
    for number in range(files):
        path = target / f'{number:04d}.log'
        if path.exists() and path.stat().st_size == records_per_file * 256:
            continue
        with path.open('wb') as output:
            for record in range(records_per_file):
                prefix = f'{number * records_per_file + record:012d} '
                output.write((prefix + 'x' * (255 - len(prefix)) + '\n').encode())
    return target


CASES = {
    'steady_fs': (1, 1000000, 'filesystem', False, 128, False),
    'steady_crc': (1, 1000000, 'filesystem', True, 128, False),
    'many_tags': (1000, 64, 'filesystem', False, 128, False),
    'backpressure': (1, 250000, 'filesystem', True, 8, True),
    'memory': (1, 1000000, 'memory', False, 128, False),
    'pilot': (1, 1000, 'filesystem', True, 8, True),
}


def run(case, variant, label):
    soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (max(soft_limit, 8192), hard_limit))
    files, per_file, storage_type, checksum, max_up, blocked = CASES[case]
    expected = files * per_file
    source = dataset(case, files, per_file)
    directory = ROOT / 'runs' / f'{case}-{variant}-{label}'
    directory.mkdir(parents=True)
    storage = directory / 'storage'
    storage.mkdir()
    metrics_port = port()
    output_port = port()
    received = bytearray(expected)
    received_count = 0
    duplicate_count = 0
    rejected_requests = 0
    release = threading.Event()

    class Collector(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            nonlocal received_count, duplicate_count, rejected_requests
            data = self.rfile.read(int(self.headers['Content-Length']))
            if not release.is_set():
                rejected_requests += 1
                self.send_response(503)
            else:
                for line in data.splitlines():
                    record = json.loads(line)
                    value = record['log']
                    identity = int(value[:12])
                    assert 0 <= identity < expected
                    assert value == f'{identity:012d} ' + 'x' * 242
                    duplicate_count += received[identity]
                    received[identity] = 1
                    received_count += 1
                self.send_response(200)
            self.send_header('Content-Length', '0')
            self.end_headers()

    server = http.server.HTTPServer(('127.0.0.1', output_port), Collector) if blocked else None
    if server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    output = ('    Name http\n    Host 127.0.0.1\n'
              f'    Port {output_port}\n    Format json_lines\n'
              '    Retry_Limit no_limits\n    Workers 1\n') if blocked else '    Name null\n'
    config = f'''[SERVICE]
    Flush 1
    Grace 1
    Log_Level warn
    HTTP_Server On
    HTTP_Listen 127.0.0.1
    HTTP_Port {metrics_port}
    storage.path {storage}
    storage.sync normal
    storage.checksum {'on' if checksum else 'off'}
    storage.metrics On
    storage.max_chunks_up {max_up}
    scheduler.base 1
    scheduler.cap 2
[INPUT]
    Name tail
    Path {source}/*.log
    Tag bench.*
    Read_from_Head On
    Refresh_Interval 60
    storage.type {storage_type}
[OUTPUT]
{output}    Match *
'''
    (directory / 'fluent-bit.conf').write_text(config)
    env = dict(os.environ, BENCH_RECORDS=str(expected),
               BENCH_READY=str(directory / 'ready.json'),
               BENCH_STATS=str(directory / 'stats.json'))
    log = (directory / 'fluent-bit.log').open('w')
    started = time.monotonic()
    process = subprocess.Popen(['taskset', '-c', CPU, str(ROOT / 'bin' / f'fluent-bit-{variant}'),
                                '-c', str(directory / 'fluent-bit.conf')], env=env, stdout=log, stderr=log)
    peak_bytes = peak_blocks = peak_files = peak_down = 0
    metrics = status = None
    ready_at = None
    released_at = None
    next_metrics = 0
    error = None
    try:
        while time.monotonic() - started < 120:
            if process.poll() is not None:
                raise RuntimeError(f'exit {process.returncode}: {directory}')
            now = time.monotonic()
            entries = []
            for path in storage.glob('*/*'):
                try:
                    entries.append(path.stat())
                except FileNotFoundError:
                    pass
            peak_bytes = max(peak_bytes, sum(item.st_size for item in entries))
            peak_blocks = max(peak_blocks, sum(item.st_blocks * 512 for item in entries))
            peak_files = max(peak_files, len(entries))
            if ready_at is None and (directory / 'ready.json').exists():
                ready_at = now
            if blocked and ready_at and not release.is_set() and now - ready_at >= 3:
                release.set()
                released_at = now
            if now >= next_metrics:
                next_metrics = now + 0.1
                try:
                    with urllib.request.urlopen(f'http://127.0.0.1:{metrics_port}/api/v1/metrics', timeout=0.3) as response:
                        metrics = json.load(response)
                    with urllib.request.urlopen(f'http://127.0.0.1:{metrics_port}/api/v1/storage', timeout=0.3) as response:
                        status = json.load(response)
                    peak_down = max(peak_down, status['storage_layer']['chunks']['fs_chunks_down'])
                    outputs = metrics['output']
                    processed = sum(value['proc_records'] for value in outputs.values())
                    if processed == expected and ready_at and (not blocked or received_count == expected):
                        break
                except (OSError, ValueError, KeyError):
                    pass
            time.sleep(0.02)
        else:
            raise RuntimeError(f'timeout: {directory}; metrics={metrics}; received={received_count}')
        completed = time.monotonic()
        assert sum(value['records'] for key, value in metrics['input'].items() if key.startswith('tail')) == expected, metrics
        assert all(value.get('dropped_records', 0) == 0 and value.get('retries_failed', 0) == 0 for value in metrics['output'].values()), metrics
        if blocked:
            assert sum(received) == expected and duplicate_count == 0
            assert rejected_requests > 0
            if case != 'pilot':
                assert peak_down > 0, status
    except BaseException as caught:
        error = caught
    finally:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        log.close()
        if server:
            server.shutdown()
            server.server_close()
    if error:
        raise error
    assert process.returncode == 0, process.returncode
    result = dict(case=case, variant=variant, label=label, records=expected,
                  source_bytes=expected * 256, observed_completion_seconds=completed-started,
                  peak_file_bytes=peak_bytes, peak_allocated_bytes=peak_blocks,
                  peak_files=peak_files, peak_down=peak_down, metrics=metrics,
                  received_records=received_count, duplicates=duplicate_count,
                  rejected_requests=rejected_requests,
                  recovery_seconds=completed-released_at if released_at else None)
    result.update(json.loads((directory / 'ready.json').read_text()))
    result.update(json.loads((directory / 'stats.json').read_text()))
    result['ingest_mib_per_second'] = expected * 256 / 1048576 / result['ingest_seconds']
    (directory / 'result.json').write_text(json.dumps(result, indent=2))
    print(json.dumps({key: value for key, value in result.items() if key != 'metrics'}), flush=True)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--case', default='pilot')
    parser.add_argument('--variant', default='base')
    parser.add_argument('--label', default='pilot')
    args = parser.parse_args()
    run(args.case, args.variant, args.label)
