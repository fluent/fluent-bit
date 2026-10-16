"""File format framing regressions using the dummy input."""
import csv
import io
import json
import os
from pathlib import Path
import subprocess
import time

import pytest


def file_output(tmp_path, record, format_name, options=None):
    root = Path(__file__).resolve().parents[5]
    binary = os.environ.get('FLUENT_BIT_BINARY', str(root / 'build/bin/fluent-bit'))
    if os.name == 'nt' and not binary.endswith('.exe'):
        binary += '.exe'
    config = tmp_path / 'file.yaml'
    target = tmp_path / 'output.log'
    output = {'name': 'file', 'match': '*', 'format': format_name,
              'path': tmp_path.as_posix(), 'file': target.name}
    output.update(options or {})
    # JSON is also valid YAML, including escaped control bytes in dummy data.
    config.write_text(json.dumps({'service': {'flush': 0.1, 'grace': 1},
        'pipeline': {'inputs': [{'name': 'dummy', 'samples': 1,
                                'dummy': json.dumps(record)}], 'outputs': [output]}}))
    with (tmp_path / 'stderr').open('w+') as log:
        command = [binary, '-c', str(config)]
        if os.environ.get('VALGRIND') or os.environ.get('LEAKS'):
            pytest.fail('Memory-checker execution requires a supported process wrapper')
        process = subprocess.Popen(command, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                if target.exists() and target.stat().st_size:
                    return target.read_bytes().decode('utf-8')
                if process.poll() is not None:
                    log.seek(0)
                    pytest.fail(log.read())
                time.sleep(0.05)
            pytest.fail('Timed out waiting for file output')
        finally:
            process.terminate()
            process.wait(timeout=10)


@pytest.mark.parametrize('delimiter,configured', [(',', 'comma'), ('\t', 'tab'), (' ', 'space')])
@pytest.mark.parametrize('dynamic', [False, True])
def test_csv_escaping(tmp_path, delimiter, configured, dynamic):
    key = 'key,"\r\nnext\tfield'
    value = 'value,"\r\nforged\tfield'
    record = {key: value, 'nested': ['a,"\nrow', {'b': 'c"'}], 'empty': '', 'number': 42}
    options = {'delimiter': configured, 'csv_column_names': True}
    if dynamic:
        record['destination'] = 'output'
        options.update({'file': '$destination.log',
                        'fallback_path': tmp_path.as_posix(), 'fallback_file': 'fallback.log'})
    text = file_output(tmp_path, record, 'csv', options)
    rows = list(csv.reader(io.StringIO(text, newline=''), delimiter=delimiter, strict=True))
    assert len(rows) == 2
    normalize = lambda s: s.replace('\r\r\n', '\r\n').replace('\r\n', '\n')
    assert list(map(normalize, rows[0])) == ['timestamp'] + list(map(normalize, record))
    assert len(rows[1]) == len(rows[0])
    # Windows text streams translate LF to CRLF, including inside quoted fields.
    normalize = lambda s: s.replace('\r\r\n', '\r\n').replace('\r\n', '\n')
    assert normalize(rows[1][1]) == normalize(value)
    assert 'forged' in rows[1][1]
    assert 'a,' in rows[1][2] and 'c"' in rows[1][2]
    assert rows[1][3:5] == ['', '42']
