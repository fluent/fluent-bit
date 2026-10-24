"""File format framing regressions using dummy and binary Forward records."""
import csv
import io
import json
import os
from pathlib import Path
import socket
import time

import pytest

from utils.fluent_bit_manager import FluentBitManager
from utils.memory_check import memory_check_enabled


def file_output(tmp_path, record, format_name, options=None, forward_message=None):
    root = Path(__file__).resolve().parents[5]
    binary = os.environ.get('FLUENT_BIT_BINARY', str(root / 'build/bin/fluent-bit'))
    if os.name == 'nt' and not binary.endswith('.exe'):
        binary += '.exe'
    config = tmp_path / 'file.yaml'
    target = tmp_path / 'output.log'
    output = {'name': 'file', 'match': '*', 'format': format_name,
              'path': tmp_path.as_posix(), 'file': target.name}
    output.update(options or {})
    input_config = {'name': 'dummy', 'samples': 1, 'dummy': json.dumps(record)}
    if forward_message is not None:
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        input_config = {'name': 'forward', 'listen': '127.0.0.1', 'port': port}
    # JSON is also valid YAML, including escaped control bytes in dummy data.
    config.write_text(json.dumps({'service': {'flush': 0.1, 'grace': 1},
        'pipeline': {'inputs': [input_config], 'outputs': [output]}}))
    manager = FluentBitManager(str(config), binary_path=binary)
    try:
        # This scenario waits for its output file instead of an HTTP health endpoint.
        manager.start(wait_for_ready=False)
        deadline = time.monotonic() + (30 if memory_check_enabled() else 8)
        while time.monotonic() < deadline:
            if forward_message is not None:
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.1) as connection:
                        connection.sendall(forward_message)
                    forward_message = None
                except ConnectionRefusedError:
                    time.sleep(0.05)
                    continue
            if target.exists() and target.stat().st_size:
                return target.read_bytes().decode('utf-8')
            if manager.process.poll() is not None:
                pytest.fail(Path(manager.log_file).read_text())
            time.sleep(0.05)
        pytest.fail('Timed out waiting for file output')
    finally:
        manager.stop()


@pytest.mark.parametrize('delimiter,configured', [(',', 'comma'), ('\t', 'tab'), (' ', 'space')])
@pytest.mark.parametrize('dynamic', [False, True])
def test_csv_escaping(tmp_path, delimiter, configured, dynamic):
    key = 'key,"\r\nnext\tfield'
    value = 'value,"\r\nforged\tfield'
    record = {key: value, 'nested': ['a,"\nrow', {'b': 'c"'}], 'empty': '', 'number': 42, 'large': 1e200}
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


@pytest.mark.parametrize('delimiter,configured,label,label_config', [
    ('\t', 'tab', ':', 'colon'), (' ', 'space', ',', 'comma'),
    (',', 'comma', ':', 'colon')])
@pytest.mark.parametrize('dynamic', [False, True])
def test_ltsv_escaping(tmp_path, delimiter, configured, label, label_config, dynamic):
    key = 'key\t:\r\n, =%'
    value = 'value\t:\r\nforged, =%0A'
    record = {key: value, 'nested': ['one\ntwo', {'tab\t': 'x:y,z'}], 'empty': '', 'number': 42, 'large': 1e200}
    options = {'delimiter': configured, 'label_delimiter': label_config}
    if dynamic:
        record['destination'] = 'output'
        options.update({'file': '$destination.log', 'fallback_path': tmp_path.as_posix(),
                        'fallback_file': 'fallback.log'})
    text = file_output(tmp_path, record, 'ltsv', options)
    assert len(text.splitlines()) == 1
    fields = text.rstrip('\r\n').split(delimiter)
    assert len(fields) == len(record) + 1
    assert all(len(field.split(label)) == 2 for field in fields)
    def escape(value):
        return ''.join('%%%02X' % ord(c) if ord(c) < 32 or ord(c) == 127 or
                       c in '%' + delimiter + label else c for c in value)
    assert fields[1] == '"' + escape(key) + '"' + label + '"' + escape(value) + '"'
    assert '%0A' in fields[2] and '%09' in fields[2]
    assert fields[3] == '"empty"' + label + '""'
    assert fields[4] == '"number"' + label + '42'
    assert float(fields[5].split(label)[1]) == 1e200


@pytest.mark.parametrize('format_name', ['csv', 'ltsv'])
@pytest.mark.parametrize('dynamic', [False, True])
def test_binary_escaping(tmp_path, format_name, dynamic):
    value = bytes(range(256))
    # Forward Message mode: ["test", 1, {binary: binary, "nested": [binary]}].
    binary = b'\xc5' + len(value).to_bytes(2, 'big') + value
    body = b'\x82' + binary + binary + b'\xa6nested\x91' + binary
    options = {'csv_column_names': True} if format_name == 'csv' else {}
    if dynamic:
        body = b'\x83' + body[1:] + b'\xabdestination\xa6output'
        options.update({'file': '$destination.log', 'fallback_path': tmp_path.as_posix(),
                        'fallback_file': 'output.log'})
    text = file_output(tmp_path, None, format_name, options,
                       forward_message=b'\x93\xa4test\x01' + body)
    if format_name == 'csv':
        escaped = ''.join(chr(c) if 32 <= c < 127 else r'\x%02x' % c for c in value)
        rows = list(csv.reader(io.StringIO(text, newline=''), strict=True))
        assert len(rows) == 2
        assert rows[0][1] == escaped
        assert rows[1][1] == escaped
        assert rows[1][2] == '["' + escaped + '"]'
    else:
        escaped = ''.join('%%%02X' % c if c < 32 or c >= 127 or chr(c) in '%\t:'
                          else chr(c) for c in value)
        fields = text.rstrip('\r\n').split('\t')
        assert len(fields) == (4 if dynamic else 3)
        assert fields[1] == '"' + escaped + '":"' + escaped + '"'
        assert fields[2] == '"nested":["' + escaped + '"]'
