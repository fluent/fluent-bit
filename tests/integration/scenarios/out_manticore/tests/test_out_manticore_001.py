#!/usr/bin/env python3

import json
import os
import signal
import socket
import subprocess
import tempfile
import threading
import time

import pytest

from utils.fluent_bit_manager import FluentBitManager


pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="Manticore single_chunk is not supported on Windows"
)


CONFIG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../config"))


def config_command(fluent_bit, config_file):
    return [fluent_bit, "-c", os.path.join(CONFIG_DIR, config_file)]


def config_environment(**values):
    environment = os.environ.copy()
    environment.update({key: str(value) for key, value in values.items()})
    return environment


def read_request(connection):
    stream = connection.makefile("rb")
    request_line = stream.readline().decode().strip()
    headers = {}

    while True:
        line = stream.readline()
        if line in (b"\r\n", b"\n", b""):
            break
        key, value = line.decode().split(":", 1)
        headers[key.lower()] = value.strip()

    chunks = []
    while True:
        size_line = stream.readline().strip()
        size = int(size_line.split(b";", 1)[0], 16)
        if size == 0:
            stream.readline()
            break
        chunks.append(stream.read(size))
        if stream.read(2) != b"\r\n":
            raise AssertionError("invalid HTTP chunk terminator")

    return request_line, headers, chunks


def send_response(connection, body, status="200 OK"):
    response = (
        "HTTP/1.1 {}\r\n".format(status).encode()
        +
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: close\r\n\r\n" + body
    )
    connection.sendall(response)
    connection.close()


def capture_request(listener, result):
    connection, _ = listener.accept()
    request_line, headers, chunks = read_request(connection)
    result.update(
        request_line=request_line,
        headers=headers,
        chunks=chunks,
    )

    body = (
        b'{"items":[{"bulk":{"created":20,"status":201}}],'
        b'"current_line":20,"skipped_lines":0,"errors": false,"error":""}'
    )
    send_response(connection, body)
    listener.close()


def capture_retry(listener, result):
    responses = [
        b'{"items":[{"bulk":{"status":503}}],"errors":true}',
        b'{"items":[{"bulk":{"status":201}}],"errors":false}',
    ]
    result["requests"] = []

    for body in responses:
        connection, _ = listener.accept()
        result["requests"].append(read_request(connection))
        send_response(connection, body)

    listener.close()


def capture_permanent_server_error(listener, result):
    connection, _ = listener.accept()
    result["request"] = read_request(connection)
    body = b'{"items":[{"insert":{"status":409}}],"errors":true}'
    send_response(connection, body, status="500 Internal Server Error")
    listener.close()


def stop_process(process, delay=2):
    time.sleep(delay)
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
    try:
        output, _ = process.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        output, _ = process.communicate()
        raise AssertionError("Fluent Bit did not stop\n{}".format(output))
    return output


def assert_rejected_before_connect(fluent_bit, payload, expected, copies=None):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(0.5)
    port = listener.getsockname()[1]

    command = [
        fluent_bit,
        "-f", "0.2",
        "-i", "dummy",
        "-p", "dummy={}".format(json.dumps(payload, separators=(",", ":"))),
        "-p", "samples=1",
    ]
    if copies is not None:
        command.extend(["-p", "copies={}".format(copies)])
    command.extend([
        "-o", "manticore",
        "-p", "host=127.0.0.1",
        "-p", "port={}".format(port),
        "-p", "table=wire_logs",
        "-m", "*",
    ])

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
    )
    time.sleep(2)
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
    output, _ = process.communicate(timeout=15)

    connected = False
    try:
        connection, _ = listener.accept()
        connection.close()
        connected = True
    except socket.timeout:
        pass
    listener.close()

    assert not connected
    assert expected in output
    assert "retry in" not in output


def test_out_manticore_chunked_and_recovery():
    fluent_bit = FluentBitManager().binary_absolute_path
    result = {}
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    server = threading.Thread(
        target=capture_request,
        args=(listener, result),
        daemon=True,
    )
    server.start()

    fixture_dir = tempfile.TemporaryDirectory()
    input_path = os.path.join(fixture_dir.name, "records.json")
    parsers_path = os.path.join(fixture_dir.name, "parsers.conf")
    with open(input_path, "w") as stream:
        for document_id in range(1, 21):
            stream.write(json.dumps({
                "id": document_id,
                "message": "wire-test",
                "status": 200,
            }) + "\n")
    with open(parsers_path, "w") as stream:
        stream.write("[PARSER]\n    Name manticore_json\n    Format json\n")

    command = config_command(fluent_bit, "out_manticore_wire.yaml")
    environment = config_environment(
        MANTICORE_INPUT_PATH=input_path,
        MANTICORE_PARSERS_FILE=parsers_path,
        MANTICORE_PORT=port,
    )
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        env=environment,
    )

    server.join(20)
    time.sleep(0.2)
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)

    try:
        output, _ = process.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        output, _ = process.communicate()
        raise AssertionError("Fluent Bit did not stop\n{}".format(output))

    if server.is_alive():
        raise AssertionError("no request received\n{}".format(output))
    if process.returncode != 0:
        raise AssertionError("Fluent Bit exited {}\n{}".format(
            process.returncode, output))

    headers = result["headers"]
    chunks = result["chunks"]
    records = [json.loads(line) for line in b"".join(chunks).splitlines()]

    assert result["request_line"] == (
        "POST /bulk?bulk_import=wire%20logs HTTP/1.1"
    )
    assert headers.get("transfer-encoding") == "chunked"
    assert headers.get("connection") == "close"
    assert "content-length" not in headers
    assert len(chunks) > 1
    assert len(records) == 20
    assert records == [
        {
            "insert": {
                "table": "wire logs",
                "id": document_id,
                "doc": {"message": "wire-test", "status": 200},
            }
        }
        for document_id in range(1, 21)
    ]
    fixture_dir.cleanup()

    print("captured {} records in {} HTTP chunks".format(
        len(records), len(chunks)))

    session_result = {}
    session_listener = socket.socket()
    session_listener.bind(("127.0.0.1", 0))
    session_listener.listen(1)
    session_port = session_listener.getsockname()[1]
    session_server = threading.Thread(
        target=capture_request,
        args=(session_listener, session_result),
        daemon=True,
    )
    session_server.start()
    session_dir = tempfile.TemporaryDirectory()
    session_input = os.path.join(session_dir.name, "session-records.json")
    session_parser = os.path.join(session_dir.name, "parsers.conf")
    session_spool = os.path.join(session_dir.name, "session.ndjson")
    with open(session_input, "w") as stream:
        for document_id in range(1, 30001):
            stream.write(json.dumps({
                "id": document_id,
                "message": "session-test",
                "payload": "x" * 128,
            }, separators=(",", ":")) + "\n")
    with open(session_parser, "w") as stream:
        stream.write("[PARSER]\n    Name session_json\n    Format json\n")
    session_command = config_command(fluent_bit, "out_manticore_session.yaml")
    session_environment = config_environment(
        MANTICORE_INPUT_PATH=session_input,
        MANTICORE_PARSERS_FILE=session_parser,
        MANTICORE_PORT=session_port,
        MANTICORE_SPOOL_PATH=session_spool,
    )
    session_process = subprocess.run(
        session_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        timeout=60,
        env=session_environment,
    )
    session_server.join(timeout=5)
    assert session_process.returncode == 0, session_process.stdout
    assert not session_server.is_alive()
    session_records = b"".join(session_result["chunks"]).splitlines()
    assert len(session_records) == 30000
    assert session_result["request_line"] == (
        "POST /bulk?bulk_import=session_logs HTTP/1.1")
    assert not os.path.exists(session_spool)
    assert not os.path.exists(session_spool + ".commit")
    assert "service has stopped (0 pending tasks)" in session_process.stdout

    with open(session_input, "a") as stream:
        stream.write(json.dumps({
            "id": 1,
            "message": "duplicate-late",
            "payload": "x" * 128,
        }, separators=(",", ":")) + "\n")
    rejected_listener = socket.socket()
    rejected_listener.bind(("127.0.0.1", 0))
    rejected_listener.listen(1)
    rejected_listener.settimeout(1)
    rejected_port = rejected_listener.getsockname()[1]
    rejected_environment = config_environment(
        MANTICORE_INPUT_PATH=session_input,
        MANTICORE_PARSERS_FILE=session_parser,
        MANTICORE_PORT=rejected_port,
        MANTICORE_SPOOL_PATH=session_spool,
    )
    rejected_session = subprocess.run(
        session_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        timeout=60,
        env=rejected_environment,
    )
    connected = False
    try:
        rejected_connection, _ = rejected_listener.accept()
        rejected_connection.close()
        connected = True
    except socket.timeout:
        pass
    rejected_listener.close()
    assert rejected_session.returncode == 0
    assert not connected
    assert "must be unique within a session" in rejected_session.stdout
    assert "single-chunk session aborted" in rejected_session.stdout
    assert not os.path.exists(session_spool)
    assert not os.path.exists(session_spool + ".commit")
    session_dir.cleanup()
    print("single_chunk combined 30000 records and aborted a late duplicate")

    recovery_dir = tempfile.TemporaryDirectory()
    recovery_input = os.path.join(recovery_dir.name, "recovery.json")
    recovery_empty = os.path.join(recovery_dir.name, "empty.json")
    recovery_parser = os.path.join(recovery_dir.name, "parsers.conf")
    recovery_spool = os.path.join(recovery_dir.name, "recovery.ndjson")
    with open(recovery_input, "w") as stream:
        stream.write('{"id":70001,"message":"recover-me"}\n')
    open(recovery_empty, "w").close()
    with open(recovery_parser, "w") as stream:
        stream.write("[PARSER]\n    Name recovery_json\n    Format json\n")
    unavailable = socket.socket()
    unavailable.bind(("127.0.0.1", 0))
    recovery_port = unavailable.getsockname()[1]
    unavailable.close()

    recovery_command = config_command(fluent_bit, "out_manticore_recovery.yaml")

    def recovery_environment(path, table="recovery_logs", port=recovery_port):
        return config_environment(
            MANTICORE_INPUT_PATH=path,
            MANTICORE_PARSERS_FILE=recovery_parser,
            MANTICORE_PORT=port,
            MANTICORE_SPOOL_PATH=recovery_spool,
            MANTICORE_TABLE=table,
        )

    failed_session = subprocess.run(
        recovery_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        timeout=30,
        env=recovery_environment(recovery_input),
    )
    assert failed_session.returncode == 0
    assert os.path.getsize(recovery_spool) > 0
    assert os.path.getsize(recovery_spool + ".commit") > 0
    assert "preserving spool" in failed_session.stdout

    with open(recovery_spool, "ab") as stream:
        stream.write(b'{"insert":{"table":"recovery_logs","id":999')
    with open(recovery_spool + ".commit", "ab") as stream:
        stream.write(b"000000000000")

    recovery_result = {}
    recovery_listener = socket.socket()
    recovery_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    recovery_listener.bind(("127.0.0.1", recovery_port))
    recovery_listener.listen(1)
    recovery_server = threading.Thread(
        target=capture_request,
        args=(recovery_listener, recovery_result),
        daemon=True,
    )
    recovery_server.start()
    recovered_session = subprocess.run(
        recovery_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        timeout=30,
        env=recovery_environment(recovery_empty),
    )
    recovery_server.join(timeout=5)
    assert recovered_session.returncode == 0, recovered_session.stdout
    assert not recovery_server.is_alive()
    recovered_records = b"".join(recovery_result["chunks"]).splitlines()
    assert len(recovered_records) == 1
    assert json.loads(recovered_records[0])["insert"]["id"] == 70001
    assert "replaying pending single-chunk spool" in recovered_session.stdout
    assert not os.path.exists(recovery_spool)
    assert not os.path.exists(recovery_spool + ".commit")

    second_failed = subprocess.run(
        recovery_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        timeout=30,
        env=recovery_environment(recovery_input),
    )
    assert second_failed.returncode == 0
    with open(recovery_spool, "r+b") as stream:
        data = stream.read()
        marker = data.index(b"recover-me")
        stream.seek(marker)
        stream.write(b"Recover-me")
    corrupt_session = subprocess.run(
        recovery_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        timeout=30,
        env=recovery_environment(recovery_empty),
    )
    assert corrupt_session.returncode != 0
    assert "commit journal or spool" in corrupt_session.stdout
    assert "is corrupt" in corrupt_session.stdout
    os.remove(recovery_spool)
    os.remove(recovery_spool + ".commit")

    third_failed = subprocess.run(
        recovery_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        timeout=30,
        env=recovery_environment(recovery_input),
    )
    assert third_failed.returncode == 0

    changed_config_result = {}
    changed_config_listener = socket.socket()
    changed_config_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    changed_config_listener.bind(("127.0.0.1", recovery_port))
    changed_config_listener.listen(1)
    changed_config_server = threading.Thread(
        target=capture_request,
        args=(changed_config_listener, changed_config_result),
        daemon=True,
    )
    changed_config_server.start()
    changed_config_environment = recovery_environment(
        recovery_empty, table="other_logs")
    changed_config_session = subprocess.run(
        recovery_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        timeout=30,
        env=changed_config_environment,
    )
    changed_config_server.join(timeout=5)
    assert changed_config_session.returncode == 0, changed_config_session.stdout
    assert not changed_config_server.is_alive()
    assert changed_config_result["request_line"] == \
        "POST /bulk?bulk_import=other_logs HTTP/1.1"
    recovery_dir.cleanup()
    print("recovery discarded torn tails and replayed under changed configuration")

    rejected_records = [
        ({"id": {"invalid": True}, "message": "poison"}, None,
         "must be a unique, non-zero numeric ID"),
        ({"message": "missing ID"}, None,
         "must contain a non-zero numeric ID"),
        ({"id": 0, "message": "zero ID"}, None,
         "must be a unique, non-zero numeric ID"),
        ({"id": 44, "message": "duplicate ID"}, 2,
         "must be unique within a chunk"),
    ]
    for payload, copies, expected_error in rejected_records:
        assert_rejected_before_connect(
            fluent_bit, payload, expected_error, copies=copies)
    print("permanent ID errors were rejected before delivery")

    retry_result = {}
    retry_listener = socket.socket()
    retry_listener.bind(("127.0.0.1", 0))
    retry_listener.listen(2)
    retry_port = retry_listener.getsockname()[1]
    retry_server = threading.Thread(
        target=capture_retry,
        args=(retry_listener, retry_result),
        daemon=True,
    )
    retry_server.start()

    retry_command = config_command(fluent_bit, "out_manticore_retry.yaml")
    retry_environment = config_environment(MANTICORE_PORT=retry_port)
    retry_process = subprocess.Popen(
        retry_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        env=retry_environment,
    )
    retry_server.join(20)
    if retry_process.poll() is None:
        retry_process.send_signal(signal.SIGTERM)
    retry_output, _ = retry_process.communicate(timeout=15)

    if retry_server.is_alive():
        retry_process.kill()
        raise AssertionError("transient item was not retried\n{}".format(
            retry_output))

    assert len(retry_result["requests"]) == 2
    first_body = b"".join(retry_result["requests"][0][2])
    second_body = b"".join(retry_result["requests"][1][2])
    assert first_body == second_body
    assert json.loads(first_body) == {
        "create": {
            "table": "wire_logs",
            "id": 43,
            "doc": {"message": "retry-item"},
        }
    }
    assert "retryable item error" in retry_output
    print("transient item error retried the original chunk")

    permanent_result = {}
    permanent_listener = socket.socket()
    permanent_listener.bind(("127.0.0.1", 0))
    permanent_listener.listen(1)
    permanent_port = permanent_listener.getsockname()[1]
    permanent_server = threading.Thread(
        target=capture_permanent_server_error,
        args=(permanent_listener, permanent_result),
        daemon=True,
    )
    permanent_server.start()
    permanent_command = config_command(fluent_bit, "out_manticore_permanent.yaml")
    permanent_environment = config_environment(MANTICORE_PORT=permanent_port)
    permanent_proc = subprocess.Popen(
        permanent_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=permanent_environment,
    )
    permanent_output = stop_process(permanent_proc)
    permanent_server.join(timeout=2)
    assert not permanent_server.is_alive()
    assert permanent_result["request"][0] == (
        "POST /bulk?bulk_import=wire_logs HTTP/1.1")
    assert "returned HTTP 500" in permanent_output
    assert "retry in" not in permanent_output
    print("permanent item status inside HTTP 500 was not retried")

    invalid_action_command = [
        fluent_bit,
        "-f", "0.2",
        "-i", "dummy",
        "-p", "samples=1",
        "-o", "manticore",
        "-p", "host=127.0.0.1",
        "-p", "port=9",
        "-p", "table=wire_logs",
        "-p", "action=replace",
        "-m", "*",
    ]
    invalid_action_process = subprocess.run(
        invalid_action_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        timeout=15,
    )
    assert invalid_action_process.returncode != 0
    assert "action must be 'insert' or 'create'" in invalid_action_process.stdout
    print("replace action rejected before delivery")

    single_invalid_dir = tempfile.TemporaryDirectory(
        prefix="manticore-single-config-")
    single_invalid_spool = os.path.join(single_invalid_dir.name, "spool.ndjson")
    for extra, expected in [
        (["-p", "workers=2"],
         "single_chunk requires exactly one output worker"),
        (["-p", "action=create"],
         "single_chunk requires action 'insert' for replay safety"),
        (["-p", "max_session_ids=0"],
         "stream_chunk_size and max_session_ids must be greater than zero"),
    ]:
        command = [
            fluent_bit,
            "-f", "0.2",
            "-i", "dummy",
            "-p", "samples=1",
            "-o", "manticore",
            "-p", "host=127.0.0.1",
            "-p", "port=9",
            "-p", "table=wire_logs",
            "-p", "workers=1",
            "-p", "single_chunk=true",
            "-p", "spool_path={}".format(single_invalid_spool),
        ] + extra + ["-m", "*"]
        process = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            timeout=15,
        )
        assert process.returncode != 0
        assert expected in process.stdout
    single_invalid_dir.cleanup()
    print("invalid single_chunk worker/action/limit configurations rejected")
