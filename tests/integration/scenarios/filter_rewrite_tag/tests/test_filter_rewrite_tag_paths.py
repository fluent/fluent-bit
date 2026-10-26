import copy
import json
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest
import requests
import yaml

from utils.fluent_bit_manager import FluentBitStartupError
from utils.test_service import FluentBitTestService


def records(service):
    result = []
    for line in Path(service.flb.log_file).read_text().splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and "id" in value:
            result.append(value)
    return result


def config_for(tmp_path, messages, rewrite, placement="filter"):
    input_config = {"name": "dummy", "tag": "source.app", "samples": 1,
                    "dummy": " ".join(json.dumps(message) for message in messages)}
    config = {
        "service": {"flush": 0.1, "grace": 1, "log_level": "info",
                    "scheduler.base": 1, "scheduler.cap": 1,
                    "storage.path": str(tmp_path / "storage"),
                    "http_server": "on", "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {"inputs": [input_config], "outputs": [
            {"name": "stdout", "match": "*", "format": "json_lines", "workers": 0},
        ]},
    }
    if placement == "filter":
        rewrite["match"] = "source.app"
        config["pipeline"]["filters"] = [rewrite]
    else:
        input_config["processors"] = {"logs": [rewrite]}
    for tag in ["source.app", "routed.error.blue.app", "routed", "wrong"]:
        config["pipeline"].setdefault("filters", []).append(
            {"name": "record_modifier", "match": tag, "record": f"route {tag}"}
        )
    return config


def service_for(tmp_path, config, name="config.yaml"):
    path = tmp_path / name
    path.write_text(yaml.safe_dump(config))
    return FluentBitTestService(str(path))


@pytest.fixture
def retry_sink():
    state = SimpleNamespace(allow=threading.Event(), attempted=threading.Event(),
                            lock=threading.Lock(), received=[])

    class Sink(BaseHTTPRequestHandler):
        def do_POST(self):
            batch = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state.attempted.set()
            if state.allow.is_set():
                with state.lock:
                    state.received.extend(record["id"] for record in batch)
                status = 200
            else:
                status = 503
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Sink)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    state.port = server.server_port
    try:
        yield state
    finally:
        state.allow.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def add_retry_output(config, sink):
    config["pipeline"]["outputs"].append({
        "name": "http", "match": "routed", "host": "127.0.0.1", "port": sink.port,
        "uri": "/records", "format": "json", "json_date_key": False,
        "workers": 1, "retry_limit": False,
    })


def test_emitter_backpressure_keeps_records_and_resumes_input(tmp_path, retry_sink):
    rewrite = {"name": "rewrite_tag", "emitter_name": "pressure_emitter",
               "emitter_mem_buf_limit": "1K", "rule": "$kind ^emit$ routed false"}
    config = config_for(tmp_path, [], rewrite)
    config["pipeline"]["inputs"] = [{
        "name": "http", "listen": "127.0.0.1", "port": "${FLUENT_BIT_TEST_LISTENER_PORT}",
    }]
    add_retry_output(config, retry_sink)
    service = service_for(tmp_path, config)
    try:
        service.start()
        url = f"http://127.0.0.1:{service.flb_listener_port}/source.app"
        messages = [{"id": i, "kind": "emit", "padding": "x" * 200} for i in range(24)]
        response = requests.post(url, json=messages, timeout=15)
        assert response.status_code == 201, response.text
        service.wait_for_condition(lambda: len(records(service)) == 24, timeout=30)
        service.wait_for_condition(
            lambda: "pressure_emitter paused (mem buf overlimit" in Path(service.flb.log_file).read_text(),
            timeout=30, description="emitter pause propagated under output retries",
        )
        assert retry_sink.attempted.wait(30)
        assert {r["route"] for r in records(service)} == {"source.app", "routed"}
        retry_sink.allow.set()
        service.wait_for_condition(
            lambda: "pressure_emitter resume (mem buf overlimit" in Path(service.flb.log_file).read_text(),
            timeout=30, description="emitter resumes after output recovery",
        )
        response = requests.post(url, json={"id": 24, "kind": "emit"}, timeout=15)
        assert response.status_code == 201, response.text
        service.wait_for_condition(lambda: len(records(service)) == 25, timeout=30)
        routed = Counter(r["id"] for r in records(service) if r["route"] == "routed")
        service.wait_for_condition(lambda: Counter(retry_sink.received) == routed, timeout=30)
    finally:
        retry_sink.allow.set()
        service.stop()
    assert Counter(r["id"] for r in records(service)) == Counter(range(25))


def test_filesystem_emitter_backlog_replays_with_live_records(tmp_path, retry_sink):
    rewrite = {"name": "rewrite_tag", "emitter_name": "persistent_emitter",
               "emitter_storage.type": "filesystem", "rule": "$kind ^emit$ routed false"}
    config = config_for(tmp_path, [{"id": i, "kind": "emit"} for i in range(3)], rewrite)
    add_retry_output(config, retry_sink)
    first = service_for(tmp_path, config, "seed.yaml")
    chunks = tmp_path / "storage"
    try:
        first.start()
        assert retry_sink.attempted.wait(30)
        first.wait_for_condition(lambda: list(chunks.glob("*/*.flb")), timeout=30)
    finally:
        first.stop()
    assert list(chunks.glob("*/*.flb")), "undelivered emitter chunks must survive shutdown"
    retry_sink.allow.set()
    config["pipeline"]["inputs"][0]["dummy"] = " ".join(
        json.dumps({"id": i, "kind": "emit"}) for i in range(3, 5)
    )
    second = service_for(tmp_path, config, "replay.yaml")
    try:
        second.start()
        second.wait_for_condition(lambda: Counter(retry_sink.received) == Counter(range(5)), timeout=30)
        second.wait_for_condition(lambda: not list(chunks.glob("*/*.flb")), timeout=30)
    finally:
        second.stop()
    assert Counter(retry_sink.received) == Counter(range(5))
