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


@pytest.mark.parametrize("placement", ["filter", "processor"])
def test_rule_precedence_and_accessors(tmp_path, placement):
    messages = [
        {"id": 0, "meta": {"level": "error", "destination": "blue"}},
        {"id": 1, "meta": {"level": "info"}},
        {"id": 2},
        {"id": 3, "meta": {"level": 7}},
    ]
    rewrite = {"name": "rewrite_tag", "rule": [
        "$meta['level'] ^(error)$ routed.$1.$meta['destination'].$TAG[1] false",
        "$meta['level'] ^error$ wrong true",
    ]}
    service = service_for(tmp_path, config_for(tmp_path, messages, rewrite, placement))
    try:
        service.start()
        service.wait_for_condition(lambda: len(records(service)) >= 4, timeout=30)
    finally:
        service.stop()
    assert Counter((r["id"], r["route"]) for r in records(service)) == Counter({
        (0, "routed.error.blue.app"): 1, (1, "source.app"): 1,
        (2, "source.app"): 1, (3, "source.app"): 1,
    })


@pytest.mark.parametrize("placement", ["filter", "processor"])
def test_invalid_first_expansion_does_not_try_later_rules(tmp_path, placement):
    messages = [{"id": 0, "kind": "emit"},
                {"id": 1, "kind": "emit", "destination": "routed"}]
    rewrite = {"name": "rewrite_tag", "rule": [
        "$kind ^emit$ $destination false", "$kind ^emit$ wrong false",
    ]}
    service = service_for(tmp_path, config_for(tmp_path, messages, rewrite, placement))
    try:
        service.start()
        service.wait_for_condition(lambda: len(records(service)) >= 2, timeout=30)
    finally:
        service.stop()
    assert Counter((r["id"], r["route"]) for r in records(service)) == Counter({
        (0, "source.app"): 1, (1, "routed"): 1,
    })


@pytest.mark.parametrize("placement", ["filter", "processor"])
def test_explicit_emitter_name_is_preserved(tmp_path, placement):
    rewrite = {"name": "rewrite_tag", "emitter_name": "custom_emitter",
               "rule": "$kind ^emit$ routed false"}
    config = config_for(tmp_path, [{"id": 0, "kind": "emit"}], rewrite, placement)
    service = service_for(tmp_path, config)
    try:
        service.start()
        service.wait_for_condition(lambda: len(records(service)) == 1, timeout=30)
        response = requests.get(
            f"http://127.0.0.1:{service.flb.http_monitoring_port}/api/v1/metrics", timeout=5,
        )
        response.raise_for_status()
        assert "custom_emitter" in response.json()["input"]
    finally:
        service.stop()


@pytest.mark.parametrize("placement", ["filter", "processor"])
@pytest.mark.parametrize("failure", ["duplicate-name", "invalid-regex", "invalid-storage", "missing-storage-path"])
def test_invalid_configuration_is_rejected_cleanly(tmp_path, placement, failure):
    rewrite = {"name": "rewrite_tag", "emitter_name": "shared_emitter",
               "rule": "$kind ^emit$ routed false"}
    if failure == "invalid-regex":
        rewrite["rule"] = "$kind [ routed false"
    elif failure == "invalid-storage":
        rewrite["emitter_storage.type"] = "unsupported"
    config = config_for(tmp_path, [{"id": 0, "kind": "emit"}], rewrite, placement)
    if failure == "missing-storage-path":
        rewrite["emitter_storage.type"] = "filesystem"
        config["service"].pop("storage.path")
    if failure == "duplicate-name":
        if placement == "filter":
            config["pipeline"]["filters"].insert(1, copy.deepcopy(rewrite))
        else:
            config["pipeline"]["inputs"].append(copy.deepcopy(config["pipeline"]["inputs"][0]))
    service = service_for(tmp_path, config)
    with pytest.raises(FluentBitStartupError, match="exited early"):
        service.start()
    log = Path(service.flb.log_file).read_text()
    if failure == "duplicate-name":
        assert "emitter_name 'shared_emitter' already exists" in log
    elif failure == "invalid-storage":
        assert "invalid 'emitter_storage.type'" in log
    elif failure == "invalid-regex":
        assert "could not compile regex" in log
    elif failure == "missing-storage-path":
        assert "but no filesystem path was defined" in log


@pytest.mark.parametrize("placement", ["filter", "processor"])
def test_no_rules_preserves_existing_passthrough_behavior(tmp_path, placement):
    config = config_for(tmp_path, [{"id": 0}, {"id": 1}], {"name": "rewrite_tag"}, placement)
    service = service_for(tmp_path, config)
    try:
        service.start()
        service.wait_for_condition(lambda: len(records(service)) == 2, timeout=30)
    finally:
        service.stop()
    assert Counter((r["id"], r["route"]) for r in records(service)) == Counter({
        (0, "source.app"): 1, (1, "source.app"): 1,
    })


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


@pytest.mark.parametrize("threaded", [False, True])
def test_multiple_rewrite_processor_stages_have_unique_emitters(tmp_path, threaded):
    config = config_for(tmp_path, [{"id": 0, "kind": "emit"}], {
        "name": "rewrite_tag", "rule": "$kind ^emit$ middle false",
    }, "processor")
    input_config = config["pipeline"]["inputs"][0]
    input_config["threaded"] = threaded
    input_config["processors"]["logs"].append({
        "name": "rewrite_tag", "rule": "$kind ^emit$ routed false",
    })
    service = service_for(tmp_path, config)
    try:
        service.start()
        service.wait_for_condition(lambda: len(records(service)) == 1, timeout=30)
        response = requests.get(
            f"http://127.0.0.1:{service.flb.http_monitoring_port}/api/v1/metrics", timeout=5,
        )
        response.raise_for_status()
        emitter_names = [name for name in response.json()["input"] if name.startswith("emitter_for_")]
        assert len(emitter_names) == 2
        assert len(set(emitter_names)) == 2
    finally:
        service.stop()
    assert [(r["id"], r["route"]) for r in records(service)] == [(0, "routed")]


@pytest.mark.parametrize("placement", ["filter", "processor"])
def test_existing_default_emitter_metric_name_is_preserved(tmp_path, placement):
    config = config_for(tmp_path, [{"id": 0, "kind": "emit"}], {
        "name": "rewrite_tag", "rule": "$kind ^emit$ routed false",
    }, placement)
    # No other global filters consume an instance ID before this processor.
    if placement == "processor":
        config["pipeline"].pop("filters")
    service = service_for(tmp_path, config)
    try:
        service.start()
        service.wait_for_condition(lambda: len(records(service)) == 1, timeout=30)
        response = requests.get(
            f"http://127.0.0.1:{service.flb.http_monitoring_port}/api/v1/metrics", timeout=5,
        )
        response.raise_for_status()
        emitter_names = [name for name in response.json()["input"] if name.startswith("emitter_for_")]
        assert emitter_names == ["emitter_for_rewrite_tag.0"]
    finally:
        service.stop()
