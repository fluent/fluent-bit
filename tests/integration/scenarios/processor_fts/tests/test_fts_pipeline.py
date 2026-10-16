"""Real OTLP export, fan-out isolation, retry, and filesystem ingestion."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import requests
import yaml
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest

from utils.test_service import FluentBitTestService
from test_fts_policies import PolicyRunner, attributes, scalar


@pytest.mark.parametrize("placement", ["input", "output"])
@pytest.mark.parametrize("finish_native", [False, True])
@pytest.mark.parametrize("native_neighbor", ["none", "before", "after"])
def test_native_filter_chain_preserves_edits_and_groups(tmp_path, placement, finish_native,
                                                       native_neighbor):
    script = tmp_path / "select.lua"
    script.write_text('''function select_log(tag, timestamp, record)
      if record.text ~= "operationA" then return -1, timestamp, record end
      record.filter_ran = true
      return 2, timestamp, record
    end''')
    processors = [{"name": "fts", "code": '''function process(log)
      log.body:set("stage", "before")
      log.resource.attributes:set("kept.text", log.body:get_string("text"))
    end'''}, {"name": "lua", "script": str(script), "call": "select_log"}]
    if native_neighbor != "none":
        processors.insert(0 if native_neighbor == "before" else 1,
                          {"name": "content_modifier", "context": "body", "action": "insert",
                           "key": "native_ran", "value": "preserved"})
    if finish_native:
        processors.append({"name": "fts", "code": '''function process(log)
          assert(log.body:get_string("stage") == "before")
          log.body:set("stage", "after")
        end'''})
    source = {"name": "opentelemetry", "port": "${FLUENT_BIT_TEST_LISTENER_PORT}"}
    output = {"name": "stdout", "match": "*", "format": "otlp_json"}
    (source if placement == "input" else output)["processors"] = {"logs": processors}
    config = tmp_path / "mixed-chain.yaml"
    config.write_text(yaml.safe_dump({"service": {"flush": 0.2, "grace": 1,
        "http_server": True, "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {"inputs": [source], "outputs": [output]}}))
    service = FluentBitTestService(str(config))
    try:
        service.start()
        payload = PolicyRunner(None, 0).payload("unused", "mixed-chain")
        logs = payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
        logs.insert(2, json.loads(json.dumps(logs[0])))
        response = requests.post(f"http://127.0.0.1:{service.flb_listener_port}/v1/logs",
                                 json=payload, timeout=15)
        response.raise_for_status()

        def collect():
            rows = []
            for line in Path(service.flb.log_file).read_text().splitlines(keepends=True):
                if not line.startswith("{") or not line.endswith("\n"):
                    continue
                batch = json.loads(line)
                rows.extend((resource, log) for resource in batch["resourceLogs"]
                            for scope in resource["scopeLogs"] for log in scope["logRecords"])
            return rows if len(rows) >= 2 else None

        rows = service.wait_for_condition(collect, timeout=30)
        assert len(rows) == 2
        for resource, log in rows:
            body = scalar(log["body"])
            assert body["text"] == "operationA"
            if native_neighbor != "none":
                assert body["native_ran"] == "preserved"
            assert body["filter_ran"] is True
            assert body["stage"] == ("after" if finish_native else "before")
            assert attributes(resource["resource"]["attributes"])["kept.text"] == "operationA"
            assert all(scope["logRecords"] for scope in resource["scopeLogs"])
        diagnostics = Path(service.flb.log_file).read_text()
        assert "cannot construct" not in diagnostics and "policy failed" not in diagnostics
    finally:
        service.stop()


def test_group_end_markers_reach_native_processors(tmp_path):
    """Native processors after FTS receive complete group end records."""
    processors = [{"name": "fts", "code": "function process(log) log.body:set('seen', true) end"},
                  {"name": "sql", "query": "SELECT text, seen FROM STREAM;"}]
    source = {"name": "opentelemetry", "port": "${FLUENT_BIT_TEST_LISTENER_PORT}",
              "processors": {"logs": processors}}
    output = {"name": "stdout", "match": "*", "format": "otlp_json"}
    config = tmp_path / "fts-sql.yaml"
    config.write_text(yaml.safe_dump({"service": {"flush": 0.2, "grace": 1,
        "http_server": True, "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {"inputs": [source], "outputs": [output]}}))
    service = FluentBitTestService(str(config))
    try:
        service.start()
        payload = PolicyRunner(None, 0).payload("unused", "fts-sql")
        response = requests.post(f"http://127.0.0.1:{service.flb_listener_port}/v1/logs",
                                 json=payload, timeout=15)
        response.raise_for_status()

        def collect():
            rows = []
            for line in Path(service.flb.log_file).read_text().splitlines(keepends=True):
                if not line.startswith("{") or not line.endswith("\n"):
                    continue
                batch = json.loads(line)
                rows.extend(log for resource in batch["resourceLogs"]
                            for scope in resource["scopeLogs"] for log in scope["logRecords"])
            return rows or None

        rows = service.wait_for_condition(collect, timeout=30)
        assert rows and all(scalar(log["body"])["seen"] is True for log in rows)
    finally:
        service.stop()

def protobuf_string_field(message, number):
    # The suite's pinned OTel Python bindings predate event_name. Protobuf
    # retains unknown fields, so verify field 12 on the exported wire itself.
    data = message.SerializeToString()
    position = 0
    result = []

    def varint():
        nonlocal position
        value, shift = 0, 0
        while True:
            byte = data[position]; position += 1
            value |= (byte & 127) << shift
            if byte < 128: return value
            shift += 7
            assert shift < 70

    while position < len(data):
        key = varint(); wire = key & 7
        if wire == 0: varint()
        elif wire == 1: position += 8
        elif wire == 5: position += 4
        else:
            assert wire == 2
            length = varint()
            if key >> 3 == number:
                result.append(data[position:position + length].decode("utf-8"))
            position += length
        assert position <= len(data)
    return result


@pytest.mark.parametrize("filesystem,replay", [(False, False), (True, False), (True, True)])
def test_output_policy_isolated_across_routes_and_retries(tmp_path, filesystem, replay):
    received, attempts = [], []
    blocked = {"value": replay}

    class Collector(BaseHTTPRequestHandler):
        def do_POST(self):
            message = ExportLogsServiceRequest.FromString(self.rfile.read(int(self.headers["Content-Length"])))
            attempts.append(message)
            status = 503 if blocked["value"] or len(attempts) == 1 else 200
            if status == 200:
                received.append(message)
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Collector)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    policy = '''function process(log)
      local producer = log.body:get_string("text")
      log.resource.attributes:set("service.name", producer)
      log.scope.name = producer
      log.body:set("export.policy", "sanitized")
      log.body:remove("secret")
    end'''
    source = {"name":"opentelemetry", "port":"${FLUENT_BIT_TEST_LISTENER_PORT}"}
    service_config = {"flush":0.2, "grace":1, "http_server":True,
                      "http_port":"${FLUENT_BIT_HTTP_MONITORING_PORT}",
                      "scheduler.base":1, "scheduler.cap":1}
    if filesystem:
        service_config["storage.path"] = str(tmp_path / "storage")
        source["storage.type"] = "filesystem"
    config = tmp_path / "pipeline.yaml"
    config.write_text(yaml.safe_dump({"service":service_config, "pipeline":{
        "inputs":[source], "outputs":[
            {"name":"stdout", "match":"*", "format":"otlp_json"},
            {"name":"opentelemetry", "match":"*", "host":"127.0.0.1", "port":server.server_port,
             "retry_limit":False, "processors":{"logs":[{"name":"fts", "code":policy}]}},
        ]}}))
    service = FluentBitTestService(str(config))
    try:
        service.start()
        payload = PolicyRunner(None, 0).payload("unused", "route-isolation")
        payload["resourceLogs"][0]["resource"]["droppedAttributesCount"] = 7
        payload["resourceLogs"][0]["scopeLogs"][0]["scope"]["droppedAttributesCount"] = 5
        logs = payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
        logs.insert(2, json.loads(json.dumps(logs[0])))
        for log in logs:
            log["body"]["kvlistValue"]["values"].append(
                {"key":"secret", "value":{"stringValue":"sensitive"}})
        response = requests.post(f"http://127.0.0.1:{service.flb_listener_port}/v1/logs",json=payload, timeout=15)
        assert response.status_code in (200, 201)
        if replay:
            service.wait_for_condition(lambda: attempts, timeout=30)
            service.stop()
            original_log = Path(service.flb.log_file).read_text()
            assert list((tmp_path / "storage").rglob("*.flb")), "filesystem chunk was not retained"
            blocked["value"] = False
            service = FluentBitTestService(str(config))
            service.start()
        service.wait_for_condition(lambda: received, timeout=30)
        service.stop()
        if not replay:
            original_log = Path(service.flb.log_file).read_text()
        assert len(attempts) >= 2
        assert attempts[0].SerializeToString() == attempts[1].SerializeToString()
        rows = [(resource, scope, log) for message in received for resource in message.resource_logs
                for scope in resource.scope_logs for log in scope.log_records]
        assert [dict((v.key, v.value.string_value) for v in log.body.kvlist_value.values)["text"]
                for _, _, log in rows] == ["operationA", "operationB", "operationA", "control"]
        for resource, scope, log in rows:
            body = {v.key:v.value.string_value for v in log.body.kvlist_value.values}
            assert body["export.policy"] == "sanitized" and "secret" not in body
            assert {v.key:v.value.string_value for v in resource.resource.attributes}["service.name"] == body["text"]
            assert scope.scope.name == body["text"]
            assert resource.resource.dropped_attributes_count == 7
            assert scope.scope.dropped_attributes_count == 5
            assert log.dropped_attributes_count in (1, 2)
            assert protobuf_string_field(log, 12) == ["application.event"]
            assert log.time_unix_nano == 2147483648123456789 and log.flags in (1, 2)
        raw_batches = [json.loads(line) for line in original_log.splitlines()
                       if line.startswith('{')]
        raw_logs = [log for batch in raw_batches for resource in batch["resourceLogs"]
                    for scope in resource["scopeLogs"] for log in scope["logRecords"]]
        assert len(raw_logs) == 4
        assert all(scalar(log["body"])["secret"] == "sensitive" for log in raw_logs)
        assert all("export.policy" not in scalar(log["body"]) for log in raw_logs)
        for batch in raw_batches:
            for resource in batch["resourceLogs"]:
                assert "service.name" not in attributes(resource["resource"]["attributes"])
                assert all(scope["scope"]["name"] == "scope" for scope in resource["scopeLogs"])
    finally:
        service.stop()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("placement", ["input", "output"])
@pytest.mark.parametrize("rollback", [False, True])
def test_pooled_batch_commit_rollback_and_retained_values(tmp_path, placement, rollback):
    from test_fts_security_batches import BatchRunner

    code = '''
      local saved
      function process(log)
        if saved then
          assert(saved:get_string("text") == "retained snapshot")
          saved:set("text", "changed after commit")
        end
        log.body:set("text", "retained snapshot")
        log.body:set("edited", true)
        saved = log.body:copy()
        if ROLLBACK and log.body:get_number("index") == 599 then
          log.body:set("large", string.rep("x", 70000))
        end
      end
    '''.replace("ROLLBACK", "true" if rollback else "false")
    source = {"name": "opentelemetry", "port": "${FLUENT_BIT_TEST_LISTENER_PORT}"}
    output = {"name": "stdout", "match": "*", "format": "otlp_json"}
    (source if placement == "input" else output)["processors"] = {"logs": [
        {"name": "fts", "code": code, "error_mode": "keep", "output_limit": "65536"}]}
    config = tmp_path / "pooled-batch.yaml"
    config.write_text(yaml.safe_dump({"service": {"flush": 0.2, "grace": 1,
        "http_server": True, "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {"inputs": [source], "outputs": [output]}}))
    service = FluentBitTestService(str(config))
    try:
        service.start()
        runner = BatchRunner(service.flb, service.flb_listener_port, "logs")
        items = [{"timeUnixNano": "2147483648123456789", "body": {"kvlistValue": {"values": [
            {"key": "index", "value": {"intValue": str(index)}},
            {"key": "text", "value": {"stringValue": "original"}}]}}} for index in range(600)]
        for _ in range(2):
            _, rows = runner.send(items, "json")
            assert len(rows) == 600
            bodies = [scalar(row["body"]) for row in rows]
            assert [body["index"] for body in bodies] == list(range(600))
            assert all(body["text"] == ("original" if rollback else "retained snapshot")
                       for body in bodies)
            assert all(("edited" not in body) if rollback else body["edited"] is True
                       for body in bodies)
            diagnostics = runner.recent_log()
            assert "policy failed" not in diagnostics
            assert ("cannot construct policy output" in diagnostics) is rollback
    finally:
        service.stop()
