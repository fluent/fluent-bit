#  Fluent Bit
#  ==========
#  Copyright (C) 2015-2026 The Fluent Bit Authors
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import base64
import json
import os
from pathlib import Path

import pytest
import requests
import yaml

from google.protobuf import json_format
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
from utils.test_service import FluentBitTestService

RECORDS = 9

ACTIONS = [
    ("rename", "exception.type", "exception.kind"),
    ("delete", "count", None),
    ("delete", "never", None),
    ("insert", "benchmark.enriched", "true"),
    ("upsert", "benchmark.enriched", "again"),
    ("insert", "view.added", "yes"),
]


def any_value(value):
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    if isinstance(value, bytes):
        return {"bytesValue": base64.b64encode(value).decode()}
    if isinstance(value, list):
        return {"arrayValue": {"values": [any_value(item) for item in value]}}
    if isinstance(value, dict):
        return {"kvlistValue": {"values": key_values(value)}}
    if value is None:
        return {}
    return {"stringValue": value}


def key_values(mapping):
    return [{"key": key, "value": any_value(value)} for key, value in mapping.items()]


def logs_request():
    """Two resources, three scopes, every attribute type and body shape."""
    attributes = {
        "exception.type": "java.lang.IllegalStateException", "count": 42, "negative": -7,
        "ratio": 1.5, "enabled": True, "none": None, "empty": "", "raw": b"\x00\x01\xff",
        "labels": {"inner": "nested", "depth": {"more": [1, "two"]}}, "tags": ["sample", 2],
    }
    bodies = ["plain text", {"message": "structured", "code": 503}, None, 7, ["a", "b"]]
    records = []
    for index in range(RECORDS):
        record = {
            "timeUnixNano": str(1700000000000000000 + index),
            "severityNumber": 9 + index % 3,
            "severityText": "INFO" if index % 2 else "",
            "flags": index,
        }
        body = bodies[index % len(bodies)]
        if body is not None:
            record["body"] = any_value(body)
        if index % 4 != 3:
            # every fourth record has no attributes at all
            record["attributes"] = key_values(
                attributes if index % 2 == 0 else {"exception.type": "second", "only": index}
            )
        if index % 3 == 0:
            record["observedTimeUnixNano"] = str(1700000000000001000 + index)
            # protobuf JSON carries bytes as base64
            record["traceId"] = base64.b64encode(bytes(range(16))).decode()
            record["spanId"] = base64.b64encode(bytes(range(8))).decode()
            record["droppedAttributesCount"] = 2
        records.append(record)

    payload = {"resourceLogs": [
        {
            "resource": {"attributes": key_values({"service.name": "orders", "zone": 3}),
                         "droppedAttributesCount": 1},
            "schemaUrl": "https://example.test/resource",
            "scopeLogs": [
                {"scope": {"name": "first", "version": "1.2.3",
                           "attributes": key_values({"scope.kind": "library"})},
                 "schemaUrl": "https://example.test/scope", "logRecords": records[:4]},
                {"logRecords": records[4:6]},
            ],
        },
        {"scopeLogs": [{"scope": {"name": "second"}, "logRecords": records[6:]}]},
    ]}
    return json_format.Parse(json.dumps(payload), ExportLogsServiceRequest()).SerializeToString()


def start_service(tmp_path, name, views, processors, workers):
    receiver = {
        "name": "opentelemetry", "listen": "127.0.0.1",
        "port": "${FLUENT_BIT_TEST_LISTENER_PORT}", "http_server.workers": workers,
        "otlp_log_views": views,
    }
    if processors:
        receiver["processors"] = {"logs": processors}
    config = tmp_path / f"{name}.yaml"
    config.write_text(yaml.safe_dump({
        "service": {"flush": 0.2, "http_server": "on",
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {"inputs": [receiver],
                     "outputs": [{"name": "stdout", "match": "*", "format": "otlp_json"}]},
    }), encoding="utf-8")
    service = FluentBitTestService(str(config))
    service.start()
    return service


def post_logs(service, payload):
    return requests.post(
        f"http://127.0.0.1:{service.flb_listener_port}/v1/logs", data=payload,
        headers={"Content-Type": "application/x-protobuf"}, timeout=10)


def delivered_groups(service):
    groups = []
    text = Path(service.flb.log_file).read_text(encoding="utf-8")
    for line in text.splitlines(keepends=True):
        if line.startswith('{"resourceLogs":') and line.endswith("\n"):
            groups.extend(json.loads(line)["resourceLogs"])
    return groups


def record_count(groups):
    return sum(len(scope["logRecords"]) for group in groups for scope in group["scopeLogs"])


def run_case(tmp_path, name, views, processors, workers):
    service = start_service(tmp_path, name, views, processors, workers)
    try:
        response = post_logs(service, logs_request())
        assert response.status_code in (200, 201)

        def delivered():
            groups = delivered_groups(service)
            return groups if record_count(groups) >= RECORDS else None

        groups = service.wait_for_condition(delivered, timeout=25)
    finally:
        service.stop()
    return [(group.get("resource"), group.get("schemaUrl"), scope.get("scope"),
             scope.get("schemaUrl"), record)
            for group in groups for scope in group["scopeLogs"]
            for record in scope["logRecords"]]


def content_modifier_units():
    units = []
    for action, key, value in ACTIONS:
        unit = {"name": "content_modifier", "context": "otel_log_attributes",
                "action": action, "key": key}
        if value is not None:
            unit["value"] = value
        units.append(unit)
    return units


@pytest.mark.parametrize("workers", [
    1,
    pytest.param(2, marks=pytest.mark.skipif(
        os.name == "nt", reason="HTTP shared listener ports are unavailable on Windows"
    )),
])
@pytest.mark.parametrize("chain", ["none", "views", "cfl"])
def test_otlp_protobuf_logs_match_the_unpacking_decoder(chain, workers, tmp_path):
    # 'none': no processors, the request is transcoded directly.
    # 'views': a chain that edits record views while it is transcoded.
    # 'cfl': a chain with a unit that needs CFL records, so views are not used.
    processors = [] if chain == "none" else content_modifier_units()
    if chain == "cfl":
        processors.append({"name": "content_modifier", "context": "otel_log_attributes",
                           "action": "hash", "key": "only"})
    expected = run_case(tmp_path, "reference", False, processors, workers)
    actual = run_case(tmp_path, "direct", True, processors, workers)
    assert len(expected) == RECORDS
    assert actual == expected

    if chain != "none":
        for *_, record in actual:
            attributes = {entry["key"]: entry["value"] for entry in record["attributes"]}
            assert "exception.type" not in attributes and "count" not in attributes
            assert attributes["benchmark.enriched"] == {"stringValue": "again"}
            assert attributes["view.added"] == {"stringValue": "yes"}


@pytest.mark.parametrize("views", [False, True])
def test_otlp_protobuf_logs_malformed_value_in_removed_attribute(views, tmp_path):
    # A processor that deletes an attribute never reads its value. The request
    # is still rejected when that value is malformed, on both decoding paths,
    # and nothing of it is ingested.
    valid = logs_request()
    int_value = b"\x05count\x12\x02\x18\x2a"
    assert int_value in valid
    # the same bytes as a string of 42 bytes inside a value of two
    malformed = valid.replace(int_value, b"\x05count\x12\x02\x0a\x2a")

    units = [{"name": "content_modifier", "context": "otel_log_attributes",
              "action": "delete", "key": "count"}]
    service = start_service(tmp_path, "malformed", views, units, 1)
    try:
        assert post_logs(service, malformed).status_code == 400
        assert post_logs(service, valid).status_code in (200, 201)
        groups = service.wait_for_condition(
            lambda: delivered_groups(service) if record_count(delivered_groups(service)) >= RECORDS
            else None, timeout=25)
    finally:
        service.stop()

    # only the valid request arrived, without the deleted attribute
    assert record_count(groups) == RECORDS
    for group in groups:
        for scope in group["scopeLogs"]:
            for record in scope["logRecords"]:
                assert all(entry["key"] != "count" for entry in record.get("attributes", []))
