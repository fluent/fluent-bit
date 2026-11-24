"""OTLP log exports preserve the record event name."""

import json

import pytest
import requests
import yaml
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest

from test_out_opentelemetry_001 import (
    Service, _event_time, _group_end, _group_start, _send_forward, data_storage,
)

EVENT_NAME_FIELD = 12


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


def protobuf_string_bytes(number, value):
    """Encode a length-delimited string field the pinned bindings do not know."""
    data = value.encode("utf-8")
    assert number < 16 and len(data) < 128
    return bytes([number << 3 | 2, len(data)]) + data


def event_name(record_id):
    # Every third record carries no event name.
    return None if record_id % 3 == 0 else f"app.event.{record_id}"


def grouped_protobuf_payload():
    payload = ExportLogsServiceRequest()
    for group in range(2):
        resource = payload.resource_logs.add()
        resource.resource.attributes.add(key="service.name").value.string_value = f"service-{group}"
        scope = resource.scope_logs.add()
        scope.scope.name = f"scope-{group}"
        for index in range(3):
            record_id = group * 3 + index
            record = scope.log_records.add()
            record.time_unix_nano = 1700000000000000000 + record_id
            record.body.kvlist_value.values.add(key="id").value.int_value = record_id
            if event_name(record_id) is not None:
                record.MergeFromString(protobuf_string_bytes(EVENT_NAME_FIELD, event_name(record_id)))
    return payload.SerializeToString(), "application/x-protobuf"


def grouped_json_payload():
    resource_logs = []
    for group in range(2):
        records = []
        for index in range(3):
            record_id = group * 3 + index
            record = {
                "timeUnixNano": str(1700000000000000000 + record_id),
                "body": {"kvlistValue": {"values": [{"key": "id", "value": {"intValue": str(record_id)}}]}},
            }
            if event_name(record_id) is not None:
                record["eventName"] = event_name(record_id)
            records.append(record)
        resource_logs.append({
            "resource": {"attributes": [{"key": "service.name",
                                         "value": {"stringValue": f"service-{group}"}}]},
            "scopeLogs": [{"scope": {"name": f"scope-{group}"}, "logRecords": records}],
        })
    return json.dumps({"resourceLogs": resource_logs}), "application/json"


def exported_event_names():
    """Map every exported record id to the event names found on the wire."""
    names = {}
    for payload in data_storage["logs"]:
        for resource in payload.resource_logs:
            for scope in resource.scope_logs:
                for record in scope.log_records:
                    record_id = next(item.value.int_value for item in record.body.kvlist_value.values
                                     if item.key == "id")
                    names[record_id] = protobuf_string_field(record, EVENT_NAME_FIELD)
    return names


def run_service(tmp_path, input_config, output_config, send):
    config = {
        "service": {"flush": 0.1, "grace": 1, "http_server": True,
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {
            "inputs": [dict(input_config, listen="127.0.0.1", port="${FLUENT_BIT_TEST_LISTENER_PORT}")],
            "outputs": [dict({"name": "opentelemetry", "match": "*", "host": "127.0.0.1",
                              "port": "${TEST_SUITE_HTTP_PORT}"}, **output_config)],
        },
    }
    config_path = tmp_path / "fluent-bit.yaml"
    config_path.write_text(yaml.safe_dump(config))
    service = Service(str(config_path))
    try:
        service.start()
        expected = send(service)
        service.service.wait_for_condition(
            lambda: len(exported_event_names()) >= expected or None,
            timeout=30, interval=0.1, description="all exported records",
        )
    finally:
        service.stop()
    return exported_event_names()


@pytest.mark.parametrize("payload", [grouped_protobuf_payload, grouped_json_payload],
                         ids=["protobuf", "json"])
@pytest.mark.parametrize("batch_size", [1000, 2], ids=["single-batch", "batched"])
def test_event_name_round_trip(tmp_path, payload, batch_size):
    """An OTLP event name received by the input is exported on its own record."""
    data, content_type = payload()

    def send(service):
        response = requests.post(f"http://127.0.0.1:{service.flb_listener_port}/v1/logs",
                                 data=data, headers={"Content-Type": content_type}, timeout=30)
        assert response.status_code in (200, 201), response.text
        return 6

    names = run_service(tmp_path, {"name": "opentelemetry", "tag": "test"},
                        {"batch_size": batch_size}, send)

    assert names == {record_id: [] if event_name(record_id) is None else [event_name(record_id)]
                     for record_id in range(6)}


@pytest.mark.parametrize("grouped", [False, True], ids=["standalone", "grouped"])
def test_event_name_metadata_validation(tmp_path, grouped):
    """Only a string otlp.event_name metadata value becomes the record event name."""
    cases = [({"otlp": {"event_name": "app.event"}}, ["app.event"]),
             ({"otlp": {"event_name": "é.event"}}, ["é.event"]),
             ({"otlp": {"event_name": 7}}, []),
             ({"otlp": {"event_name": b"\xc0"}}, []),
             ({"otlp": {"event_name": b"\xc3"}}, []),
             ({"otlp": {}}, []),
             ({"otlp": "app.event"}, []),
             ({}, [])]
    # The event name is never read from the record body.
    entries = []
    for index, (metadata, _) in enumerate(cases):
        if grouped:
            entries.append(_group_start(index, f"resource-{index}"))
        entries.append([[_event_time(1700000000), metadata], {"id": index, "event_name": "body"}])
        if grouped:
            entries.append(_group_end())

    def send(service):
        _send_forward(service, entries)
        return len(cases)

    names = run_service(tmp_path, {"name": "forward"}, {}, send)

    assert names == {index: expected for index, (_, expected) in enumerate(cases)}
