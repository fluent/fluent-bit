#!/usr/bin/env python3
"""Generate the corpora compared by the OTLP logs CFL parity tests.

logs_parity.jsonl holds one OTLP/JSON logs request per line. logs_parity.pb
holds OTLP protobuf logs requests, each one prefixed by its length as a
little-endian 32-bit integer.

The requests are random and often invalid on purpose: the tests check that
the CFL decoders accept, reject and size every request like the msgpack
decoders do.

Usage: logs_parity_corpus.py [count] [seed]
"""

import json
import os
import random
import struct
import sys

from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest

# Wrapper keys, including prefixes and unknown names
JSON_WRAPPERS = ["stringValue", "boolValue", "intValue", "doubleValue", "bytesValue",
                 "arrayValue", "kvlistValue", "str", "int", "x", ""]


def json_scalar():
    return random.choice([None, True, False, 0, 1, -5, 2**63, 1.5, -0.0, "", "s", "123",
                          "-9", "1.25", "abc", "aGVsbG8=", "a"])


def json_any_value(depth=0):
    choice = random.random()
    if depth > 3 or choice < 0.3:
        return json_scalar()
    if choice < 0.7:
        key = random.choice(JSON_WRAPPERS)
        if key == "arrayValue":
            value = random.choice([
                [json_any_value(depth + 1) for _ in range(random.randint(0, 3))],
                {"values": [json_any_value(depth + 1) for _ in range(2)]},
                {}, {"other": 1}, json_scalar()])
        elif key == "kvlistValue":
            value = random.choice([
                {"values": json_key_values(depth + 1)}, {},
                {"a": json_any_value(depth + 1), "b": 1},
                json_key_values(depth + 1), json_scalar()])
        elif random.random() < 0.8:
            value = json_scalar()
        else:
            value = json_any_value(depth + 1)
        return {key: value}
    if choice < 0.85:
        return [json_any_value(depth + 1) for _ in range(random.randint(0, 3))]
    return {random.choice(["a", "b", "c"]): json_any_value(depth + 1)
            for _ in range(random.randint(0, 3))}


def json_key_values(depth=0):
    entries = []
    for _ in range(random.randint(0, 3)):
        entry = {}
        if random.random() < 0.9:
            entry["key"] = random.choice(["k", "k2", "", None, 5, {"stringValue": "w"},
                                          {"intValue": 1}])
        if random.random() < 0.85:
            if random.random() < 0.2:
                entry["value"] = random.choice([{}, json_any_value(depth + 1), "plain"])
            elif random.random() < 0.3:
                entry["value"] = json_any_value(depth + 1)
            else:
                entry["value"] = {random.choice(JSON_WRAPPERS[:7]): json_scalar()}
        entries.append(entry if random.random() < 0.95 else json_scalar())
    return entries


def json_log_record():
    fields = [
        ("timeUnixNano", lambda: random.choice(["1640995200000000000", "", 1640995200000000000,
                                                -1, 1.5, "9x", "99999999999999999999999"])),
        ("observedTimeUnixNano", lambda: random.choice(["5", "x", 5, ""])),
        ("severityNumber", json_scalar),
        ("severityText", json_scalar),
        ("attributes", lambda: random.choice([json_key_values(), {}, json_scalar()])),
        ("droppedAttributesCount", json_scalar),
        ("traceId", lambda: random.choice(["", "0123456789abcdef0123456789abcdef", "zz", 5,
                                           "0123456789abcdef0123456789abcdeg"])),
        ("spanId", lambda: random.choice(["", "0123456789abcdef", "0123", None])),
        ("flags", json_scalar),
        ("eventName", json_scalar),
        ("body", lambda: random.choice([json_any_value(), json_any_value(), {}, json_scalar()])),
    ]
    record = {}
    for name, generate in fields:
        if random.random() < 0.45:
            record[name] = generate()
    return record if random.random() < 0.97 else json_scalar()


def json_scope_logs():
    scope_logs = {}
    if random.random() < 0.5:
        scope_logs["scope"] = random.choice([
            {"name": json_scalar(), "version": json_scalar(),
             "attributes": random.choice([json_key_values(), {}, []]),
             "droppedAttributesCount": json_scalar()},
            {}, json_scalar()])
    if random.random() < 0.3:
        scope_logs["schemaUrl"] = json_scalar()
    if random.random() < 0.95:
        if random.random() < 0.1:
            scope_logs["logRecords"] = random.choice([{}, json_scalar()])
        else:
            scope_logs["logRecords"] = [json_log_record() for _ in range(random.randint(0, 3))]
    return scope_logs if random.random() < 0.97 else json_scalar()


def json_resource_logs():
    resource_logs = {}
    if random.random() < 0.5:
        resource_logs["resource"] = random.choice([
            {"attributes": random.choice([json_key_values(), {}]),
             "droppedAttributesCount": json_scalar()},
            json_scalar()])
    if random.random() < 0.3:
        resource_logs["schemaUrl"] = json_scalar()
    if random.random() < 0.97:
        if random.random() < 0.95:
            resource_logs["scopeLogs"] = [json_scope_logs() for _ in range(random.randint(0, 3))]
        else:
            resource_logs["scopeLogs"] = json_scalar()
    return resource_logs if random.random() < 0.97 else json_scalar()


def json_request():
    return {"resourceLogs": [json_resource_logs() for _ in range(random.randint(0, 2))]}


def pb_any_value(value, depth=0):
    choice = random.random()
    if choice < 0.08:
        return
    if depth > 3 or choice < 0.55:
        field = random.choice(["string_value", "bool_value", "int_value", "double_value",
                               "bytes_value"])
        setattr(value, field, {
            "string_value": random.choice(["", "s", "x" * 40]),
            "bool_value": random.choice([True, False]),
            "int_value": random.choice([0, 1, -1, 2**62, -(2**63)]),
            "double_value": random.choice([0.0, -1.5, 1e300]),
            "bytes_value": random.choice([b"", b"\x00\xff", b"abc"]),
        }[field])
        return
    if choice < 0.78:
        for _ in range(random.randint(0, 3)):
            pb_any_value(value.array_value.values.add(), depth + 1)
        if not value.array_value.values and random.random() < 0.5:
            value.array_value.SetInParent()
        return
    pb_key_values(value.kvlist_value.values, depth + 1)
    if not value.kvlist_value.values:
        value.kvlist_value.SetInParent()


def pb_key_values(entries, depth=0):
    for _ in range(random.randint(0, 3)):
        entry = entries.add(key=random.choice(["k", "", "key.name", "k"]))
        if random.random() < 0.9:
            pb_any_value(entry.value, depth)


def pb_log_record(record):
    if random.random() < 0.8:
        record.time_unix_nano = random.choice([1640995200000000000, 1, 0])
    if random.random() < 0.5:
        record.observed_time_unix_nano = random.choice([1640995200000000001, 0])
    if random.random() < 0.5:
        record.severity_number = random.choice([0, 9, 24, 25])
    if random.random() < 0.4:
        record.severity_text = random.choice(["", "INFO"])
    if random.random() < 0.7:
        pb_any_value(record.body)
    if random.random() < 0.5:
        pb_key_values(record.attributes)
    if random.random() < 0.3:
        record.dropped_attributes_count = random.randint(0, 3)
    if random.random() < 0.3:
        record.flags = random.choice([0, 1, 257])
    if random.random() < 0.3:
        record.trace_id = random.choice([b"", bytes(16), bytes(range(16)), b"\x01" * 8])
    if random.random() < 0.3:
        record.span_id = random.choice([b"", bytes(8), bytes(range(8)), b"\x01" * 4])


def pb_request():
    request = ExportLogsServiceRequest()
    for _ in range(random.randint(0, 2)):
        resource_logs = request.resource_logs.add()
        if random.random() < 0.6:
            pb_key_values(resource_logs.resource.attributes)
            if random.random() < 0.3:
                resource_logs.resource.dropped_attributes_count = random.randint(0, 5)
            if random.random() < 0.2:
                resource_logs.resource.SetInParent()
        if random.random() < 0.3:
            resource_logs.schema_url = random.choice(["", "https://r"])
        for _ in range(random.randint(0, 3)):
            scope_logs = resource_logs.scope_logs.add()
            if random.random() < 0.6:
                scope = scope_logs.scope
                if random.random() < 0.5:
                    scope.name = random.choice(["", "n"])
                if random.random() < 0.5:
                    scope.version = random.choice(["", "1"])
                if random.random() < 0.5:
                    pb_key_values(scope.attributes)
                if random.random() < 0.3:
                    scope.dropped_attributes_count = random.randint(0, 3)
                scope.SetInParent()
            if random.random() < 0.3:
                scope_logs.schema_url = random.choice(["", "https://s"])
            for _ in range(random.randint(0, 3)):
                pb_log_record(scope_logs.log_records.add())
    return request.SerializeToString()


def main():
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    random.seed(int(sys.argv[2]) if len(sys.argv) > 2 else 7)
    directory = os.path.dirname(os.path.abspath(__file__))

    with open(os.path.join(directory, "logs_parity.jsonl"), "w") as output:
        for _ in range(count):
            output.write(json.dumps(json_request()) + "\n")

    with open(os.path.join(directory, "logs_parity.pb"), "wb") as output:
        for _ in range(count):
            request = pb_request()
            output.write(struct.pack("<I", len(request)))
            output.write(request)


if __name__ == "__main__":
    main()
