import json
import struct
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import requests
import yaml
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

from server.kafka_server import data_storage
from server.schema_registry_server import data_storage as registry_data
from test_out_kafka_001 import Service, _wait_for_log_text
from utils.fluent_bit_manager import FluentBitStartupError
from utils.fluent_bit_manager import fluent_bit_output_supports_config_property


@pytest.fixture(autouse=True, scope="module")
def require_protobuf_encoder():
    if not fluent_bit_output_supports_config_property("kafka", "protobuf_message"):
        pytest.skip("Kafka Protobuf Schema Registry requires FLB_PROTOBUF_ENCODER=On")


DETAILS = '''syntax = "proto3"; package registry;
message Details { int64 count = 1; enum Kind { UNKNOWN = 0; ACTIVE = 1; } Kind kind = 2; }
'''
ROOT = '''syntax = "proto3"; package registry; import "details.proto";
message Placeholder {}
message Envelope {
  map<string, string> labels = 1;
  message Placeholder {}
  message Event {
    string message = 1;
    Details details = 2;
    repeated sint64 values = 3;
    bytes raw = 4;
    map<string, int32> counts = 5;
    oneof choice { string text = 6; int32 number = 7; }
  }
}
'''
EVENT = {
    "message": "hello protobuf",
    "details": {"count": "9223372036854775807", "kind": "ACTIVE"},
    "values": ["-9223372036854775808", "9223372036854775807"],
    "raw": "AAEC/w==",
    "counts": {"a": 1},
    "number": 7,
}


def _response(schema, *, schema_id=42, references=None):
    return 200, {"id": schema_id, "schemaType": "PROTOBUF", "schema": schema,
                 "references": references or []}


def _responses():
    return {
        "/subjects/events-value/versions/3": _response(
            ROOT, references=[{"name": "details.proto", "subject": "details-value", "version": 2}]),
        "/subjects/details-value/versions/2": _response(DETAILS, schema_id=17),
    }


def _service(tmp_path, *, responses=None, event=None, tls=False, samples=3):
    config = yaml.safe_load((Path(__file__).parent / "../config/out_kafka_avro_schema_registry.yaml").read_text())
    config["pipeline"]["inputs"][0].update(dummy=json.dumps(EVENT if event is None else event), samples=samples)
    output = config["pipeline"]["outputs"][0]
    output.update(format="protobuf", schema_registry_subject="events-value", schema_registry_version="3",
                  protobuf_message="registry.Envelope.Event", schema_registry_http_user="registry-user",
                  schema_registry_http_passwd="registry-password", workers=2)
    options = {"responses": _responses() if responses is None else responses}
    if tls:
        cert_dir = (Path(__file__).parent / "../../in_splunk/certificate").resolve()
        output.update(schema_registry_url="https://localhost:${TEST_SUITE_SCHEMA_REGISTRY_PORT}",
                      **{"tls": "on", "tls.verify": "on", "tls.ca_file": str(cert_dir / "certificate.pem")})
        options.update(tls_crt_file=str(cert_dir / "certificate.pem"),
                       tls_key_file=str(cert_dir / "private_key.pem"))
    path = tmp_path / "schema_registry.yaml"
    path.write_text(yaml.safe_dump(config))
    return Service(str(path), use_schema_registry=True, schema_registry_options=options)


def _event_class():
    # Independent consumer descriptor; no Fluent Bit encoder code is used for decoding.
    file = descriptor_pb2.FileDescriptorProto(name="consumer.proto", package="consumer", syntax="proto3")
    details = file.message_type.add(name="Details")
    details.field.add(name="count", number=1, type=3, label=1)
    enum = details.enum_type.add(name="Kind")
    enum.value.add(name="UNKNOWN", number=0)
    enum.value.add(name="ACTIVE", number=1)
    details.field.add(name="kind", number=2, type=14, type_name=".consumer.Details.Kind", label=1)
    event = file.message_type.add(name="Event")
    event.field.add(name="message", number=1, type=9, label=1)
    event.field.add(name="details", number=2, type=11, type_name=".consumer.Details", label=1)
    event.field.add(name="values", number=3, type=18, label=3)
    event.field.add(name="raw", number=4, type=12, label=1)
    entry = event.nested_type.add(name="CountsEntry")
    entry.options.map_entry = True
    entry.field.add(name="key", number=1, type=9, label=1)
    entry.field.add(name="value", number=2, type=5, label=1)
    event.field.add(name="counts", number=5, type=11, type_name=".consumer.Event.CountsEntry", label=3)
    event.oneof_decl.add(name="choice")
    event.field.add(name="text", number=6, type=9, label=1, oneof_index=0)
    event.field.add(name="number", number=7, type=5, label=1, oneof_index=0)
    pool = descriptor_pool.DescriptorPool()
    pool.Add(file)
    return message_factory.GetMessageClass(pool.FindMessageTypeByName("consumer.Event"))


@pytest.mark.parametrize("tls", [False, True], ids=["http", "https"])
def test_protobuf_schema_registry_reference_cache_and_payload(tmp_path, tls):
    service = _service(tmp_path, tls=tls)
    service.start()
    try:
        messages = service.wait_for_messages(3, timeout=30)
    finally:
        service.stop()
    event_class = _event_class()
    for message in messages:
        assert message["topic"] == "test"
        assert message["value"][:8] == bytes([0, 0, 0, 0, 42, 4, 2, 2])
        decoded = event_class.FromString(message["value"][8:])
        assert decoded.message == "hello protobuf"
        assert decoded.details.count == 2**63 - 1
        assert decoded.details.kind == 1
        assert list(decoded.values) == [-(2**63), 2**63 - 1]
        assert decoded.raw == bytes([0, 1, 2, 255])
        assert dict(decoded.counts) == {"a": 1}
        assert decoded.WhichOneof("choice") == "number"
        assert decoded.number == 7
    requests = registry_data["requests"]
    assert [r["path"] for r in requests] == [
        "/subjects/events-value/versions/3", "/subjects/details-value/versions/2"]
    assert all(r["method"] == "GET" for r in requests)
    assert all(r["headers"]["Authorization"] == "Basic cmVnaXN0cnktdXNlcjpyZWdpc3RyeS1wYXNzd29yZA=="
               for r in requests)


@pytest.mark.parametrize("event", [
    {**EVENT, "unexpected": "value"},
    {**EVENT, "number": 2**31},
    {**EVENT, "text": "conflicting oneof"},
])
def test_protobuf_schema_registry_rejects_invalid_event(tmp_path, event):
    """Reject invalid Protobuf data with a payload-free schema mismatch diagnostic."""
    service = _service(tmp_path, event=event, samples=1)
    service.start()
    try:
        _wait_for_log_text(service.flb.log_file,
                           "cannot encode Protobuf event: JSON does not match Protobuf schema", timeout=30)
    finally:
        service.stop()
    assert data_storage["messages"] == []


@pytest.mark.parametrize("failure", ["missing_import", "conflicting_reference", "invalid_schema"])
def test_protobuf_schema_registry_rejects_invalid_graph(tmp_path, failure):
    responses = _responses()
    root = responses["/subjects/events-value/versions/3"][1]
    if failure == "missing_import":
        root["references"] = []
    elif failure == "conflicting_reference":
        root["references"].append({"name": "details.proto", "subject": "different", "version": 2})
    else:
        root["schema"] = "invalid proto schema"
    service = _service(tmp_path, responses=responses, samples=1)
    service.start()
    try:
        _wait_for_log_text(service.flb.log_file, "cannot load Schema Registry schema", timeout=30)
    finally:
        service.stop()
    assert data_storage["messages"] == []


def test_protobuf_schema_registry_retries_reference_without_partial_cache(tmp_path):
    responses = _responses()
    child_path = "/subjects/details-value/versions/2"
    responses[child_path] = [(503, {"error_code": 50001}), responses[child_path]]
    service = _service(tmp_path, responses=responses)
    service.start()
    try:
        messages = service.wait_for_messages(3, timeout=30)
    finally:
        service.stop()
    assert all(m["value"][:8] == bytes([0, 0, 0, 0, 42, 4, 2, 2]) for m in messages)
    paths = [r["path"] for r in registry_data["requests"]]
    assert paths.count("/subjects/events-value/versions/3") == 2
    assert paths.count(child_path) == 2


@pytest.mark.parametrize("body", [
    pytest.param(b"{invalid json", id="malformed"),
    pytest.param([], id="array"),
    pytest.param(None, id="null"),
    pytest.param({"error_code": 50001, "message": "unhealthy registry"}, id="error-envelope"),
    pytest.param({**_response(DETAILS)[1], "schemaType": "AVRO"}, id="wrong-type"),
    pytest.param({**_response(DETAILS)[1], "schema": ""}, id="empty-schema"),
    pytest.param({**_response(DETAILS)[1], "id": 0}, id="invalid-id"),
    pytest.param({**_response(DETAILS)[1], "references": {}}, id="invalid-references"),
    pytest.param({**_response(DETAILS)[1], "references": [
        {"name": "child.proto", "subject": "child", "version": "2"}]}, id="invalid-reference-version"),
])
@pytest.mark.parametrize("reference", [False, True], ids=["root", "reference"])
def test_protobuf_schema_registry_invalid_body_failover(tmp_path, body, reference):
    responses = _responses()
    failed_path = ("/subjects/details-value/versions/2" if reference
                   else "/subjects/events-value/versions/3")
    responses.update({"/healthy" + path: response for path, response in list(responses.items())})
    responses[failed_path] = (200, body)
    service = _service(tmp_path, responses=responses)
    path = Path(service.config_file)
    config = yaml.safe_load(path.read_text())
    config["pipeline"]["outputs"][0]["schema_registry_url"] = (
        "http://127.0.0.1:${TEST_SUITE_SCHEMA_REGISTRY_PORT},"
        "http://127.0.0.1:${TEST_SUITE_SCHEMA_REGISTRY_PORT}/healthy")
    path.write_text(yaml.safe_dump(config))
    service.start()
    try:
        messages = service.wait_for_messages(3, timeout=30)
    finally:
        service.stop()
    assert all(m["value"][:8] == bytes([0, 0, 0, 0, 42, 4, 2, 2]) for m in messages)
    paths = [r["path"] for r in registry_data["requests"]]
    assert paths.count(failed_path) == 1
    assert paths.count("/healthy" + failed_path) == 1


def test_protobuf_schema_registry_inline_schema_requires_selector(tmp_path):
    service = _service(tmp_path)
    path = Path(service.config_file)
    config = yaml.safe_load(path.read_text())
    output = config["pipeline"]["outputs"][0]
    output.pop("schema_registry_subject")
    output.pop("schema_id", None)
    output["schema_str"] = ROOT
    path.write_text(yaml.safe_dump(config))
    with pytest.raises(FluentBitStartupError):
        service.start()
    log = Path(service.service.flb.log_file).read_text()
    assert "schema_registry_url requires schema_id or schema_registry_subject" in log
    assert registry_data["requests"] == []


def test_schema_registry_concurrent_response_sequence(tmp_path):
    responses = _responses()
    responses["/sequence"] = [(503, {"retry": True}), (200, {"ready": True})]
    service = _service(tmp_path, responses=responses, samples=1)
    service.start()
    try:
        url = f"http://127.0.0.1:{service.schema_registry_port}/sequence"

        def fetch(_):
            response = requests.get(url, timeout=10)
            return response.status_code, response.json()

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(fetch, range(32)))
        assert results.count((503, {"retry": True})) == 1
        assert results.count((200, {"ready": True})) == 31
        service.wait_for_messages(1, timeout=30)
    finally:
        service.stop()


@pytest.mark.parametrize("by_id", [False, True], ids=["subject", "id"])
def test_protobuf_schema_registry_optional_response_ids(tmp_path, by_id):
    responses = _responses()
    responses["/subjects/details-value/versions/2"][1].pop("id")
    if by_id:
        root = responses.pop("/subjects/events-value/versions/3")
        root[1].pop("id")
        responses["/schemas/ids/42"] = root
    service = _service(tmp_path, responses=responses, samples=1)
    if by_id:
        path = Path(service.config_file)
        config = yaml.safe_load(path.read_text())
        output = config["pipeline"]["outputs"][0]
        output.pop("schema_registry_subject")
        output["schema_id"] = 42
        path.write_text(yaml.safe_dump(config))
    service.start()
    try:
        messages = service.wait_for_messages(1, timeout=30)
    finally:
        service.stop()
    assert messages[0]["value"][:8] == bytes([0, 0, 0, 0, 42, 4, 2, 2])


def _http_service(tmp_path, encoding):
    """Build an HTTP-input service with two distinct latest-schema versions."""
    service = _service(tmp_path)
    path = Path(service.config_file)
    config = yaml.safe_load(path.read_text())
    config["service"].update(hot_reload="on", grace=1)
    config["pipeline"]["inputs"] = [{"name": "http", "listen": "127.0.0.1",
        "port": "${FLUENT_BIT_TEST_LISTENER_PORT}", "tag": "out_kafka"}]
    output = config["pipeline"]["outputs"][0]
    output.update(format=encoding, schema_registry_version="latest", workers=0)
    if encoding == "avro":
        output.pop("protobuf_message")
        schema = {"type": "record", "name": "Event", "fields": [
            {"name": "message", "type": "string", "default": "declared"}]}
        first = {"id": 42, "schemaType": "AVRO", "schema": json.dumps(schema)}
    else:
        output["protobuf_message"] = "Event"
        first = {"id": 42, "schemaType": "PROTOBUF",
                 "schema": 'syntax = "proto3"; message Event { string message = 1; }'}
    if encoding == "avro":
        schema["fields"].append({"name": "generation", "type": "int"})
        second = {**first, "id": 43, "schema": json.dumps(schema)}
    else:
        second = {**first, "id": 43, "schema":
                  'syntax = "proto3"; message Event { string message = 1; int32 generation = 2; }'}
    service.schema_registry_options["responses"] = {
        "/subjects/events-value/versions/latest": [(200, first), (200, second)]}
    path.write_text(yaml.safe_dump(config))
    return service


def _post_records(service, records):
    """Submit records together to exercise continued processing within a chunk."""
    response = requests.post(f"http://127.0.0.1:{service.flb_listener_port}/",
                             json=records, timeout=10)
    response.raise_for_status()


@pytest.mark.parametrize("encoding", ["avro", "protobuf"])
def test_registry_rejection_preserves_later_records_and_metrics(tmp_path, encoding):
    """Verify permanent rejection metrics and the exact surviving record payload."""
    service = _http_service(tmp_path, encoding)
    invalid = [{"message": "bad", "extra": 1}, {"message": 123}]
    if encoding == "avro":
        invalid.append({})
    service.start()
    try:
        _post_records(service, invalid + [{"message": "valid"}])
        messages = service.wait_for_messages(1, timeout=30)
        assert len(messages) == 1
        payload = b"\x0avalid" if encoding == "avro" else b"\x00\x0a\x05valid"
        assert messages[0]["value"] == bytes([0, 0, 0, 0, 42]) + payload

        def rejection_metric():
            """Wait for the cmetrics rejection counter to be exported."""
            response = requests.get(
                f"http://127.0.0.1:{service.flb.http_monitoring_port}/api/v2/metrics/prometheus",
                timeout=10)
            response.raise_for_status()
            return [line for line in response.text.splitlines()
                    if line.startswith("fluentbit_kafka_rejected_records_total{")]

        lines = service.service.wait_for_condition(rejection_metric, timeout=15,
                                                   description="Kafka rejection metric")
        assert len(lines) == 1
        assert f'format="{encoding}"' in lines[0]
        assert float(lines[0].split()[-1]) == len(invalid)
    finally:
        service.stop()


@pytest.mark.parametrize("encoding", ["avro", "protobuf"])
def test_registry_latest_cache_refreshes_only_after_hot_reload(tmp_path, encoding):
    """Verify hot reload changes both the schema ID and serialized field layout."""
    service = _http_service(tmp_path, encoding)
    service.start()
    try:
        _post_records(service, {"message": "before"})
        service.wait_for_messages(1, timeout=30)
        _post_records(service, {"message": "cached"})
        messages = service.wait_for_messages(2, timeout=30)
        assert [int.from_bytes(m["value"][1:5], "big") for m in messages] == [42, 42]
        assert len(registry_data["requests"]) == 1
        service.flb.trigger_http_reload()
        service.flb.wait_for_hot_reload_count(1, timeout=30)
        _post_records(service, {"message": "after", "generation": 7})
        messages = service.wait_for_messages(3, timeout=30)
        assert int.from_bytes(messages[-1]["value"][1:5], "big") == 43
        payload = b"\x0aafter\x0e" if encoding == "avro" else b"\x00\x0a\x05after\x10\x07"
        assert messages[-1]["value"] == bytes([0, 0, 0, 0, 43]) + payload
        assert len(registry_data["requests"]) == 2
    finally:
        service.stop()


def test_registry_https_without_tls_rejected_before_request(tmp_path):
    """Reject an HTTPS URL without TLS before sending registry credentials or data."""
    service = _service(tmp_path)
    path = Path(service.config_file)
    config = yaml.safe_load(path.read_text())
    config["pipeline"]["outputs"][0]["schema_registry_url"] = (
        "https://127.0.0.1:${TEST_SUITE_SCHEMA_REGISTRY_PORT}")
    path.write_text(yaml.safe_dump(config))
    with pytest.raises(FluentBitStartupError):
        service.start()
    assert "HTTPS Schema Registry requires tls on" in Path(service.service.flb.log_file).read_text()
    assert registry_data["requests"] == []


def test_avro_wide_nested_map_and_duplicate_rejection(tmp_path):
    """Deliver a wide nested map after rejecting duplicate keys in an earlier record."""
    from test_out_kafka_001 import _decode_avro_long, _decode_avro_string

    service = _http_service(tmp_path, "avro")
    schema = {"type": "record", "name": "Wide", "fields": [
        {"name": "labels", "type": {"type": "map", "values": "int"}}]}
    service.schema_registry_options["responses"] = {
        "/subjects/events-value/versions/latest": (200, {
            "id": 42, "schemaType": "AVRO", "schema": json.dumps(schema)})}
    labels = {f"k{i}": 0 for i in range(100000)}
    # Keep duplicate keys in the JSON input, including the valid empty map key.
    payload = '[{"labels":{"":0,"":1}},' + json.dumps({"labels": labels}) + ']'
    service.start()
    try:
        response = requests.post(f"http://127.0.0.1:{service.flb_listener_port}/",
                                 data=payload, headers={"Content-Type": "application/json"},
                                 timeout=10)
        response.raise_for_status()
        messages = service.wait_for_messages(1, timeout=30)
        _wait_for_log_text(service.flb.log_file, "permanently rejected avro record", timeout=10)
        assert len(messages) == 1
        encoded = messages[0]["value"]
        assert encoded[:5] == bytes([0, 0, 0, 0, 42])
        count, offset = _decode_avro_long(encoded, 5)
        decoded = {}
        while count:
            if count < 0:
                count = -count
                _, offset = _decode_avro_long(encoded, offset)
            for _ in range(count):
                key, offset = _decode_avro_string(encoded, offset)
                value, offset = _decode_avro_long(encoded, offset)
                decoded[key] = value
            count, offset = _decode_avro_long(encoded, offset)
        assert decoded == labels
        assert offset == len(encoded)
    finally:
        service.stop()


@pytest.mark.parametrize("count,optional", [(1500, None), (5000, "present")])
def test_avro_expanding_payload_double_and_union(tmp_path, count, optional):
    """Grow the wire buffer for expanding integers and decode double/union fields."""
    from test_out_kafka_001 import _decode_avro_long, _decode_avro_string

    service = _http_service(tmp_path, "avro")
    schema = {"type": "record", "name": "Expanded", "fields": [
        {"name": "numbers", "type": {"type": "array", "items": "int"}},
        {"name": "optional", "type": ["null", "string"]},
        {"name": "value", "type": "double"}]}
    service.schema_registry_options["responses"] = {
        "/subjects/events-value/versions/latest": (200, {
            "id": 42, "schemaType": "AVRO", "schema": json.dumps(schema)})}
    service.start()
    try:
        _post_records(service, {"numbers": [64] * count, "optional": optional, "value": 1.5})
        messages = service.wait_for_messages(1, timeout=30)
        encoded = messages[0]["value"]
        assert encoded[:5] == bytes([0, 0, 0, 0, 42])
        block, offset = _decode_avro_long(encoded, 5)
        decoded = []
        while block:
            if block < 0:
                block = -block
                _, offset = _decode_avro_long(encoded, offset)
            for _ in range(block):
                value, offset = _decode_avro_long(encoded, offset)
                decoded.append(value)
            block, offset = _decode_avro_long(encoded, offset)
        assert decoded == [64] * count
        branch, offset = _decode_avro_long(encoded, offset)
        assert branch == (0 if optional is None else 1)
        if optional is not None:
            value, offset = _decode_avro_string(encoded, offset)
            assert value == optional
        assert struct.unpack("<d", encoded[offset:])[0] == 1.5
    finally:
        service.stop()


def test_avro_invalid_schema_is_permanently_rejected(tmp_path):
    """An invalid cached schema must reject records instead of retrying forever."""
    service = _http_service(tmp_path, "avro")
    service.schema_registry_options["responses"] = {
        "/subjects/events-value/versions/latest": (200, {
            "id": 42, "schemaType": "AVRO", "schema": '"invalid-type"'})}
    service.start()
    try:
        _post_records(service, {"message": "invalid schema"})
        _wait_for_log_text(service.flb.log_file, "permanently rejected avro record", timeout=30)
        assert data_storage["messages"] == []
        assert len(registry_data["requests"]) == 1
    finally:
        service.stop()


@pytest.mark.parametrize("null_first", [True, False])
def test_avro_named_union_branch(tmp_path, null_first):
    """Resolve named record branches while preserving null and wire branch indexes."""
    service = _http_service(tmp_path, "avro")
    branches = ["null", "Address"] if null_first else ["Address", "null"]
    schema = {"type": "record", "name": "Person", "fields": [
        {"name": "home", "type": {"type": "record", "name": "Address", "fields": [
            {"name": "city", "type": "string"}]}},
        {"name": "other", "type": branches}]}
    service.schema_registry_options["responses"] = {
        "/subjects/events-value/versions/latest": (200, {
            "id": 42, "schemaType": "AVRO", "schema": json.dumps(schema)})}
    service.start()
    try:
        _post_records(service, [
            {"home": {"city": "A"}, "other": 7},
            {"home": {"city": "A"}, "other": {"city": "B"}},
            {"home": {"city": "A"}, "other": None}])
        messages = service.wait_for_messages(2, timeout=30)
        prefix = bytes([0, 0, 0, 0, 42, 2]) + b"A"
        assert [m["value"] for m in messages] == [
            prefix + bytes([2 if null_first else 0, 2]) + b"B",
            prefix + bytes([0 if null_first else 2])]
        _wait_for_log_text(service.flb.log_file, "permanently rejected avro record", timeout=10)
    finally:
        service.stop()
