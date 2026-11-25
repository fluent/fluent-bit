import os
import socket
import struct
from pathlib import Path

import yaml
import time

import pytest

from server.forward_server import (
    data_storage as forward_data_storage,
    forward_server_run,
    forward_server_stop,
)
from utils.fluent_bit_manager import FluentBitManager
from utils.memory_check import memory_check_enabled
from utils.network import find_available_port, wait_for_port_to_be_free


TEST_TAG = "test"
TEST_TS = 1234567890
TEST_METADATA = {"source": "suite", "scope": "out_forward"}


class FluentBitForwardChain:
    def __init__(self, sender_config_file):
        self.config_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../config"))
        self.sender_config_file = os.path.join(self.config_dir, sender_config_file)
        self.receiver_config_file = os.path.join(self.config_dir, "out_forward_metadata_receiver.yaml")
        self.sender = None
        self.receiver = None
        self.previous_env = {}

    def _set_env(self, key, value):
        self.previous_env.setdefault(key, os.environ.get(key))
        os.environ[key] = str(value)

    def _restore_env(self):
        for key, value in self.previous_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.previous_env.clear()

    def start(self):
        self.sender_port = find_available_port()
        self.receiver_port = find_available_port()
        self.capture_port = find_available_port()

        self._set_env("FORWARD_METADATA_SENDER_PORT", self.sender_port)
        self._set_env("FORWARD_METADATA_RECEIVER_PORT", self.receiver_port)
        self._set_env("FORWARD_METADATA_CAPTURE_PORT", self.capture_port)

        forward_server_run(self.capture_port)

        self.receiver = FluentBitManager(self.receiver_config_file)
        self.receiver.start()

        time.sleep(1)

        self.sender = FluentBitManager(self.sender_config_file)
        self.sender.start()

    def stop(self):
        try:
            if self.sender:
                self.sender.stop()
            if self.receiver:
                self.receiver.stop()
        finally:
            forward_server_stop()
            timeout = 10 if memory_check_enabled() else 5
            wait_for_port_to_be_free(self.capture_port, timeout=timeout)
            self._restore_env()

    def wait_for_forward_messages(self, minimum_count, timeout=10):
        deadline = time.time() + timeout
        while time.time() < deadline:
            messages = forward_data_storage["messages"]
            if len(messages) >= minimum_count:
                return messages
            time.sleep(0.2)
        raise TimeoutError(f"Timed out waiting for {minimum_count} captured forward messages")


def _pack_uint(value):
    if value < 0x80:
        return bytes([value])
    if value <= 0xFF:
        return b"\xCC" + bytes([value])
    if value <= 0xFFFF:
        return b"\xCD" + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return b"\xCE" + value.to_bytes(4, "big")
    return b"\xCF" + value.to_bytes(8, "big")


def _pack_str(value):
    data = value.encode()
    length = len(data)
    if length <= 31:
        return bytes([0xA0 | length]) + data
    if length <= 0xFF:
        return b"\xD9" + bytes([length]) + data
    if length <= 0xFFFF:
        return b"\xDA" + length.to_bytes(2, "big") + data
    return b"\xDB" + length.to_bytes(4, "big") + data


def _pack_array(items):
    length = len(items)
    if length <= 15:
        prefix = bytes([0x90 | length])
    elif length <= 0xFFFF:
        prefix = b"\xDC" + length.to_bytes(2, "big")
    else:
        prefix = b"\xDD" + length.to_bytes(4, "big")
    return prefix + b"".join(_pack_obj(item) for item in items)


def _pack_map(mapping):
    items = list(mapping.items())
    length = len(items)
    if length <= 15:
        prefix = bytes([0x80 | length])
    elif length <= 0xFFFF:
        prefix = b"\xDE" + length.to_bytes(2, "big")
    else:
        prefix = b"\xDF" + length.to_bytes(4, "big")

    encoded = []
    for key, value in items:
        encoded.append(_pack_obj(key))
        encoded.append(_pack_obj(value))
    return prefix + b"".join(encoded)


def _pack_obj(value):
    if isinstance(value, tuple) and value[0] == "__ext__":
        return b"\xd7" + bytes([value[1]]) + value[2]
    if isinstance(value, bytes):
        return b"\xc6" + struct.pack(">I", len(value)) + value
    if isinstance(value, int):
        return _pack_uint(value)
    if isinstance(value, str):
        return _pack_str(value)
    if isinstance(value, list):
        return _pack_array(value)
    if isinstance(value, dict):
        return _pack_map(value)
    raise TypeError(f"Unsupported value type {type(value)!r}")


def _send_log_event_with_metadata(port, message):
    payload = _pack_obj(
        [
            TEST_TAG,
            TEST_TS,
            {"message": message},
            {"metadata": TEST_METADATA, "chunk": f"{message}-chunk"},
        ]
    )
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(payload)


def _capture_record(sender_config_file, message):
    service = FluentBitForwardChain(sender_config_file)
    service.start()

    try:
        _send_log_event_with_metadata(service.sender_port, message)
        timeout = 20 if memory_check_enabled() else 10
        messages = service.wait_for_forward_messages(1, timeout=timeout)
    finally:
        service.stop()

    assert messages[0]["mode"] == "forward"
    assert messages[0]["tag"] == TEST_TAG
    assert messages[0]["options"]["fluent_signal"] == 0
    assert messages[0]["options"]["size"] == 1
    return messages[0]["records"][0]


@pytest.mark.parametrize(
    "sender_config_file",
    [
        "out_forward_metadata_sender_default.yaml",
        "out_forward_metadata_sender_true.yaml",
    ],
)
def test_out_forward_fluent_bit_to_fluent_bit_preserves_metadata(sender_config_file):
    record = _capture_record(sender_config_file, sender_config_file)

    assert record["body"]["message"] == sender_config_file
    assert record["metadata"] == TEST_METADATA
    assert len(record["raw"]) == 2
    assert len(record["raw"][0]) == 2
    assert record["raw"][0][1] == TEST_METADATA


def test_out_forward_fluent_bit_to_fluent_bit_opt_out_drops_metadata():
    record = _capture_record("out_forward_metadata_sender_false.yaml", "metadata-opt-out")

    assert record["body"]["message"] == "metadata-opt-out"
    assert not record["metadata"]
    assert len(record["raw"]) == 2
    assert not record["raw"][0][1]
    assert record["raw"][1] == {"message": "metadata-opt-out"}


@pytest.mark.parametrize("ack", [False, True])
@pytest.mark.parametrize("integer_time", [False, True])
def test_dynamic_tags_preserve_groups_across_forward_hop(tmp_path, ack, integer_time):
    config_dir = Path(__file__).parent.parent / "config"
    sender = yaml.safe_load((config_dir / "out_forward_metadata_sender_default.yaml").read_text())
    sender["pipeline"]["outputs"][0].update(
        tag="$route", match="*", require_ack_response=ack, time_as_integer=integer_time, workers=1)
    receiver = yaml.safe_load((config_dir / "out_forward_metadata_receiver.yaml").read_text())
    # The capture server services one persistent connection at a time.
    receiver["pipeline"]["outputs"][0].update({"match": "*", "workers": 1, "net.keepalive": False})
    sender_path = tmp_path / "sender.yaml"
    receiver_path = tmp_path / "receiver.yaml"
    sender_path.write_text(yaml.safe_dump(sender))
    receiver_path.write_text(yaml.safe_dump(receiver))
    service = FluentBitForwardChain(str(sender_path))
    service.receiver_config_file = str(receiver_path)
    start_time = ("__ext__", 0, struct.pack(">II", 0xFFFFFFFF, 0))
    end_time = ("__ext__", 0, struct.pack(">II", 0xFFFFFFFE, 0))
    timestamp = ("__ext__", 0, struct.pack(">II", TEST_TS, 123456789))
    records = []
    for group in range(2):
        records.append([[start_time, {"schema": "otlp", "identity": group}],
                        {"resource": {"name": f"resource-{group}"},
                         "scope": {"name": f"scope-{group}"}}])
        for index in range(2):
            records.append([[timestamp, {"otlp": {"severity_number": 9}}],
                            {"route": f"route.{index}", "message": f"group-{group}-{index}"}])
        records.append([[end_time, {}], {}])
    records.append([[timestamp, {"native": "keep"}],
                    {"route": "route.ungrouped", "message": "ungrouped"}])
    payload = _pack_obj([TEST_TAG, b"".join(_pack_obj(record) for record in records), {}])
    service.start()
    try:
        with socket.create_connection(("127.0.0.1", service.sender_port), timeout=5) as sock:
            sock.sendall(payload)
        deadline = time.time() + (30 if memory_check_enabled() else 15)
        while time.time() < deadline:
            captured = [record for msg in forward_data_storage["messages"]
                        for record in msg["records"] if "message" in record.get("body", {})]
            if len(captured) >= 5:
                break
            time.sleep(0.2)
        messages = list(forward_data_storage["messages"])
    finally:
        service.stop()
    seen = set()
    for message in messages:
        group_metadata = None
        group_attributes = None
        for record in message["records"]:
            ts = record["timestamp"]
            seconds, nanos = (struct.unpack(">II", ts["__ext__"]["data"])
                              if isinstance(ts, dict) else (ts, 0))
            if seconds == 0xFFFFFFFF:
                group_metadata, group_attributes = record["metadata"], record["body"]
                continue
            if seconds == 0xFFFFFFFE:
                group_metadata = group_attributes = None
                continue
            body = record["body"]
            seen.add(body["message"])
            assert message["tag"] == body["route"]
            assert seconds == TEST_TS
            assert nanos == (0 if integer_time else 123456789)
            if body["message"] == "ungrouped":
                assert group_metadata is None and record["metadata"] == {"native": "keep"}
            else:
                group = int(body["message"].split("-")[1])
                assert group_metadata == {"schema": "otlp", "identity": group}
                assert group_attributes == {"resource": {"name": f"resource-{group}"},
                                            "scope": {"name": f"scope-{group}"}}
                assert record["metadata"] == {"otlp": {"severity_number": 9}}
    assert seen == {"group-0-0", "group-0-1", "group-1-0", "group-1-1", "ungrouped"}
