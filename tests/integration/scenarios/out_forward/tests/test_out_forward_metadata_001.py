import os
import socket
import time

import pytest

from server.forward_server import (
    data_storage as forward_data_storage,
    forward_server_run,
    forward_server_stop,
)
from utils.fluent_bit_manager import FluentBitManager
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
            wait_for_port_to_be_free(self.capture_port, timeout=10 if os.environ.get("VALGRIND") else 5)
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
        messages = service.wait_for_forward_messages(1, timeout=20 if os.environ.get("VALGRIND") else 10)
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
