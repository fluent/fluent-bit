import base64
import os
import socket
import time

import pytest

from server.forward_server import (
    data_storage as forward_data_storage,
    forward_server_run,
    forward_server_stop,
)
from utils.data_utils import read_file
from utils.fluent_bit_manager import FluentBitManager
from utils.memory_check import memory_check_enabled
from utils.network import find_available_port, wait_for_port_to_be_free


TEST_TAG = "test"
TEST_TS = 1234567890
SECURE_SHARED_KEY = "integration-secret"


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
    return b"\xDA" + length.to_bytes(2, "big") + data


def _pack_obj(value):
    if isinstance(value, int):
        return _pack_uint(value)
    if isinstance(value, str):
        return _pack_str(value)
    if isinstance(value, list):
        return bytes([0x90 | len(value)]) + b"".join(_pack_obj(item) for item in value)
    if isinstance(value, dict):
        encoded = []
        for key, item in value.items():
            encoded.append(_pack_obj(key))
            encoded.append(_pack_obj(item))
        return bytes([0x80 | len(value)]) + b"".join(encoded)
    raise TypeError(f"Unsupported value type {type(value)!r}")


def _send_message(port, message):
    payload = _pack_obj([TEST_TAG, TEST_TS, {"message": message}])
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(payload)


class SecureForwardChain:
    """
    Fluent Bit sender (out_forward + shared_key) -> python secure forward
    receiver.
    """

    def __init__(self, *, corrupt_pong_digest=False):
        config_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../config"))
        self.sender_config_file = os.path.join(config_dir, "out_forward_secure_sender.yaml")
        self.corrupt_pong_digest = corrupt_pong_digest
        self.sender = None
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

        self._set_env("FORWARD_SECURE_SENDER_PORT", self.sender_port)
        self._set_env("FORWARD_SECURE_RECEIVER_PORT", self.receiver_port)

        forward_server_run(
            self.receiver_port,
            shared_key=SECURE_SHARED_KEY,
            corrupt_pong_digest=self.corrupt_pong_digest,
        )

        self.sender = FluentBitManager(self.sender_config_file)
        self.sender.start()

    def stop(self):
        try:
            if self.sender:
                self.sender.stop()
        finally:
            forward_server_stop()
            wait_for_port_to_be_free(
                self.receiver_port,
                timeout=10 if memory_check_enabled() else 5,
            )
            self._restore_env()

    def wait_for_forward_messages(self, minimum_count, timeout=10):
        deadline = time.time() + timeout
        while time.time() < deadline:
            messages = forward_data_storage["messages"]
            if len(messages) >= minimum_count:
                return messages
            time.sleep(0.2)
        raise TimeoutError(f"Timed out waiting for {minimum_count} captured forward messages")

    def wait_for_handshakes(self, minimum_count, timeout=10):
        deadline = time.time() + timeout
        while time.time() < deadline:
            handshakes = forward_data_storage["handshakes"]
            if len(handshakes) >= minimum_count:
                return handshakes
            time.sleep(0.2)
        raise TimeoutError(f"Timed out waiting for {minimum_count} secure forward handshakes")

    def wait_for_sender_log(self, text, timeout=10):
        deadline = time.time() + timeout
        while time.time() < deadline:
            log_text = read_file(self.sender.log_file)
            if text in log_text:
                return log_text
            time.sleep(0.2)
        raise TimeoutError(f"Timed out waiting for sender log text {text!r}")


def test_out_forward_secure_handshake_delivers_records():
    chain = SecureForwardChain()
    chain.start()

    try:
        _send_message(chain.sender_port, "secure-forward-e2e")
        messages = chain.wait_for_forward_messages(
            1, timeout=20 if memory_check_enabled() else 10
        )
        handshakes = chain.wait_for_handshakes(1)
    finally:
        chain.stop()

    # The client proved the shared_key in PING:
    # sha512_hex(shared_key_salt + client_hostname + nonce + shared_key)
    assert handshakes[0]["client_hostname"] == "sender-node"
    assert handshakes[0]["client_digest_valid"] is True

    message = messages[0]
    assert message["tag"] == TEST_TAG
    assert message["options"]["fluent_signal"] == 0
    assert message["records"][0]["body"]["message"] == "secure-forward-e2e"

    # 'chunk' must be a Base64 representation of a 128 bits unique id
    chunk = message["options"]["chunk"]
    assert len(chunk) == 24
    decoded = base64.b64decode(chunk, validate=True)
    assert len(decoded) == 16


def test_out_forward_secure_handshake_rejects_wrong_server_digest():
    chain = SecureForwardChain(corrupt_pong_digest=True)
    chain.start()

    try:
        _send_message(chain.sender_port, "secure-forward-reject")

        # The client must attempt the handshake and reject the PONG
        chain.wait_for_handshakes(1)
        chain.wait_for_sender_log("digest mismatch", timeout=15)

        # No event data may be accepted by the (impostor) server
        with pytest.raises(TimeoutError):
            chain.wait_for_forward_messages(1, timeout=3)
    finally:
        chain.stop()
