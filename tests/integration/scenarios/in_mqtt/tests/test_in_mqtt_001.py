import os
import socket
import time

import requests

from server.http_server import data_storage, http_server_run
from utils.test_service import FluentBitTestService


MQTT_CONNECT_PACKET = bytes(
    [0x10, 0x0A, 0x00, 0x04, ord("M"), ord("Q"), ord("T"), ord("T"), 0x04, 0xCE, 0x00, 0x0A]
)
MQTT_TRUNCATED_QOS1_PUBLISH_PACKET = bytes([0x32, 0x04, 0x00, 0x01, ord("X"), 0x00])
MQTT_EMPTY_PUBLISH_PACKET = bytes([0x30, 0x03, 0x00, 0x01, ord("a")])
MQTT_INVALID_TOPIC_LENGTH_PACKET = bytes([0x30, 0x04, 0x00, 0x05, ord("a"), ord("b")])
MQTT_VALID_PAYLOAD = b'{"key":"val"}'
MQTT_INVALID_JSON_PAYLOAD = b'{"key"'


class Service:
    def __init__(self, config_file="in_mqtt.yaml"):
        self.config_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "../config", config_file))
        self.service = FluentBitTestService(
            self.config_file,
            data_storage=data_storage,
            data_keys=["payloads"],
            pre_start=self._start_receiver,
            post_stop=self._stop_receiver,
        )

    def _start_receiver(self, service):
        http_server_run(service.test_suite_http_port)
        self.service.wait_for_http_endpoint(
            f"http://127.0.0.1:{service.test_suite_http_port}/ping",
            timeout=10,
            interval=0.5,
        )

    def _stop_receiver(self, service):
        try:
            requests.post(f"http://127.0.0.1:{service.test_suite_http_port}/shutdown", timeout=2)
        except requests.RequestException:
            pass

    def start(self):
        self.service.start()
        self.flb_listener_port = self.service.flb_listener_port

    def stop(self):
        self.service.stop()

    def assert_running(self):
        assert self.service.flb.process is not None
        assert self.service.flb.process.poll() is None

    def read_forwarded_payloads(self, timeout=10):
        return self.service.wait_for_condition(
            lambda: data_storage["payloads"] if data_storage["payloads"] else None,
            timeout=timeout,
            interval=0.2,
            description="forwarded mqtt payloads",
        )


def _recv_connack(sock):
    response = sock.recv(4)
    assert response
    assert response[0] == 0x20


def _build_publish_packet(payload, topic=b"a/b"):
    remaining_length = 2 + len(topic) + len(payload)
    return bytes([0x30, remaining_length]) + len(topic).to_bytes(2, "big") + topic + payload


def _assert_record(payloads):
    assert len(payloads) == 1
    assert isinstance(payloads[0], list)
    assert len(payloads[0]) == 1
    record = payloads[0][0]
    assert record["topic"] == "a/b"
    assert record["key"] == "val"


def _assert_payload_key_record(payloads):
    assert len(payloads) == 1
    assert isinstance(payloads[0], list)
    assert len(payloads[0]) == 1
    record = payloads[0][0]
    assert record["topic"] == "a/b"
    assert record["payload_k"]["key"] == "val"


def test_in_mqtt_publish_forwards_json():
    service = Service()
    service.start()

    try:
        with socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=5) as sock:
            sock.sendall(MQTT_CONNECT_PACKET)
            _recv_connack(sock)
            sock.sendall(_build_publish_packet(MQTT_VALID_PAYLOAD))

        payloads = service.read_forwarded_payloads()
    finally:
        service.stop()

    _assert_record(payloads)


def test_in_mqtt_truncated_publish_recovers():
    service = Service()
    service.start()

    try:
        with socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=5) as sock:
            sock.sendall(MQTT_CONNECT_PACKET)
            _recv_connack(sock)
            sock.sendall(MQTT_TRUNCATED_QOS1_PUBLISH_PACKET)

        time.sleep(0.2)
        assert data_storage["payloads"] == []
        service.assert_running()

        with socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=5) as recovery_sock:
            recovery_sock.sendall(MQTT_CONNECT_PACKET)
            _recv_connack(recovery_sock)
            recovery_sock.sendall(_build_publish_packet(MQTT_VALID_PAYLOAD))

        payloads = service.read_forwarded_payloads()
    finally:
        service.stop()

    _assert_record(payloads)


def test_in_mqtt_empty_publish_recovers():
    service = Service()
    service.start()

    try:
        with socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=5) as sock:
            sock.sendall(MQTT_CONNECT_PACKET)
            _recv_connack(sock)
            sock.sendall(MQTT_EMPTY_PUBLISH_PACKET)

            time.sleep(0.2)
            assert data_storage["payloads"] == []
            service.assert_running()

            sock.sendall(_build_publish_packet(MQTT_VALID_PAYLOAD))

        payloads = service.read_forwarded_payloads()
    finally:
        service.stop()

    _assert_record(payloads)


def test_in_mqtt_invalid_topic_length_recovers():
    service = Service()
    service.start()

    try:
        with socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=5) as sock:
            sock.sendall(MQTT_CONNECT_PACKET)
            _recv_connack(sock)
            sock.sendall(MQTT_INVALID_TOPIC_LENGTH_PACKET)

        time.sleep(0.2)
        assert data_storage["payloads"] == []
        service.assert_running()

        with socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=5) as recovery_sock:
            recovery_sock.sendall(MQTT_CONNECT_PACKET)
            _recv_connack(recovery_sock)
            recovery_sock.sendall(_build_publish_packet(MQTT_VALID_PAYLOAD))

        payloads = service.read_forwarded_payloads()
    finally:
        service.stop()

    _assert_record(payloads)


def test_in_mqtt_invalid_json_payload_recovers():
    service = Service()
    service.start()

    try:
        with socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=5) as sock:
            sock.sendall(MQTT_CONNECT_PACKET)
            _recv_connack(sock)
            sock.sendall(_build_publish_packet(MQTT_INVALID_JSON_PAYLOAD))

        time.sleep(0.2)
        assert data_storage["payloads"] == []
        service.assert_running()

        with socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=5) as recovery_sock:
            recovery_sock.sendall(MQTT_CONNECT_PACKET)
            _recv_connack(recovery_sock)
            recovery_sock.sendall(_build_publish_packet(MQTT_VALID_PAYLOAD))

        payloads = service.read_forwarded_payloads()
    finally:
        service.stop()

    _assert_record(payloads)


def test_in_mqtt_payload_key_wraps_payload():
    service = Service("in_mqtt_payload_key.yaml")
    service.start()

    try:
        with socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=5) as sock:
            sock.sendall(MQTT_CONNECT_PACKET)
            _recv_connack(sock)
            sock.sendall(_build_publish_packet(MQTT_VALID_PAYLOAD))

        payloads = service.read_forwarded_payloads()
    finally:
        service.stop()

    _assert_payload_key_record(payloads)
