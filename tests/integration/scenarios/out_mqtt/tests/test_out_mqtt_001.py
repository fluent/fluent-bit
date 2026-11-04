import json
import os
import re
import socket
import ssl
import threading
import time

import pytest
import requests

from utils.fluent_bit_manager import FluentBitManager, FluentBitStartupError
from utils.memory_check import memory_check_enabled
from utils.test_service import FluentBitTestService


CONNECT = 1
PUBLISH = 3
PUBACK = 4
PUBREC = 5
PUBREL = 6
PUBCOMP = 7
PINGREQ = 12
DISCONNECT = 14

# flb + 12 hex digits (output instance) + 8 hex digits (connection sequence)
GENERATED_CLIENT_ID = re.compile(r"^flb([0-9a-f]{12})([0-9a-f]{8})$")

# Logged by the engine when a flush returns FLB_RETRY
RETRY_LOG = "failed to flush chunk"

BROKER_PUBLISH_ID = 0x1234


def scaled(timeout):
    """Wait longer when Fluent Bit runs under Valgrind or Leaks."""
    if memory_check_enabled():
        return max(timeout * 3, 60)
    return timeout


class MqttProtocolError(Exception):
    pass


def _read_exact(conn, buf, size):
    while len(buf) < size:
        chunk = conn.recv(4096)
        if not chunk:
            raise EOFError("connection closed by the client")
        buf.extend(chunk)


def read_packet(conn, buf):
    """
    Read the next MQTT control packet, extra bytes stay in 'buf'. Returns
    the packet type, the flags, the body and the size of the Remaining Length.
    """
    _read_exact(conn, buf, 2)

    length = 0
    multiplier = 1
    pos = 1
    while True:
        _read_exact(conn, buf, pos + 1)
        byte = buf[pos]
        length += (byte & 0x7F) * multiplier
        pos += 1
        if not byte & 0x80:
            break
        if pos > 4:
            raise MqttProtocolError("malformed remaining length")
        multiplier *= 128

    _read_exact(conn, buf, pos + length)
    packet_type = buf[0] >> 4
    flags = buf[0] & 0x0F
    body = bytes(buf[pos : pos + length])
    del buf[: pos + length]

    return packet_type, flags, body, pos - 1


def encode_length(length):
    out = bytearray()
    while True:
        byte = length % 128
        length //= 128
        if length:
            byte |= 0x80
        out.append(byte)
        if not length:
            return bytes(out)


def read_string(body, pos):
    if pos + 2 > len(body):
        raise MqttProtocolError("truncated string length")
    size = int.from_bytes(body[pos : pos + 2], "big")
    pos += 2
    if pos + size > len(body):
        raise MqttProtocolError("truncated string")
    return body[pos : pos + size], pos + size


def decode_utf8(value, what):
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MqttProtocolError(f"invalid UTF-8 in {what}") from exc


def parse_connect(flags, body):
    if flags != 0:
        raise MqttProtocolError("invalid CONNECT fixed header flags")

    name, pos = read_string(body, 0)
    if pos + 4 > len(body):
        raise MqttProtocolError("truncated CONNECT variable header")
    level = body[pos]
    connect_flags = body[pos + 1]
    keep_alive = int.from_bytes(body[pos + 2 : pos + 4], "big")
    pos += 4

    if connect_flags & 0x01:
        raise MqttProtocolError("reserved CONNECT flag set")
    if connect_flags & 0x04:
        raise MqttProtocolError("unexpected will message")

    client_id, pos = read_string(body, pos)
    username = None
    password = None
    if connect_flags & 0x80:
        username, pos = read_string(body, pos)
    if connect_flags & 0x40:
        password, pos = read_string(body, pos)
    if pos != len(body):
        raise MqttProtocolError("trailing bytes in CONNECT")

    return {
        "protocol": decode_utf8(name, "protocol name"),
        "level": level,
        "clean_session": bool(connect_flags & 0x02),
        "keep_alive": keep_alive,
        "client_id": decode_utf8(client_id, "client identifier"),
        "username": decode_utf8(username, "user name") if username is not None else None,
        "password": decode_utf8(password, "password") if password is not None else None,
    }


def parse_publish(flags, body):
    qos = (flags >> 1) & 0x03
    if qos == 3:
        raise MqttProtocolError("invalid QoS")
    if qos == 0 and flags & 0x08:
        raise MqttProtocolError("DUP flag on a QoS 0 PUBLISH")

    topic, pos = read_string(body, 0)
    topic = decode_utf8(topic, "topic name")
    if not topic or "+" in topic or "#" in topic:
        raise MqttProtocolError(f"invalid topic name {topic!r}")

    packet_id = None
    if qos > 0:
        if pos + 2 > len(body):
            raise MqttProtocolError("truncated packet identifier")
        packet_id = int.from_bytes(body[pos : pos + 2], "big")
        pos += 2
        if packet_id == 0:
            raise MqttProtocolError("packet identifier 0")

    return {
        "topic": topic,
        "qos": qos,
        "retain": bool(flags & 0x01),
        "dup": bool(flags & 0x08),
        "packet_id": packet_id,
        "payload": body[pos:],
    }


def ack(packet_type, packet_id, flags=0):
    return bytes([(packet_type << 4) | flags, 0x02]) + packet_id.to_bytes(2, "big")


def broker_publish_packet(size, qos):
    """A PUBLISH the broker sends on its own, as for a server side subscription."""
    topic = b"broker/notice"
    body = len(topic).to_bytes(2, "big") + topic
    if qos > 0:
        body += BROKER_PUBLISH_ID.to_bytes(2, "big")
    body += b"x" * size
    return bytes([0x30 | (qos << 1)]) + encode_length(len(body)) + body


class FakeBroker:
    """
    MQTT 3.1.1 broker for the tests. It records CONNECT and PUBLISH packets,
    emulates session takeover and injects faults. Every fault option is a
    number of connections: the fault applies to the connections whose index
    is lower than the value, so later connections work normally.
    """

    def __init__(
        self,
        port,
        *,
        cert_file=None,
        key_file=None,
        connack_codes=None,
        credentials=None,
        close_on_publish=0,
        withhold_connack=0,
        withhold_puback=0,
        withhold_pingresp=0,
        bogus_puback=0,
        malformed_header=0,
        close_idle_after_ack=0,
        reverse_acks=False,
        ack_delay=0.0,
        inject_pingresp=False,
        broker_publish=None,
        broker_publish_connections=None,
    ):
        self.port = port
        self.connack_codes = list(connack_codes or [])
        self.credentials = credentials
        self.close_on_publish = close_on_publish
        self.withhold_connack = withhold_connack
        self.withhold_puback = withhold_puback
        self.withhold_pingresp = withhold_pingresp
        self.bogus_puback = bogus_puback
        self.malformed_header = malformed_header
        self.close_idle_after_ack = close_idle_after_ack
        self.reverse_acks = reverse_acks
        self.ack_delay = ack_delay
        self.inject_pingresp = inject_pingresp
        self.broker_publish = broker_publish
        self.broker_publish_connections = broker_publish_connections

        self.lock = threading.Lock()
        self.connects = []
        self.messages = []
        self.dropped = []
        self.client_acks = []
        self.errors = []
        self.disconnects = 0
        self.pings = 0
        self.idle_closes = 0
        self.takeovers = 0
        self.active = 0
        self.max_active = 0
        self.sessions = {}

        self._tls = None
        if cert_file:
            self._tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self._tls.load_cert_chain(certfile=cert_file, keyfile=key_file)

        self._stop = threading.Event()
        self._server = None
        self._threads = []
        self._connections = 0

    def start(self):
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("127.0.0.1", self.port))
        self._server.listen(16)
        self._server.settimeout(0.2)

        thread = threading.Thread(target=self._accept_loop, daemon=True)
        thread.start()
        self._threads.append(thread)

    def stop(self):
        self._stop.set()
        for thread in list(self._threads):
            thread.join(timeout=5)
        if self._server is not None:
            self._server.close()

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            index = self._connections
            self._connections += 1

            thread = threading.Thread(target=self._serve, args=(conn, index), daemon=True)
            thread.start()
            self._threads.append(thread)

    def _serve(self, conn, index):
        state = {"accepted": False, "acked": False, "client_id": None, "fault_sent": False}
        try:
            if self._tls is not None:
                conn.settimeout(10)
                conn = self._tls.wrap_socket(conn, server_side=True)
            conn.settimeout(0.3)
            self._session(conn, index, state)
        except (EOFError, ConnectionError, ssl.SSLError, socket.timeout):
            pass
        except MqttProtocolError as exc:
            with self.lock:
                self.errors.append(f"connection {index}: {exc}")
        except OSError:
            pass
        except Exception as exc:  # noqa: BLE001 - a broker bug must fail the test
            with self.lock:
                self.errors.append(f"connection {index}: unexpected {exc!r}")
        finally:
            with self.lock:
                if state["accepted"]:
                    self.active -= 1
                if self.sessions.get(state["client_id"]) is conn:
                    del self.sessions[state["client_id"]]
            conn.close()

    def _connack_code(self, info):
        if self.connack_codes:
            return self.connack_codes.pop(0)
        if self.credentials is not None:
            if (info["username"], info["password"]) != self.credentials:
                return 4
        return 0

    def _wait_close(self, conn):
        """Answer nothing until the client gives up on the session."""
        while not self._stop.is_set():
            try:
                if not conn.recv(4096):
                    return
            except socket.timeout:
                continue

    def _accept(self, conn, index, state, info):
        with self.lock:
            code = self._connack_code(info)
            info["return_code"] = code
            self.connects.append(info)

        conn.sendall(bytes([0x20, 0x02, 0x00, code]))
        if code != 0:
            return False

        with self.lock:
            # A broker closes the older session that uses the same client id
            previous = self.sessions.get(info["client_id"])
            if previous is not None:
                self.takeovers += 1
                self.errors.append(f"session takeover for client id {info['client_id']}")
                try:
                    previous.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            self.sessions[info["client_id"]] = conn
            state["accepted"] = True
            state["client_id"] = info["client_id"]
            self.active += 1
            self.max_active = max(self.max_active, self.active)

        if self.broker_publish is not None and (
            self.broker_publish_connections is None or index < self.broker_publish_connections
        ):
            size, qos = self.broker_publish
            conn.sendall(broker_publish_packet(size, qos))

        return True

    def _publish(self, conn, index, state, message):
        qos = message["qos"]

        if index < self.close_on_publish:
            # Lose the session before any acknowledgement or PINGRESP
            with self.lock:
                self.dropped.append(message)
            raise EOFError("session dropped by the broker")

        if qos == 0:
            unconfirmed = index < self.withhold_pingresp
        else:
            unconfirmed = (
                index < self.withhold_puback
                or index < self.bogus_puback
                or index < self.malformed_header
            )

        if unconfirmed:
            # The flush fails, the client publishes the message again
            with self.lock:
                self.dropped.append(message)

            if qos == 1 and not state["fault_sent"]:
                if index < self.malformed_header:
                    # Continuation bit set on the 4th Remaining Length byte
                    conn.sendall(bytes([0x40, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]))
                    state["fault_sent"] = True
                elif index < self.bogus_puback:
                    conn.sendall(ack(PUBACK, (message["packet_id"] + 1000) % 65536 or 1))
                    state["fault_sent"] = True
            return

        with self.lock:
            self.messages.append(message)

        if qos != 1:
            return

        if self.reverse_acks:
            state["pending"].append(message["packet_id"])
            return

        if self.ack_delay:
            time.sleep(self.ack_delay)
        if self.inject_pingresp:
            conn.sendall(b"\xd0\x00")
        conn.sendall(ack(PUBACK, message["packet_id"]))
        state["acked"] = True

    def _session(self, conn, index, state):
        buf = bytearray()
        state["pending"] = []
        last_packet = time.time()

        while not self._stop.is_set():
            try:
                packet_type, flags, body, length_bytes = read_packet(conn, buf)
            except socket.timeout:
                if state["pending"]:
                    # Acknowledge the window in reverse order
                    for packet_id in reversed(state["pending"]):
                        conn.sendall(ack(PUBACK, packet_id))
                    state["pending"] = []
                    state["acked"] = True
                if (
                    index < self.close_idle_after_ack
                    and state["acked"]
                    and not buf
                    and time.time() - last_packet > 0.5
                ):
                    # Close the idle session after its first acknowledged flush
                    with self.lock:
                        self.idle_closes += 1
                    return
                continue

            last_packet = time.time()

            if not state["accepted"]:
                if packet_type != CONNECT:
                    raise MqttProtocolError(f"expected CONNECT, got {packet_type}")

                info = parse_connect(flags, body)
                info["connection"] = index

                if index < self.withhold_connack:
                    with self.lock:
                        info["return_code"] = None
                        self.connects.append(info)
                    self._wait_close(conn)
                    return

                if not self._accept(conn, index, state, info):
                    return
                continue

            if packet_type == PUBLISH:
                message = parse_publish(flags, body)
                message["connection"] = index
                message["length_bytes"] = length_bytes
                self._publish(conn, index, state, message)
            elif packet_type in (PUBACK, PUBREC, PUBCOMP):
                # Acknowledgements of the PUBLISH sent by the broker
                if flags != 0 or len(body) != 2:
                    raise MqttProtocolError(f"invalid acknowledgement type {packet_type}")
                packet_id = int.from_bytes(body, "big")
                with self.lock:
                    self.client_acks.append((packet_type, packet_id, index))
                if packet_type == PUBREC:
                    conn.sendall(ack(PUBREL, packet_id, flags=0x02))
            elif packet_type == PINGREQ:
                if flags != 0 or body:
                    raise MqttProtocolError("invalid PINGREQ")
                with self.lock:
                    self.pings += 1
                if index < self.withhold_pingresp:
                    continue
                conn.sendall(b"\xd0\x00")
                state["acked"] = True
            elif packet_type == DISCONNECT:
                if flags != 0 or body:
                    raise MqttProtocolError("invalid DISCONNECT")
                with self.lock:
                    self.disconnects += 1
                return
            else:
                raise MqttProtocolError(f"unexpected packet type {packet_type}")

    def wait_for(self, predicate, timeout, description):
        deadline = time.time() + scaled(timeout)
        while time.time() < deadline:
            with self.lock:
                if predicate(self):
                    return
            time.sleep(0.1)

        with self.lock:
            raise TimeoutError(
                f"timed out waiting for {description}; messages={len(self.messages)} "
                f"connects={self.connects} errors={self.errors}"
            )

    def wait_for_messages(self, count, timeout=20):
        self.wait_for(lambda b: len(b.messages) >= count, timeout, f"{count} messages")
        with self.lock:
            return list(self.messages)


class Service:
    def __init__(self, config_file, **broker_options):
        if os.path.isabs(config_file):
            self.config_file = config_file
        else:
            self.config_file = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "../config", config_file)
            )
        self.broker_options = broker_options
        self.broker = None
        self.service = FluentBitTestService(
            self.config_file,
            pre_start=self._start_broker,
            post_stop=self._stop_broker,
        )

    def _start_broker(self, service):
        port = service.allocate_port_env("MQTT_BROKER_PORT")
        self.broker = FakeBroker(port, **self.broker_options)
        self.broker.start()

    def _stop_broker(self, _service):
        if self.broker is not None:
            self.broker.stop()

    def start(self):
        self.service.start()

    def stop(self):
        self.service.stop()

    def log_contents(self):
        with open(self.service.flb.log_file, encoding="utf-8", errors="replace") as log_file:
            return log_file.read()

    def metrics(self):
        """Prometheus metrics, None until the first metrics snapshot exists."""
        port = self.service.flb.http_monitoring_port
        try:
            response = requests.get(
                f"http://127.0.0.1:{port}/api/v2/metrics/prometheus", timeout=scaled(5)
            )
        except requests.RequestException:
            return None
        if response.status_code != 200:
            return None
        return response.text


METRIC_LINE = re.compile(
    r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(?P<labels>[^}]*)\})?\s+(?P<value>\S+)"
)


def metric_value(text, metric, labels):
    """Sum of the samples of 'metric' whose labels include 'labels', None if absent."""
    total = None
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        match = METRIC_LINE.match(line)
        if not match or match.group("name") != metric:
            continue
        found = dict(re.findall(r'(\w+)="([^"]*)"', match.group("labels") or ""))
        if all(found.get(key) == value for key, value in labels.items()):
            total = (total or 0) + float(match.group("value"))
    return total


def write_config(tmp_path, output, inputs, *, log_level="info"):
    """
    Write a configuration with dummy inputs, given as (tag, record, rate,
    samples) tuples, and one mqtt output with the 'output' properties.
    """
    lines = [
        "service:",
        "  flush: 1",
        "  grace: 1",
        f"  log_level: {log_level}",
        "  http_server: on",
        "  http_port: ${FLUENT_BIT_HTTP_MONITORING_PORT}",
        "  scheduler.base: 1",
        "  scheduler.cap: 2",
        "",
        "pipeline:",
        "  inputs:",
    ]
    for tag, record, rate, samples in inputs:
        lines += [
            "    - name: dummy",
            f"      tag: {tag}",
            f"      dummy: '{record}'",
            f"      rate: {rate}",
            f"      samples: {samples}",
        ]
    lines += [
        "",
        "  outputs:",
        "    - name: mqtt",
        "      match: '*'",
        "      host: 127.0.0.1",
        "      port: ${MQTT_BROKER_PORT}",
        "      retry_limit: 10",
    ]
    for key, value in output.items():
        lines.append(f"      {key}: {value}")

    config_file = tmp_path / "out_mqtt.yaml"
    config_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(config_file)


def run_until_messages(service, count, timeout=20):
    service.start()
    try:
        return service.broker.wait_for_messages(count, timeout=timeout)
    finally:
        service.stop()


def _tls_files():
    cert_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../../in_splunk/certificate")
    )
    return os.path.join(cert_dir, "certificate.pem"), os.path.join(cert_dir, "private_key.pem")


def _assert_clean_protocol(broker):
    assert broker.errors == []
    assert broker.takeovers == 0
    for connect in broker.connects:
        assert connect["protocol"] == "MQTT"
        assert connect["level"] == 4
        assert connect["clean_session"] is True


def _assert_qos1_messages(messages, count):
    payloads = [json.loads(message["payload"]) for message in messages]
    assert len(payloads) >= count
    for message, payload in zip(messages, payloads):
        assert message["topic"] == "devices/edge01/logs"
        assert message["qos"] == 1
        assert message["retain"] is False
        assert message["dup"] is False
        assert message["packet_id"] >= 1
        assert payload["message"] == "hello from out_mqtt"
        assert payload["level"] == "info"
        assert isinstance(payload["date"], float)


def _assert_qos0_messages(broker, messages):
    _assert_clean_protocol(broker)
    for message in messages:
        assert message["topic"] == "gateway/status"
        assert message["qos"] == 0
        assert message["retain"] is True
        assert message["packet_id"] is None
        # MessagePack map {"state": "online"}, the date key is disabled
        assert message["payload"] == b"\x81\xa5state\xa6online"

    # Every QoS 0 flush is confirmed with a PINGREQ round trip
    assert broker.pings >= 1


def _assert_redelivered(broker, messages):
    """Every message the broker dropped was published again on a new session."""
    assert broker.dropped
    delivered = {message["payload"] for message in messages}
    for message in broker.dropped:
        assert message["payload"] in delivered
    assert all(message["connection"] > broker.dropped[0]["connection"] for message in messages)


def test_out_mqtt_qos1_publish():
    service = Service("out_mqtt_qos1.yaml")
    messages = run_until_messages(service, 5)

    broker = service.broker
    _assert_clean_protocol(broker)
    _assert_qos1_messages(messages, 5)

    # One pooled session for every flush, acknowledged without PINGREQ
    assert len(broker.messages) == 5
    assert len(broker.connects) == 1
    assert broker.disconnects == 0
    assert broker.pings == 0

    connect = broker.connects[0]
    assert GENERATED_CLIENT_ID.match(connect["client_id"])
    assert connect["client_id"].endswith("00000000")
    assert connect["keep_alive"] == 60
    assert connect["username"] is None
    assert connect["password"] is None

    log_contents = service.log_contents()
    assert RETRY_LOG not in log_contents


def test_out_mqtt_qos1_out_of_order_acks():
    service = Service("out_mqtt_qos1.yaml", reverse_acks=True)
    messages = run_until_messages(service, 5)

    _assert_clean_protocol(service.broker)
    _assert_qos1_messages(messages, 5)
    assert len(service.broker.messages) == 5
    assert service.broker.pings == 0
    assert RETRY_LOG not in service.log_contents()


def test_out_mqtt_pingresp_between_pubacks():
    service = Service("out_mqtt_qos1.yaml", inject_pingresp=True)
    messages = run_until_messages(service, 5)

    _assert_clean_protocol(service.broker)
    _assert_qos1_messages(messages, 5)
    assert len(service.broker.messages) == 5
    assert len(service.broker.connects) == 1
    assert RETRY_LOG not in service.log_contents()


def test_out_mqtt_retry_after_lost_session():
    service = Service("out_mqtt_qos1.yaml", close_on_publish=1)
    messages = run_until_messages(service, 5, timeout=30)

    broker = service.broker
    _assert_clean_protocol(broker)
    _assert_qos1_messages(messages, 5)
    _assert_redelivered(broker, messages)
    assert len(broker.connects) >= 2
    assert RETRY_LOG in service.log_contents()


def test_out_mqtt_retry_after_refused_connection():
    service = Service("out_mqtt_qos1.yaml", connack_codes=[5])
    messages = run_until_messages(service, 5, timeout=30)

    broker = service.broker
    _assert_clean_protocol(broker)
    _assert_qos1_messages(messages, 5)
    assert broker.connects[0]["return_code"] == 5
    assert broker.connects[1]["return_code"] == 0
    assert "not authorized (return code 5)" in service.log_contents()


@pytest.mark.parametrize(
    ("fault", "error"),
    [
        ("withhold_connack", "no CONNACK received"),
        ("withhold_puback", "lost while waiting for"),
    ],
)
def test_out_mqtt_stalled_broker(tmp_path, fault, error):
    config_file = write_config(
        tmp_path,
        {"topic": "stall", "net.io_timeout": "2s"},
        [("stall", '{"message":"stalled"}', 5, 3)],
    )
    service = Service(config_file, **{fault: 1})
    messages = run_until_messages(service, 3, timeout=40)

    broker = service.broker
    _assert_clean_protocol(broker)
    assert all(message["connection"] >= 1 for message in messages)
    if fault == "withhold_puback":
        _assert_redelivered(broker, messages)
    assert error in service.log_contents()


def test_out_mqtt_stalled_broker_without_pingresp(tmp_path):
    config_file = write_config(
        tmp_path,
        {"topic": "stall", "qos": 0, "net.io_timeout": "2s"},
        [("stall", '{"message":"stalled"}', 5, 3)],
    )
    service = Service(config_file, withhold_pingresp=1)
    messages = run_until_messages(service, 3, timeout=40)

    broker = service.broker
    _assert_clean_protocol(broker)
    _assert_redelivered(broker, messages)
    assert "no PINGRESP received" in service.log_contents()


def test_out_mqtt_default_io_timeout(tmp_path):
    config_file = write_config(
        tmp_path,
        {"topic": "debug"},
        [("debug", '{"message":"debug"}', 1, 1)],
        log_level="debug",
    )
    service = Service(config_file)
    run_until_messages(service, 1)

    assert "net.io_timeout is not set, using 30 seconds" in service.log_contents()


@pytest.mark.parametrize(
    ("fault", "error"),
    [
        ("bogus_puback", "unexpected PUBACK for packet identifier"),
        ("malformed_header", "malformed packet received from the broker"),
    ],
)
def test_out_mqtt_protocol_faults(fault, error):
    service = Service("out_mqtt_qos1.yaml", **{fault: 1})
    messages = run_until_messages(service, 5, timeout=30)

    broker = service.broker
    _assert_clean_protocol(broker)
    _assert_qos1_messages(messages, 5)
    _assert_redelivered(broker, messages)

    log_contents = service.log_contents()
    assert error in log_contents
    assert RETRY_LOG in log_contents


@pytest.mark.parametrize("qos", [0, 1, 2])
def test_out_mqtt_broker_publish(qos):
    # Larger than the plugin receive buffer, sent right after CONNACK
    service = Service("out_mqtt_qos1.yaml", broker_publish=(3000, qos))
    messages = run_until_messages(service, 5)

    broker = service.broker
    _assert_clean_protocol(broker)
    _assert_qos1_messages(messages, 5)
    assert len(broker.messages) == 5
    assert RETRY_LOG not in service.log_contents()

    acks = [(packet_type, packet_id) for packet_type, packet_id, _ in broker.client_acks]
    if qos == 0:
        assert acks == []
    elif qos == 1:
        assert (PUBACK, BROKER_PUBLISH_ID) in acks
    else:
        # PUBREC answers the PUBLISH. The PUBCOMP follows only when the broker
        # PUBREL arrives while the session is in use, which depends on timing.
        assert (PUBREC, BROKER_PUBLISH_ID) in acks


def test_out_mqtt_broker_publish_invalid_qos():
    service = Service(
        "out_mqtt_qos1.yaml", broker_publish=(10, 3), broker_publish_connections=1
    )
    service.start()

    try:
        # The first session is dropped by the client after its PUBLISH packets
        # were acknowledged, the chunk is published again on a new session
        service.broker.wait_for(
            lambda b: len([m for m in b.messages if m["connection"] >= 1]) >= 5,
            30,
            "messages on a new session",
        )
    finally:
        service.stop()

    messages = [m for m in service.broker.messages if m["connection"] >= 1]
    _assert_clean_protocol(service.broker)
    _assert_qos1_messages(messages, 5)
    assert "malformed PUBLISH packet received from the broker (QoS 3)" in service.log_contents()


def test_out_mqtt_qos0_retain_msgpack():
    service = Service("out_mqtt_qos0_retain.yaml")
    messages = run_until_messages(service, 3)

    _assert_qos0_messages(service.broker, messages)
    assert len(service.broker.messages) == 3


def test_out_mqtt_qos0_retry_after_lost_session():
    service = Service("out_mqtt_qos0_retain.yaml", close_on_publish=1)
    messages = run_until_messages(service, 3, timeout=30)

    # Without PINGRESP the flush is not confirmed and the chunk is retried
    _assert_qos0_messages(service.broker, messages)
    _assert_redelivered(service.broker, messages)

    # Depending on timing the lost session fails the PINGREQ write or read
    log_contents = service.log_contents()
    assert "no PINGRESP received" in log_contents or "could not send PINGREQ" in log_contents


def test_out_mqtt_fixed_client_id_one_session():
    # Two inputs flush together, acknowledgements are slow: without one flush
    # at a time, two sessions would share the client identifier.
    service = Service("out_mqtt_auth.yaml", credentials=("flb", "s3cret"), ack_delay=0.05)
    messages = run_until_messages(service, 20, timeout=30)

    broker = service.broker
    _assert_clean_protocol(broker)

    for message in messages:
        assert message["topic"] == "secure/logs"
        assert json.loads(message["payload"])["message"] == "authenticated"
    assert len(broker.messages) == 20

    assert broker.max_active == 1
    assert len(broker.connects) == 1
    connect = broker.connects[0]
    assert connect["client_id"] == "fluent-bit-gateway"
    assert connect["username"] == "flb"
    assert connect["password"] == "s3cret"
    assert connect["keep_alive"] == 30
    assert connect["return_code"] == 0

    log_contents = service.log_contents()
    assert "net.keepalive_idle_timeout lowered from 30 to 27 seconds" in log_contents
    assert RETRY_LOG not in log_contents


def test_out_mqtt_auth_rejected_credentials():
    service = Service("out_mqtt_auth.yaml", credentials=("flb", "another-password"))
    service.start()

    try:
        service.broker.wait_for(lambda b: len(b.connects) >= 2, 20, "connection retries")
    finally:
        service.stop()

    broker = service.broker
    assert broker.messages == []
    assert all(connect["return_code"] == 4 for connect in broker.connects)
    assert "bad user name or password" in service.log_contents()


def test_out_mqtt_no_keepalive(tmp_path):
    config_file = write_config(
        tmp_path,
        {"topic": "sessions", "net.keepalive": "off"},
        [("sessions", '{"message":"session"}', 2, 4)],
    )
    service = Service(config_file)
    run_until_messages(service, 4)

    broker = service.broker
    _assert_clean_protocol(broker)

    # Every flush opens its own session and ends it with DISCONNECT
    assert len(broker.connects) >= 2
    assert broker.disconnects == len(broker.connects)

    matches = [GENERATED_CLIENT_ID.match(connect["client_id"]) for connect in broker.connects]
    assert all(matches)
    assert len({match.group(1) for match in matches}) == 1
    sequences = [int(match.group(2), 16) for match in matches]
    assert sequences == list(range(len(sequences)))


def test_out_mqtt_idle_session_closed_by_broker(tmp_path):
    config_file = write_config(
        tmp_path,
        {"topic": "idle"},
        [("idle", '{"message":"idle"}', 1, 3)],
    )
    service = Service(config_file, close_idle_after_ack=1)
    messages = run_until_messages(service, 3, timeout=30)

    broker = service.broker
    _assert_clean_protocol(broker)
    assert broker.idle_closes == 1
    assert len(broker.connects) >= 2
    assert len(messages) == 3

    # The closed pooled session is discarded before use, nothing is retried
    log_contents = service.log_contents()
    assert "lost while waiting" not in log_contents
    assert RETRY_LOG not in log_contents


def test_out_mqtt_keep_alive_too_short(tmp_path):
    config_file = write_config(
        tmp_path,
        {"topic": "short", "keep_alive": "2s"},
        [("short", '{"message":"short"}', 1, 3)],
    )
    service = Service(config_file)
    run_until_messages(service, 3)

    broker = service.broker
    _assert_clean_protocol(broker)
    assert all(connect["keep_alive"] == 2 for connect in broker.connects)
    assert len(broker.connects) >= 2
    assert broker.disconnects == len(broker.connects)
    assert "keep_alive 2 is too short to keep idle connections" in service.log_contents()


def test_out_mqtt_keep_alive_lowers_idle_timeout(tmp_path):
    config_file = write_config(
        tmp_path,
        {"topic": "lowered", "keep_alive": "10s"},
        [("lowered", '{"message":"lowered"}', 5, 2)],
    )
    service = Service(config_file)
    run_until_messages(service, 2)

    _assert_clean_protocol(service.broker)
    assert service.broker.connects[0]["keep_alive"] == 10
    assert "net.keepalive_idle_timeout lowered from 30 to 7 seconds" in service.log_contents()


def test_out_mqtt_large_records(tmp_path):
    small = "s" * 200
    large = "l" * 20000
    config_file = write_config(
        tmp_path,
        {"topic": "large"},
        [
            ("large.small", json.dumps({"message": small}), 1, 1),
            ("large.big", json.dumps({"message": large}), 1, 1),
        ],
    )
    service = Service(config_file)
    messages = run_until_messages(service, 2)

    _assert_clean_protocol(service.broker)
    by_message = {json.loads(message["payload"])["message"]: message for message in messages}
    assert set(by_message) == {small, large}

    # Two and three bytes Remaining Length
    assert by_message[small]["length_bytes"] == 2
    assert by_message[large]["length_bytes"] == 3


def test_out_mqtt_drop_metrics():
    service = Service("out_mqtt_drops.yaml")
    service.start()

    try:
        messages = service.broker.wait_for_messages(3)

        def counters():
            text = service.metrics()
            if text is None:
                return (None, None, None)
            return (
                metric_value(text, "fluentbit_output_proc_records_total", {"name": "mqtt.0"}),
                metric_value(text, "fluentbit_output_dropped_records_total", {"name": "mqtt.0"}),
                metric_value(
                    text, "fluentbit_routing_logs_drop_records_total", {"output": "mqtt.0"}
                ),
            )

        values = service.service.wait_for_condition(
            lambda: (lambda v: v if v[0] == 3 and v[1] == 2 else None)(counters()),
            timeout=scaled(20),
            interval=0.5,
            description="drop metrics",
        )
    finally:
        service.stop()

    _assert_clean_protocol(service.broker)
    assert len(service.broker.messages) == 3
    for message in messages:
        assert message["topic"] == "drops"
        assert json.loads(message["payload"]) == {"v": 1}

    processed, dropped, routing_dropped = values
    assert processed == 3
    assert dropped == 2
    assert routing_dropped in (None, 2)


def test_out_mqtt_topic_and_payload_keys():
    service = Service("out_mqtt_keys.yaml")
    messages = run_until_messages(service, 2)

    _assert_clean_protocol(service.broker)
    for message in messages:
        assert message["topic"] == "alerts/high"
        assert json.loads(message["payload"]) == {"level": "high", "code": 42}


def test_out_mqtt_tls():
    cert_file, key_file = _tls_files()
    service = Service("out_mqtt_tls.yaml", cert_file=cert_file, key_file=key_file)
    messages = run_until_messages(service, 3)

    _assert_clean_protocol(service.broker)
    for message in messages:
        assert message["topic"] == "secure/tls"
        assert json.loads(message["payload"])["message"] == "hello over tls"


@pytest.mark.parametrize(
    ("properties", "error"),
    [
        ("qos: 2", "qos 2 is not supported"),
        ("topic: logs/#", "invalid topic"),
        ("password: secret", "password requires username"),
        ("client_id: gateway\n      workers: 2", "a fixed client_id allows a single"),
        ("topic: logs/$TAG[1025]", "$TAG[n] index is too large"),
        ("keep_alive: 70000s", "invalid keep_alive"),
    ],
)
def test_out_mqtt_invalid_configuration(tmp_path, properties, error):
    config_file = tmp_path / "out_mqtt_invalid.yaml"
    config_file.write_text(
        f"""service:
  flush: 1
  log_level: info
  http_server: on
  http_port: ${{FLUENT_BIT_HTTP_MONITORING_PORT}}

pipeline:
  inputs:
    - name: dummy
      tag: invalid
      samples: 1

  outputs:
    - name: mqtt
      match: invalid
      host: 127.0.0.1
      port: 1883
      {properties}
""",
        encoding="utf-8",
    )
    fluent_bit = FluentBitManager(str(config_file))

    try:
        with pytest.raises(FluentBitStartupError, match="exited early with code"):
            fluent_bit.start()

        # Under Valgrind or Leaks the process is the memory checker, its exit
        # status is not the one of Fluent Bit
        if not memory_check_enabled():
            assert fluent_bit.process.returncode != 0
        with open(fluent_bit.log_file, encoding="utf-8") as log_file:
            assert error in log_file.read()
    finally:
        fluent_bit.stop()
