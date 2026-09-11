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

import logging
import socket
import struct
import threading
import time


logger = logging.getLogger(__name__)

API_KEY_PRODUCE = 0
API_KEY_FETCH = 1
API_KEY_METADATA = 3
API_KEY_API_VERSIONS = 18

BROKER_NODE_ID = 1

data_storage = {
    "connections": [],
    "requests": [],
    "messages": [],
}

server_thread = None
server_socket = None
server_port = None
produce_response_delay = 0
server_stop_event = threading.Event()
server_ready_event = threading.Event()


def reset_kafka_server_state():
    data_storage["connections"] = []
    data_storage["requests"] = []
    data_storage["messages"] = []
    server_stop_event.clear()
    server_ready_event.clear()


def _recv_exact(sock, size):
    chunks = []
    remaining = size

    while remaining > 0:
        try:
            chunk = sock.recv(remaining)
        except ConnectionResetError:
            return None
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)

    return b"".join(chunks)


def _read_int16(data, offset):
    return struct.unpack_from(">h", data, offset)[0], offset + 2


def _read_int32(data, offset):
    return struct.unpack_from(">i", data, offset)[0], offset + 4


def _read_int64(data, offset):
    return struct.unpack_from(">q", data, offset)[0], offset + 8


def _read_int8(data, offset):
    return data[offset], offset + 1


def _read_varint(data, offset, limit=None):
    value = 0
    shift = 0

    if limit is None:
        limit = len(data)

    while True:
        if offset >= limit:
            raise ValueError("Truncated Kafka varint")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return value, offset
        shift += 7
        if shift >= 64:
            raise ValueError("Kafka varint is too large")


def _read_varint_signed(data, offset, limit=None):
    value, offset = _read_varint(data, offset, limit)
    return (value >> 1) ^ -(value & 1), offset


def _read_string(data, offset):
    length, offset = _read_int16(data, offset)
    if length < 0:
        return None, offset
    end = offset + length
    return data[offset:end].decode("utf-8", errors="replace"), end


def _read_bytes(data, offset):
    length, offset = _read_int32(data, offset)
    if length < 0:
        return None, offset
    end = offset + length
    return data[offset:end], end


def _read_array_length(data, offset):
    return _read_int32(data, offset)


def _parse_request_header(payload):
    api_key, offset = _read_int16(payload, 0)
    api_version, offset = _read_int16(payload, offset)
    correlation_id, offset = _read_int32(payload, offset)
    client_id, offset = _read_string(payload, offset)

    return {
        "api_key": api_key,
        "api_version": api_version,
        "correlation_id": correlation_id,
        "client_id": client_id,
        "body": payload[offset:],
    }


def _encode_string(value):
    encoded = value.encode("utf-8")
    return struct.pack(">h", len(encoded)) + encoded


def _encode_response(correlation_id, body):
    frame = struct.pack(">i", correlation_id) + body
    return struct.pack(">i", len(frame)) + frame


def _encode_metadata_response(topics, host, port):
    body = []
    body.append(struct.pack(">i", 1))
    body.append(struct.pack(">i", BROKER_NODE_ID))
    body.append(_encode_string(host))
    body.append(struct.pack(">i", port))

    body.append(struct.pack(">i", len(topics)))
    for topic in topics:
        body.append(struct.pack(">h", 0))
        body.append(_encode_string(topic))
        body.append(struct.pack(">i", 1))
        body.append(struct.pack(">h", 0))
        body.append(struct.pack(">i", 0))
        body.append(struct.pack(">i", BROKER_NODE_ID))
        body.append(struct.pack(">i", 1))
        body.append(struct.pack(">i", BROKER_NODE_ID))
        body.append(struct.pack(">i", 1))
        body.append(struct.pack(">i", BROKER_NODE_ID))

    return b"".join(body)


def _encode_produce_response(topic, api_version, partition=0, base_offset=0):
    body = [
        struct.pack(">i", 1),
        _encode_string(topic),
        struct.pack(">i", 1),
        struct.pack(">i", partition),
        struct.pack(">h", 0),
        struct.pack(">q", base_offset),
    ]
    if api_version >= 2:
        body.append(struct.pack(">q", -1))
    if api_version >= 1:
        body.append(struct.pack(">i", 0))
    return b"".join(body)


def _encode_api_versions_response(api_version):
    api_versions = [
        (API_KEY_PRODUCE, 0, 3),
        (API_KEY_FETCH, 0, 4),
        (API_KEY_METADATA, 0, 0),
        (API_KEY_API_VERSIONS, 0, 3),
    ]

    if api_version >= 3:
        entries = []
        for api_key, min_version, max_version in api_versions:
            entries.append(
                struct.pack(">h", api_key)
                + struct.pack(">h", min_version)
                + struct.pack(">h", max_version)
                + b"\x00"
            )

        return b"".join(
            [
                struct.pack(">h", 0),
                bytes([len(api_versions) + 1]),
                b"".join(entries),
                struct.pack(">i", 0),
                b"\x00",
            ]
        )

    body = [struct.pack(">h", 0), struct.pack(">i", len(api_versions))]
    for api_key, min_version, max_version in api_versions:
        body.append(struct.pack(">h", api_key))
        body.append(struct.pack(">h", min_version))
        body.append(struct.pack(">h", max_version))
    if api_version >= 1:
        body.append(struct.pack(">i", 0))
    return b"".join(body)


def _parse_metadata_request(body):
    topic_count, offset = _read_array_length(body, 0)
    topics = []

    for _ in range(topic_count):
        topic, offset = _read_string(body, offset)
        topics.append(topic)

    return topics


def _parse_message_set(data):
    messages = []
    offset = 0

    while offset < len(data):
        if len(data) - offset < 12:
            break

        message_offset, offset = _read_int64(data, offset)
        message_size, offset = _read_int32(data, offset)
        end = offset + message_size

        if end > len(data):
            break

        _, cursor = _read_int32(data, offset)
        magic = data[cursor]
        cursor += 1
        attributes = data[cursor]
        cursor += 1
        key, cursor = _read_bytes(data, cursor)
        value, cursor = _read_bytes(data, cursor)

        if magic == 1 and cursor + 8 <= end:
            cursor += 8

        if attributes & 0x07:
            raise ValueError("Compressed Kafka message sets are not supported by the fake broker")

        messages.append(
            {
                "offset": message_offset,
                "magic": magic,
                "attributes": attributes,
                "key": key,
                "value": value,
                "headers": [],
                "batch_index": None,
            }
        )
        offset = end

    return messages


def _parse_record_batch(data):
    messages = []
    offset = 0
    batch_index = 0

    while offset < len(data):
        if len(data) - offset < 61:
            break

        message_offset, offset = _read_int64(data, offset)
        batch_length, offset = _read_int32(data, offset)
        batch_end = offset + batch_length
        if batch_length < 49 or batch_end > len(data):
            raise ValueError("Invalid Kafka record batch length")

        _, offset = _read_int32(data, offset)  # partition leader epoch
        magic, offset = _read_int8(data, offset)
        if magic != 2:
            raise ValueError("Unsupported Kafka record batch magic")

        offset += 4  # CRC
        batch_attributes, offset = _read_int16(data, offset)
        if batch_attributes & 0x07:
            raise ValueError("Compressed Kafka record batches are not supported by the fake broker")

        _, offset = _read_int32(data, offset)  # last offset delta
        offset += 8  # first timestamp
        offset += 8  # max timestamp
        offset += 8  # producer id
        offset += 2  # producer epoch
        offset += 4  # base sequence
        record_count, offset = _read_int32(data, offset)
        if record_count < 0:
            raise ValueError("Invalid Kafka record count")

        for _ in range(record_count):
            record_length, offset = _read_varint_signed(data, offset, batch_end)
            record_end = offset + record_length
            if record_length < 0 or record_end > batch_end:
                raise ValueError("Invalid Kafka record length")
            if offset >= record_end:
                raise ValueError("Truncated Kafka record")

            attributes, offset = _read_int8(data, offset)
            _, offset = _read_varint_signed(data, offset, record_end)  # timestamp delta
            offset_delta, offset = _read_varint_signed(data, offset, record_end)

            key_length, offset = _read_varint_signed(data, offset, record_end)
            if key_length < 0:
                key = None
            else:
                if offset + key_length > record_end:
                    raise ValueError("Invalid Kafka record key length")
                key = data[offset:offset + key_length]
                offset += key_length

            value_length, offset = _read_varint_signed(data, offset, record_end)
            if value_length < 0:
                value = None
            else:
                if offset + value_length > record_end:
                    raise ValueError("Invalid Kafka record value length")
                value = data[offset:offset + value_length]
                offset += value_length

            header_count, offset = _read_varint_signed(data, offset, record_end)
            if header_count < 0:
                raise ValueError("Invalid Kafka record header count")

            headers = []
            for _ in range(header_count):
                header_key_length, offset = _read_varint_signed(data, offset, record_end)
                if header_key_length < 0 or offset + header_key_length > record_end:
                    raise ValueError("Invalid Kafka header key length")
                header_key = data[offset:offset + header_key_length].decode(
                    "utf-8", errors="replace"
                )
                offset += header_key_length

                header_value_length, offset = _read_varint_signed(
                    data,
                    offset,
                    record_end,
                )
                if header_value_length < 0:
                    header_value = None
                else:
                    if offset + header_value_length > record_end:
                        raise ValueError("Invalid Kafka header value length")
                    header_value = data[offset:offset + header_value_length]
                    offset += header_value_length
                headers.append((header_key, header_value))

            if offset != record_end:
                raise ValueError("Kafka record length does not match its fields")

            messages.append(
                {
                    "offset": message_offset + offset_delta,
                    "magic": magic,
                    "attributes": attributes,
                    "key": key,
                    "value": value,
                    "headers": headers,
                    "batch_index": batch_index,
                }
            )

        offset = batch_end
        batch_index += 1

    return messages


def _parse_records(data):
    if len(data) >= 17 and data[16] == 2:
        return _parse_record_batch(data)
    return _parse_message_set(data)


def _parse_produce_request(body, api_version):
    if api_version >= 3:
        _, offset = _read_string(body, 0)
    else:
        offset = 0

    required_acks, offset = _read_int16(body, offset)
    timeout_ms, offset = _read_int32(body, offset)
    topic_count, offset = _read_array_length(body, offset)
    produced_topics = []

    for _ in range(topic_count):
        topic, offset = _read_string(body, offset)
        partition_count, offset = _read_array_length(body, offset)
        partitions = []

        for _ in range(partition_count):
            partition, offset = _read_int32(body, offset)
            message_set, offset = _read_bytes(body, offset)
            records = _parse_records(message_set or b"")
            partitions.append(
                {
                    "partition": partition,
                    "records": records,
                }
            )

        produced_topics.append(
            {
                "topic": topic,
                "partitions": partitions,
            }
        )

    return {
        "required_acks": required_acks,
        "timeout_ms": timeout_ms,
        "topics": produced_topics,
    }


def _handle_request(sock, request, host, port):
    data_storage["requests"].append(
        {
            "api_key": request["api_key"],
            "api_version": request["api_version"],
            "correlation_id": request["correlation_id"],
            "client_id": request["client_id"],
        }
    )

    if request["api_key"] == API_KEY_API_VERSIONS:
        sock.sendall(
            _encode_response(
                request["correlation_id"],
                _encode_api_versions_response(request["api_version"]),
            )
        )
        return

    if request["api_key"] == API_KEY_METADATA:
        topics = _parse_metadata_request(request["body"])
        sock.sendall(
            _encode_response(
                request["correlation_id"],
                _encode_metadata_response(topics, host, port),
            )
        )
        return

    if request["api_key"] == API_KEY_PRODUCE:
        produced = _parse_produce_request(request["body"], request["api_version"])
        for topic_data in produced["topics"]:
            for partition_data in topic_data["partitions"]:
                for record in partition_data["records"]:
                    data_storage["messages"].append(
                        {
                            "topic": topic_data["topic"],
                            "partition": partition_data["partition"],
                            "key": record["key"],
                            "value": record["value"],
                            "magic": record["magic"],
                            "attributes": record["attributes"],
                            "headers": record["headers"],
                            "batch_index": record["batch_index"],
                            "produce_correlation_id": request["correlation_id"],
                            "client_id": request["client_id"],
                        }
                    )

        first_topic = produced["topics"][0]["topic"] if produced["topics"] else "test"
        if produce_response_delay > 0:
            time.sleep(produce_response_delay)
        sock.sendall(
            _encode_response(
                request["correlation_id"],
                _encode_produce_response(first_topic, request["api_version"]),
            )
        )
        return

    logger.warning("Unsupported Kafka API key %s", request["api_key"])


def _connection_loop(client, address, host, port):
    data_storage["connections"].append({"address": address})

    with client:
        while not server_stop_event.is_set():
            header = _recv_exact(client, 4)
            if not header:
                return

            frame_size = struct.unpack(">i", header)[0]
            payload = _recv_exact(client, frame_size)
            if payload is None:
                return

            request = _parse_request_header(payload)
            _handle_request(client, request, host, port)


def _server_loop(host, port):
    global server_socket, server_port

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(16)
    sock.settimeout(0.2)

    server_socket = sock
    server_port = port
    server_ready_event.set()
    logger.info("Starting fake Kafka broker on %s:%s", host, port)

    try:
        while not server_stop_event.is_set():
            try:
                client, address = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            worker = threading.Thread(
                target=_connection_loop,
                args=(client, address, host, port),
                daemon=True,
            )
            worker.start()
    finally:
        try:
            sock.close()
        except OSError:
            pass
        server_socket = None


def kafka_server_run(port, host="127.0.0.1", response_delay=0):
    global produce_response_delay, server_thread

    reset_kafka_server_state()
    produce_response_delay = response_delay
    server_thread = threading.Thread(target=_server_loop, args=(host, port), daemon=True)
    server_thread.start()
    server_ready_event.wait(timeout=5)
    return server_thread


def kafka_server_stop():
    server_stop_event.set()

    if server_socket is not None:
        try:
            server_socket.close()
        except OSError:
            pass
