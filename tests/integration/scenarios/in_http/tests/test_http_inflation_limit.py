"""Automatic HTTP inflation must obey the configured decoded-body limit."""
import concurrent.futures
import gzip
import http.client
import json

import pytest

from utils.test_service import FluentBitTestService


WIRE_LIMIT = 4096
LIMIT = 8192


def varint(value):
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    return bytes(result + bytes([value]))


def crc32c(payload):
    crc = 0xffffffff
    for byte in payload:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    crc ^= 0xffffffff
    return (((crc >> 15) | (crc << 17)) + 0xa282ead8) & 0xffffffff


def encode(payload, codec):
    if codec == "gzip":
        return gzip.compress(payload)
    if codec == "snappy-framed":
        result = b"\xff\x06\x00\x00sNaPpY"
        for offset in range(0, len(payload), 2048):
            chunk = payload[offset:offset + 2048]
            encoded = encode(chunk, "snappy")
            result += b"\x00" + (len(encoded) + 4).to_bytes(3, "little")
            result += crc32c(chunk).to_bytes(4, "little") + encoded
        return result
    prefix = payload.rstrip(b" ")
    repeated = len(payload) - len(prefix)
    if codec.startswith("zstd"):
        header = b"\x28\xb5\x2f\xfd"
        header += (b"\xa0" + len(payload).to_bytes(4, "little")
                   if codec == "zstd" else b"\x00\x38")
        # Raw JSON prefix followed by a final RLE block of whitespace.
        if prefix:
            header += (len(prefix) << 3).to_bytes(3, "little") + prefix
        return header + ((repeated << 3) | 3).to_bytes(3, "little") + b" "
    assert codec == "snappy"
    prefix += b" "
    repeated -= 1
    result = varint(len(payload)) + bytes([(len(prefix) - 1) << 2]) + prefix
    while repeated:
        count = min(repeated, 64)
        result += bytes([((count - 1) << 2) | 2, 1, 0])
        repeated -= count
    return result


def post(port, payload, encoding):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    try:
        connection.request("POST", "/", payload, {
            "Content-Type": "application/json", "Content-Encoding": encoding,
        })
        response = connection.getresponse()
        response.read()
        return response.status
    except (http.client.RemoteDisconnected, ConnectionResetError):
        # The shared server closes malformed/over-budget requests before dispatch.
        return None
    finally:
        connection.close()


@pytest.mark.parametrize("codec", ["gzip", "zstd", "zstd-unknown", "snappy", "snappy-framed"])
@pytest.mark.parametrize("decoded_limit", [LIMIT, None, 0], ids=["custom", "default", "zero"])
def test_http_inflation_budget(tmp_path, codec, decoded_limit):
    config = {
        "service": {"flush": 0.1, "grace": 1, "http_server": "on",
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {
            "inputs": [{"name": "http", "listen": "127.0.0.1", "http2": "on",
                        "port": "${FLUENT_BIT_TEST_LISTENER_PORT}",
                        "http_server.buffer_chunk_size": "1K",
                        "http_server.buffer_max_size": str(WIRE_LIMIT),
                        "http_server.workers": "2"}],
            "outputs": [{"name": "null", "match": "*"}],
        },
    }
    if decoded_limit is not None:
        config["pipeline"]["inputs"][0]["http_server.max_decoded_body_size"] = str(decoded_limit)
    path = tmp_path / "http.yaml"
    path.write_text(json.dumps(config))
    service = FluentBitTestService(str(path))
    encoding = codec.split("-")[0]
    prefix = b'{"message":"bounded"}'
    try:
        service.start()
        port = service.flb_listener_port
        for size in (LIMIT - 1, LIMIT):
            payload = encode(prefix + b" " * (size - len(prefix)), codec)
            assert len(payload) < WIRE_LIMIT
            assert post(port, payload, encoding) == 201
        payload = encode(prefix + b" " * (LIMIT + 1 - len(prefix)), codec)
        assert len(payload) < WIRE_LIMIT
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: post(port, payload, encoding), range(8)))
        assert results == ([None] * 8 if decoded_limit == LIMIT else [201] * 8)
        assert post(port, payload[:len(payload) // 2], encoding) is None
        if codec == "gzip":
            # A forged small ISIZE must not bypass the incremental output budget.
            assert post(port, payload[:-4] + (1).to_bytes(4, "little"), encoding) is None
        if codec == "snappy":
            # Reject an attacker-controlled allocation size before decoding.
            assert post(port, varint(0xffffffff), encoding) is None
        for unsupported in ("zlib", "deflate", "gzip, snappy", "gzip-invalid"):
            assert post(port, payload, unsupported) is None
        assert post(port, encode(prefix + b" " * 128, codec), encoding) == 201
    finally:
        service.stop()
