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

import gzip
import logging
import socket
import struct
import subprocess
import threading
import time


logger = logging.getLogger(__name__)

data_storage = {
    "messages": [],
    "connections": [],
}

server_thread = None
server_port = None
server_stop_event = threading.Event()


class IncompleteBuffer(Exception):
    pass


def reset_forward_server_state():
    data_storage["messages"] = []
    data_storage["connections"] = []
    server_stop_event.clear()


def _decode_str_like(raw):
    try:
        return raw.decode()
    except UnicodeDecodeError:
        return raw


def _require_bytes(data, offset, size):
    end = offset + size
    if end > len(data):
        raise IncompleteBuffer()
    return end


def _unpack_array(data, offset, size):
    result = []
    for _ in range(size):
        value, offset = _unpack_obj(data, offset)
        result.append(value)
    return result, offset


def _unpack_map(data, offset, size):
    result = {}
    for _ in range(size):
        key, offset = _unpack_obj(data, offset)
        value, offset = _unpack_obj(data, offset)
        result[key] = value
    return result, offset


def _unpack_ext(data, offset, payload_size):
    end = _require_bytes(data, offset, 1 + payload_size)
    ext_type = int.from_bytes(data[offset:offset + 1], "big", signed=True)
    payload_offset = offset + 1
    return {"__ext__": {"type": ext_type, "data": data[payload_offset:end]}}, end


def _unpack_obj(data, offset):
    if offset >= len(data):
        raise IncompleteBuffer()

    first = data[offset]
    offset += 1

    if first <= 0x7F:
        return first, offset
    if first >= 0xE0:
        return first - 0x100, offset
    if 0x80 <= first <= 0x8F:
        return _unpack_map(data, offset, first & 0x0F)
    if 0x90 <= first <= 0x9F:
        return _unpack_array(data, offset, first & 0x0F)
    if 0xA0 <= first <= 0xBF:
        size = first & 0x1F
        end = _require_bytes(data, offset, size)
        raw = data[offset:end]
        return _decode_str_like(raw), end
    if first == 0xC0:
        return None, offset
    if first == 0xC2:
        return False, offset
    if first == 0xC3:
        return True, offset
    if first == 0xC4:
        _require_bytes(data, offset, 1)
        size = data[offset]
        offset += 1
        end = _require_bytes(data, offset, size)
        return data[offset:end], end
    if first == 0xC5:
        _require_bytes(data, offset, 2)
        size = int.from_bytes(data[offset:offset + 2], "big")
        offset += 2
        end = _require_bytes(data, offset, size)
        return data[offset:end], end
    if first == 0xC6:
        _require_bytes(data, offset, 4)
        size = int.from_bytes(data[offset:offset + 4], "big")
        offset += 4
        end = _require_bytes(data, offset, size)
        return data[offset:end], end
    if first == 0xCA:
        _require_bytes(data, offset, 4)
        return struct.unpack(">f", data[offset:offset + 4])[0], offset + 4
    if first == 0xCB:
        _require_bytes(data, offset, 8)
        return struct.unpack(">d", data[offset:offset + 8])[0], offset + 8
    if first == 0xCC:
        _require_bytes(data, offset, 1)
        return data[offset], offset + 1
    if first == 0xCD:
        _require_bytes(data, offset, 2)
        return int.from_bytes(data[offset:offset + 2], "big"), offset + 2
    if first == 0xCE:
        _require_bytes(data, offset, 4)
        return int.from_bytes(data[offset:offset + 4], "big"), offset + 4
    if first == 0xCF:
        _require_bytes(data, offset, 8)
        return int.from_bytes(data[offset:offset + 8], "big"), offset + 8
    if first == 0xD0:
        _require_bytes(data, offset, 1)
        return int.from_bytes(data[offset:offset + 1], "big", signed=True), offset + 1
    if first == 0xD1:
        _require_bytes(data, offset, 2)
        return int.from_bytes(data[offset:offset + 2], "big", signed=True), offset + 2
    if first == 0xD2:
        _require_bytes(data, offset, 4)
        return int.from_bytes(data[offset:offset + 4], "big", signed=True), offset + 4
    if first == 0xD3:
        _require_bytes(data, offset, 8)
        return int.from_bytes(data[offset:offset + 8], "big", signed=True), offset + 8
    if first == 0xD4:
        return _unpack_ext(data, offset, 1)
    if first == 0xD5:
        return _unpack_ext(data, offset, 2)
    if first == 0xD6:
        return _unpack_ext(data, offset, 4)
    if first == 0xD7:
        return _unpack_ext(data, offset, 8)
    if first == 0xD8:
        return _unpack_ext(data, offset, 16)
    if first == 0xD9:
        _require_bytes(data, offset, 1)
        size = data[offset]
        offset += 1
        end = _require_bytes(data, offset, size)
        return _decode_str_like(data[offset:end]), end
    if first == 0xDA:
        _require_bytes(data, offset, 2)
        size = int.from_bytes(data[offset:offset + 2], "big")
        offset += 2
        end = _require_bytes(data, offset, size)
        return _decode_str_like(data[offset:end]), end
    if first == 0xDB:
        _require_bytes(data, offset, 4)
        size = int.from_bytes(data[offset:offset + 4], "big")
        offset += 4
        end = _require_bytes(data, offset, size)
        return _decode_str_like(data[offset:end]), end
    if first == 0xDC:
        _require_bytes(data, offset, 2)
        size = int.from_bytes(data[offset:offset + 2], "big")
        return _unpack_array(data, offset + 2, size)
    if first == 0xDD:
        _require_bytes(data, offset, 4)
        size = int.from_bytes(data[offset:offset + 4], "big")
        return _unpack_array(data, offset + 4, size)
    if first == 0xDE:
        _require_bytes(data, offset, 2)
        size = int.from_bytes(data[offset:offset + 2], "big")
        return _unpack_map(data, offset + 2, size)
    if first == 0xDF:
        _require_bytes(data, offset, 4)
        size = int.from_bytes(data[offset:offset + 4], "big")
        return _unpack_map(data, offset + 4, size)

    raise ValueError(f"Unsupported MessagePack type 0x{first:02x}")


def _pack_str(value):
    data = value.encode()
    length = len(data)
    if length <= 31:
        return bytes([0xA0 | length]) + data
    if length <= 0xFF:
        return b"\xD9" + bytes([length]) + data
    return b"\xDA" + length.to_bytes(2, "big") + data


def _pack_map(mapping):
    items = list(mapping.items())
    prefix = bytes([0x80 | len(items)])
    encoded = []
    for key, value in items:
        encoded.append(_pack_obj(key))
        encoded.append(_pack_obj(value))
    return prefix + b"".join(encoded)


def _pack_obj(value):
    if isinstance(value, str):
        return _pack_str(value)
    if isinstance(value, bytes):
        length = len(value)
        if length <= 0xFF:
            return b"\xC4" + bytes([length]) + value
        return b"\xC5" + length.to_bytes(2, "big") + value
    if isinstance(value, dict):
        return _pack_map(value)
    raise TypeError(f"Unsupported pack type {type(value)!r}")


def _send_ack(sock, chunk):
    sock.sendall(_pack_obj({"ack": chunk}))


def _decode_packed_entries(entry, options):
    payload = entry
    if options.get("compressed") == "gzip":
        payload = gzip.decompress(payload)
    elif options.get("compressed") == "zstd":
        result = subprocess.run(
            ["zstd", "-d", "-c"],
            input=payload,
            capture_output=True,
            check=True,
        )
        payload = result.stdout

    records = []
    offset = 0
    while offset < len(payload):
        value, offset = _unpack_obj(payload, offset)
        records.append(_normalize_forward_record(value))
    return records


def _normalize_forward_record(entry):
    if not isinstance(entry, list):
        return {"raw": entry}

    if (
        len(entry) == 2 and
        isinstance(entry[0], list) and
        len(entry[0]) == 2
    ):
        return {
            "timestamp": entry[0][0],
            "metadata": entry[0][1],
            "body": entry[1],
            "raw": entry,
        }

    if len(entry) == 2:
        return {"timestamp": entry[0], "body": entry[1], "metadata": None, "raw": entry}
    if len(entry) == 3:
        return {"timestamp": entry[0], "metadata": entry[1], "body": entry[2], "raw": entry}

    return {"raw": entry}


def _classify_message(root):
    tag = root[0] if isinstance(root, list) and len(root) > 0 else None
    entry = root[1] if isinstance(root, list) and len(root) > 1 else None
    options = root[2] if isinstance(root, list) and len(root) > 2 and isinstance(root[2], dict) else {}

    message = {
        "raw": root,
        "tag": tag,
        "options": options,
        "records": [],
        "mode": "unknown",
    }

    if isinstance(entry, list) and entry and isinstance(entry[0], list):
        message["mode"] = "forward"
        message["records"] = [_normalize_forward_record(item) for item in entry]
    elif isinstance(entry, (bytes, bytearray)):
        message["mode"] = "packed_forward"
        message["records"] = _decode_packed_entries(bytes(entry), options)
    elif len(root) >= 3:
        message["mode"] = "message"
        message["records"] = [_normalize_forward_record(root[1:4])]

    return message


def _handle_client(conn, address):
    data_storage["connections"].append({"peer": address})
    buffer = b""
    conn.settimeout(0.5)

    while not server_stop_event.is_set():
        try:
            chunk = conn.recv(4096)
        except socket.timeout:
            continue
        except OSError:
            break

        if not chunk:
            break

        buffer += chunk

        while buffer:
            try:
                message, offset = _unpack_obj(buffer, 0)
            except IncompleteBuffer:
                break

            buffer = buffer[offset:]

            if isinstance(message, list):
                decoded = _classify_message(message)
                data_storage["messages"].append(decoded)

                chunk_id = decoded["options"].get("chunk")
                if chunk_id is not None:
                    _send_ack(conn, chunk_id)
            else:
                data_storage["messages"].append({"raw": message, "mode": "unknown", "tag": None, "options": {}, "records": []})


def run_forward_server(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", port))
        server.listen()
        server.settimeout(0.5)
        logger.info("Starting forward server on port %s", port)

        while not server_stop_event.is_set():
            try:
                conn, address = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            with conn:
                _handle_client(conn, address)


def forward_server_run(port):
    global server_thread, server_port

    reset_forward_server_state()
    server_port = port
    server_thread = threading.Thread(target=run_forward_server, args=(port,), daemon=True)
    server_thread.start()
    deadline = time.time() + 5
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return server_thread
        time.sleep(0.1)

    raise TimeoutError(f"Timed out waiting for forward server on port {port}")


def forward_server_stop():
    server_stop_event.set()
    if server_port is not None:
        try:
            with socket.create_connection(("127.0.0.1", server_port), timeout=0.2):
                pass
        except Exception:
            pass
