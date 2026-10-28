#  Fluent Bit
#  ==========
#  Copyright (C) 2015-2024 The Fluent Bit Authors
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

import socket
import os
import threading
import time


_allocated_ports = set()
_allocation_lock = threading.Lock()


def _configure_probe(sock):
    if os.name == "nt":
        # SO_REUSEADDR can bind an occupied port on Windows.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    else:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


def find_available_port(starting_port=0):
    with _allocation_lock:
        return _find_available_port(starting_port)


def _find_available_port(starting_port):
    if starting_port in (None, 0):
        for _ in range(1000):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                _configure_probe(sock)
                sock.bind(("0.0.0.0", 0))
                port = sock.getsockname()[1]
                if os.name != "nt" or port not in _allocated_ports:
                    _allocated_ports.add(port)
                    return port
        raise RuntimeError("Could not allocate an unused test port")

    for port in range(starting_port, 65535):
        if os.name == "nt" and port in _allocated_ports:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                _configure_probe(sock)
                sock.bind(("0.0.0.0", port))
                _allocated_ports.add(port)
                return port
            except OSError:
                continue

    raise RuntimeError("No available ports found in the specified range")


def wait_for_port_to_be_free(port, *, host="127.0.0.1", timeout=5, interval=0.1):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                _configure_probe(sock)
                sock.bind((host, port))
                return True
            except OSError:
                time.sleep(interval)
    return False
