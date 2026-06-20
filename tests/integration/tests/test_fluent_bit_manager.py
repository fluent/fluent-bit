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

import signal
from unittest.mock import Mock

import pytest
import requests

from src.utils import fluent_bit_manager as manager_module
from src.utils.fluent_bit_manager import ENV_FLB_BINARY_PATH
from src.utils.fluent_bit_manager import FluentBitManager


def test_binary_path_uses_environment_override(monkeypatch):
    monkeypatch.setenv(ENV_FLB_BINARY_PATH, "/opt/fluent-bit/bin/fluent-bit")
    monkeypatch.setattr(manager_module.shutil, "which", lambda path: f"/resolved/{path}")

    manager = FluentBitManager("/tmp/fluent-bit.yaml")

    assert manager.binary_path == "/opt/fluent-bit/bin/fluent-bit"
    assert manager.binary_absolute_path == "/resolved//opt/fluent-bit/bin/fluent-bit"


def test_send_signal_raises_when_process_is_missing():
    manager = FluentBitManager("/tmp/fluent-bit.yaml")

    with pytest.raises(RuntimeError, match="not running"):
        manager.send_signal(signal.SIGHUP)


def test_send_sighup_forwards_signal_to_process():
    manager = FluentBitManager("/tmp/fluent-bit.yaml")
    manager.process = Mock()

    manager.send_sighup()

    manager.process.send_signal.assert_called_once_with(signal.SIGHUP)


def test_trigger_http_reload_posts_to_reload_endpoint(monkeypatch):
    response = Mock()
    response.json.return_value = {"reload": "done"}
    response.raise_for_status.return_value = None

    def fake_post(url):
        assert url == "http://127.0.0.1:2020/api/v2/reload"
        return response

    monkeypatch.setattr(manager_module.requests, "post", fake_post)

    manager = FluentBitManager("/tmp/fluent-bit.yaml")
    manager.http_monitoring_port = "2020"

    assert manager.trigger_http_reload() == {"reload": "done"}


def test_start_uses_unique_valgrind_log_path(monkeypatch, tmp_path):
    config_path = tmp_path / "fluent-bit.yaml"
    config_path.write_text("service:\n  flush: 1\n", encoding="utf-8")
    popen_calls = []

    monkeypatch.setenv("VALGRIND", "1")
    monkeypatch.setattr(manager_module.os.path, "exists", lambda path: True)
    monkeypatch.setattr(manager_module, "find_available_port", lambda starting_port: 40200)
    monkeypatch.setattr(manager_module.requests, "get", lambda url: Mock(status_code=200, json=lambda: {"uptime_sec": 2}))

    created_dirs = iter([
        str(tmp_path / "run-1"),
    ])

    def fake_create_results_directory(self, base_dir='results'):
        path = next(created_dirs)
        manager_module.os.makedirs(path, exist_ok=True)
        return path

    popen_result = Mock()
    popen_result.pid = 1234

    monkeypatch.setattr(FluentBitManager, "create_results_directory", fake_create_results_directory)
    monkeypatch.setattr(FluentBitManager, "get_version_info", lambda self: ("vtest", "commit"))

    def fake_popen(command, stdout=None, stderr=None):
        popen_calls.append(command)
        return popen_result

    monkeypatch.setattr(manager_module.subprocess, "Popen", fake_popen)

    manager = FluentBitManager(str(config_path), "/usr/bin/fluent-bit")
    manager.start()

    assert manager.results_dir == str(tmp_path / "run-1")
    assert manager.valgrind_log_file == str(tmp_path / "run-1" / "valgrind.log")
    assert popen_calls == [[
        "valgrind",
        f"--log-file={manager.valgrind_log_file}",
        "--leak-check=full",
        "/usr/bin/fluent-bit",
        "-c", str(config_path),
        "-l", str(tmp_path / "run-1" / "fluent_bit.log")
    ]]


def test_wait_for_hot_reload_count_returns_when_expected_count_is_reached(monkeypatch):
    manager = FluentBitManager("/tmp/fluent-bit.yaml")
    manager.http_monitoring_port = "2020"

    payloads = iter([
        {"hot_reload_count": 0},
        {"hot_reload_count": 1},
        {"hot_reload_count": 2},
    ])

    monkeypatch.setattr(manager, "get_reload_status", lambda: next(payloads))
    monkeypatch.setattr(manager_module.time, "sleep", lambda _: None)

    payload = manager.wait_for_hot_reload_count(2, timeout=5)

    assert payload["hot_reload_count"] == 2


def test_wait_for_hot_reload_count_ignores_request_errors(monkeypatch):
    manager = FluentBitManager("/tmp/fluent-bit.yaml")
    manager.http_monitoring_port = "2020"

    values = iter([
        requests.RequestException("boom"),
        {"hot_reload_count": 1},
    ])

    def fake_get_reload_status():
        value = next(values)
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(manager, "get_reload_status", fake_get_reload_status)
    monkeypatch.setattr(manager_module.time, "sleep", lambda _: None)

    payload = manager.wait_for_hot_reload_count(1, timeout=5)

    assert payload["hot_reload_count"] == 1


def test_wait_for_hot_reload_count_times_out(monkeypatch):
    manager = FluentBitManager("/tmp/fluent-bit.yaml")
    manager.http_monitoring_port = "2020"

    timestamps = iter([0.0, 0.1, 0.2, 0.3])

    monkeypatch.setattr(manager, "get_reload_status", lambda: {"hot_reload_count": 0})
    monkeypatch.setattr(manager_module.time, "time", lambda: next(timestamps))
    monkeypatch.setattr(manager_module.time, "sleep", lambda _: None)

    with pytest.raises(TimeoutError, match="Timed out waiting for hot reload count 1"):
        manager.wait_for_hot_reload_count(1, timeout=0.25)
