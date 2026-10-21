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
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests

from src.utils import fluent_bit_manager as manager_module
from src.utils.fluent_bit_manager import ENV_FLB_BINARY_PATH
from src.utils.fluent_bit_manager import FluentBitManager
from src.utils.fluent_bit_manager import fluent_bit_binary_version
from src.utils.fluent_bit_manager import fluent_bit_binary_supports_config_property
from src.utils.fluent_bit_manager import fluent_bit_input_supports_config_property
from src.utils.fluent_bit_manager import parse_fluent_bit_version


def test_binary_path_uses_environment_override(monkeypatch):
    monkeypatch.setenv(ENV_FLB_BINARY_PATH, "/opt/fluent-bit/bin/fluent-bit")
    monkeypatch.setattr(manager_module.shutil, "which", lambda path: f"/resolved/{path}")

    manager = FluentBitManager("/tmp/fluent-bit.yaml")

    assert manager.binary_path == "/opt/fluent-bit/bin/fluent-bit"
    assert manager.binary_absolute_path == "/resolved//opt/fluent-bit/bin/fluent-bit"


def test_binary_capability_detects_config_property_in_help(monkeypatch, tmp_path):
    binary_path = tmp_path / "fluent-bit"
    binary_path.write_bytes(b"binary without the marker")
    binary_path.chmod(0o755)
    result = Mock(stdout="Options: hot_reload.watch", stderr="")
    monkeypatch.setattr(manager_module.subprocess, "run", lambda *args, **kwargs: result)

    assert fluent_bit_binary_supports_config_property(
        "hot_reload.watch", str(binary_path)
    ) is True


def test_binary_capability_detects_compiled_config_property(monkeypatch, tmp_path):
    binary_path = tmp_path / "fluent-bit"
    binary_path.write_bytes(b"prefix Hot_Reload.Watch suffix")
    binary_path.chmod(0o755)
    result = Mock(stdout="", stderr="")
    monkeypatch.setattr(manager_module.subprocess, "run", lambda *args, **kwargs: result)

    assert fluent_bit_binary_supports_config_property(
        "hot_reload.watch", str(binary_path)
    ) is True


def test_binary_capability_rejects_missing_config_property(monkeypatch, tmp_path):
    binary_path = tmp_path / "fluent-bit"
    binary_path.write_bytes(b"binary without the marker")
    binary_path.chmod(0o755)
    result = Mock(stdout="", stderr="")
    monkeypatch.setattr(manager_module.subprocess, "run", lambda *args, **kwargs: result)

    assert fluent_bit_binary_supports_config_property(
        "hot_reload.watch", str(binary_path)
    ) is False


def test_input_capability_detects_plugin_config_property(monkeypatch, tmp_path):
    binary_path = tmp_path / "fluent-bit"
    binary_path.write_bytes(b"binary")
    binary_path.chmod(0o755)
    result = Mock(stdout="workers  Set the number of listener workers", stderr="")

    def fake_run(command, **kwargs):
        assert command == [str(binary_path), "-i", "forward", "-h"]
        return result

    monkeypatch.setattr(manager_module.subprocess, "run", fake_run)

    assert fluent_bit_input_supports_config_property(
        "forward", "workers", str(binary_path)
    ) is True


def test_input_capability_rejects_property_from_other_plugins(monkeypatch, tmp_path):
    binary_path = tmp_path / "fluent-bit"
    binary_path.write_bytes(b"binary containing inotify_watcher elsewhere")
    binary_path.chmod(0o755)
    result = Mock(stdout="path  Path to tail", stderr="")
    monkeypatch.setattr(manager_module.subprocess, "run", lambda *args, **kwargs: result)

    assert fluent_bit_input_supports_config_property(
        "tail", "inotify_watcher", str(binary_path)
    ) is False


@pytest.mark.parametrize(
    "version_text,expected",
    [
        ("Fluent Bit v5.1.0", (5, 1, 0)),
        ("Fluent Bit 5.0.9\nGit commit: abc", (5, 0, 9)),
        ("v6.2.1-dev", (6, 2, 1)),
        ("unknown", None),
    ],
)
def test_parse_fluent_bit_version(version_text, expected):
    assert parse_fluent_bit_version(version_text) == expected


def test_fluent_bit_binary_version_uses_selected_binary(monkeypatch, tmp_path):
    binary_path = tmp_path / "fluent-bit"
    binary_path.write_bytes(b"binary")
    binary_path.chmod(0o755)
    result = Mock(stdout="Fluent Bit v5.1.0", stderr="")

    def fake_run(command, **kwargs):
        assert command == [str(binary_path), "--version"]
        return result

    monkeypatch.setattr(manager_module.subprocess, "run", fake_run)

    assert fluent_bit_binary_version(str(binary_path)) == (5, 1, 0)


def test_fluent_bit_binary_version_is_cached(monkeypatch, tmp_path):
    binary_path = tmp_path / "fluent-bit"
    binary_path.write_bytes(b"binary")
    binary_path.chmod(0o755)
    result = Mock(stdout="Fluent Bit v5.1.0\nGit commit: abc123", stderr="")
    run = Mock(return_value=result)
    monkeypatch.setattr(manager_module.subprocess, "run", run)

    assert fluent_bit_binary_version(str(binary_path)) == (5, 1, 0)
    manager = FluentBitManager("/tmp/fluent-bit.yaml", binary_path=str(binary_path))
    assert manager.get_version_info() == ("v5.1.0", "abc123")
    run.assert_called_once()


def test_send_signal_raises_when_process_is_missing():
    manager = FluentBitManager("/tmp/fluent-bit.yaml")

    with pytest.raises(RuntimeError, match="not running"):
        manager.send_signal(signal.SIGTERM)


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="SIGHUP is unavailable on Windows")
def test_send_sighup_forwards_signal_to_process():
    manager = FluentBitManager("/tmp/fluent-bit.yaml")
    manager.process = Mock()

    manager.send_sighup()

    manager.process.send_signal.assert_called_once_with(signal.SIGHUP)


@pytest.mark.parametrize("configured,expected", [(None, 10), (30, 30), (240, 240)])
def test_stop_uses_configured_shutdown_timeout(monkeypatch, configured, expected):
    monkeypatch.delenv("VALGRIND", raising=False)
    monkeypatch.delenv("LEAKS", raising=False)
    manager = FluentBitManager("/tmp/fluent-bit.yaml", shutdown_timeout=configured)
    process = Mock()
    process.poll.return_value = None
    manager.process = process
    windows_shutdown = Mock()
    monkeypatch.setattr(manager, "_send_windows_shutdown", windows_shutdown)

    manager.stop()

    if manager_module.os.name == "nt":
        windows_shutdown.assert_called_once_with(process.pid)
        process.send_signal.assert_not_called()
    else:
        process.send_signal.assert_called_once_with(signal.SIGTERM)
    process.wait.assert_called_once_with(timeout=expected)


def test_trigger_http_reload_posts_to_reload_endpoint(monkeypatch):
    response = Mock()
    response.json.return_value = {"reload": "done"}
    response.raise_for_status.return_value = None

    def fake_post(url, timeout):
        assert url == "http://127.0.0.1:2020/api/v2/reload"
        assert timeout == 0.5
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
    monkeypatch.setattr(manager_module.os.path, "isfile", lambda path: True)
    monkeypatch.setattr(manager_module.os, "access", lambda path, mode: True)
    monkeypatch.setattr(manager_module, "find_available_port", lambda starting_port: 40200)
    monkeypatch.setattr(
        manager_module.requests,
        "get",
        lambda url, timeout=0.5: Mock(status_code=200, json=lambda: {"uptime_sec": 2}),
    )

    created_dirs = iter([
        str(tmp_path / "run-1"),
    ])

    def fake_create_results_directory(self, base_dir='results'):
        path = next(created_dirs)
        manager_module.os.makedirs(path, exist_ok=True)
        return path

    popen_result = Mock()
    popen_result.pid = 1234
    popen_result.poll.return_value = None

    monkeypatch.setattr(FluentBitManager, "create_results_directory", fake_create_results_directory)
    monkeypatch.setattr(FluentBitManager, "get_version_info", lambda self: ("vtest", "commit"))

    def fake_popen(command, stdout=None, stderr=None, **kwargs):
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
        "--show-leak-kinds=all",
        manager.binary_absolute_path,
        "-c", str(config_path),
        "-l", str(tmp_path / "run-1" / "fluent_bit.log")
    ]]


@pytest.mark.parametrize("error", [requests.ConnectionError, requests.ReadTimeout])
def test_startup_health_check_retries_transient_errors(monkeypatch, error):
    manager = FluentBitManager("/tmp/fluent-bit.yaml")
    manager.http_monitoring_port = "2020"
    response = Mock(status_code=200)
    response.json.return_value = {"uptime_sec": 2}
    get = Mock(side_effect=[error("not ready"), response])
    monkeypatch.setattr(manager_module.requests, "get", get)
    monkeypatch.setattr(manager_module.time, "sleep", lambda _: None)

    assert manager.wait_for_fluent_bit(timeout=5) is True
    assert get.call_count == 2


def test_startup_health_check_timeouts_respect_deadline(monkeypatch):
    manager = FluentBitManager("/tmp/fluent-bit.yaml")
    manager.http_monitoring_port = "2020"
    timestamps = iter([0.0, 0.1, 0.2, 0.3])
    monkeypatch.setattr(manager_module.time, "time", lambda: next(timestamps))
    monkeypatch.setattr(manager_module.time, "sleep", lambda _: None)
    monkeypatch.setattr(
        manager_module.requests, "get", Mock(side_effect=requests.ReadTimeout("not ready"))
    )

    with pytest.raises(manager_module.FluentBitStartupError, match="did not start within"):
        manager.wait_for_fluent_bit(timeout=0.25)


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


@pytest.mark.parametrize("failed_api", [None, "AttachConsole", "SetConsoleCtrlHandler",
                                       "GenerateConsoleCtrlEvent"])
def test_windows_shutdown_helper_runs_with_optimization(monkeypatch, failed_api, capsys):
    run = Mock()
    monkeypatch.setattr(manager_module.subprocess, "run", run)
    monkeypatch.setattr(manager_module.subprocess, "CREATE_NO_WINDOW", 0, raising=False)
    FluentBitManager._send_windows_shutdown(1234)
    helper = run.call_args.args[0][2]
    kernel = Mock()
    for name in ("AttachConsole", "SetConsoleCtrlHandler", "GenerateConsoleCtrlEvent"):
        getattr(kernel, name).return_value = name != failed_api
    get_last_error = Mock(return_value=5)
    ctypes_stub = SimpleNamespace(
        WinDLL=Mock(return_value=kernel), get_last_error=get_last_error,
        WinError=lambda code: RuntimeError(f"Windows error {code}"),
    )
    monkeypatch.setitem(sys.modules, "ctypes", ctypes_stub)
    monkeypatch.setattr(sys, "argv", ["-c", "1234"])
    monkeypatch.setattr(manager_module.time, "sleep", Mock())

    optimized_helper = compile(helper, "<shutdown-helper>", "exec", optimize=2)
    if failed_api == "AttachConsole":
        with pytest.raises(SystemExit) as error:
            exec(optimized_helper, {})
        assert error.value.code == manager_module._WINDOWS_ATTACH_CONSOLE_FAILED
        assert "AttachConsole failed: 5" in capsys.readouterr().err
    elif failed_api:
        with pytest.raises(RuntimeError, match="Windows error 5"):
            exec(optimized_helper, {})
    else:
        exec(optimized_helper, {})

    kernel.AttachConsole.assert_called_once_with(1234)
    if failed_api != "AttachConsole":
        kernel.SetConsoleCtrlHandler.assert_called_once_with(None, True)
    else:
        kernel.SetConsoleCtrlHandler.assert_not_called()
    if failed_api not in ("AttachConsole", "SetConsoleCtrlHandler"):
        kernel.GenerateConsoleCtrlEvent.assert_called_once_with(0, 0)
    else:
        kernel.GenerateConsoleCtrlEvent.assert_not_called()
    assert kernel.FreeConsole.call_count == (1 if failed_api == "AttachConsole" else 2)
    assert get_last_error.call_count == (1 if failed_api else 0)


@pytest.mark.skipif(manager_module.os.name != "nt", reason="Windows console shutdown")
@pytest.mark.parametrize("error_code,exited,raises", [
    (manager_module._WINDOWS_ATTACH_CONSOLE_FAILED, True, False),
    (manager_module._WINDOWS_ATTACH_CONSOLE_FAILED, False, True),
    (1, True, True),
    (1, False, True),
])
def test_windows_shutdown_failure_cleans_up(monkeypatch, error_code, exited, raises):
    monkeypatch.delenv("VALGRIND", raising=False)
    monkeypatch.delenv("LEAKS", raising=False)
    manager = FluentBitManager("/tmp/fluent-bit.yaml", shutdown_timeout=1)
    process = Mock()
    process.poll.side_effect = [None, None, 0 if exited else None]
    if exited:
        process.wait.return_value = 0
    else:
        process.wait.side_effect = subprocess.TimeoutExpired("fluent-bit", 1)
    manager.process = process
    manager.target_pid = 1234
    handle = manager.output_handle = Mock()
    helper_error = subprocess.CalledProcessError(error_code, "shutdown-helper")
    monkeypatch.setattr(manager, "_send_windows_shutdown", Mock(side_effect=helper_error))
    force_stop = Mock()
    monkeypatch.setattr(manager, "_force_stop", force_stop)

    if raises:
        with pytest.raises(subprocess.CalledProcessError) as error:
            manager.stop()
        assert error.value is helper_error
    else:
        manager.stop()

    assert manager.process is None
    assert manager.target_pid is None
    assert manager.output_handle is None
    handle.close.assert_called_once()
    assert force_stop.call_count == (0 if exited else 1)
    if error_code == manager_module._WINDOWS_ATTACH_CONSOLE_FAILED:
        assert process.poll.call_count == 3
