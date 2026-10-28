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


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="SIGHUP requires POSIX")
def test_send_sighup_forwards_signal_to_process():
    manager = FluentBitManager("/tmp/fluent-bit.yaml")
    manager.process = Mock()

    manager.send_sighup()

    manager.process.send_signal.assert_called_once_with(signal.SIGHUP)


@pytest.mark.parametrize("configured,expected", [(None, 10), (30, 30), (240, 240)])
@pytest.mark.parametrize("system", ["Linux", "Windows"])
def test_stop_uses_configured_shutdown_timeout(monkeypatch, configured, expected, system):
    monkeypatch.setattr(manager_module.platform, "system", lambda: system)
    windows_shutdown = Mock()
    monkeypatch.setattr(manager_module, "_send_windows_shutdown", windows_shutdown)
    monkeypatch.delenv("VALGRIND", raising=False)
    monkeypatch.delenv("LEAKS", raising=False)
    manager = FluentBitManager("/tmp/fluent-bit.yaml", shutdown_timeout=configured)
    process = Mock()
    process.poll.return_value = None
    manager.process = process

    manager.stop()

    if system == "Windows":
        windows_shutdown.assert_called_once_with(process.pid)
        process.send_signal.assert_not_called()
    else:
        process.send_signal.assert_called_once_with(signal.SIGTERM)
        windows_shutdown.assert_not_called()
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


@pytest.mark.parametrize("helper_error", [
    manager_module.subprocess.CalledProcessError(1, ["shutdown-helper"]),
    manager_module.subprocess.TimeoutExpired(["shutdown-helper"], 5),
])
@pytest.mark.parametrize("wait_times_out", [False, True])
def test_windows_shutdown_helper_failure_still_cleans_up(monkeypatch, helper_error, wait_times_out):
    monkeypatch.setattr(manager_module.platform, "system", lambda: "Windows")
    monkeypatch.delenv("VALGRIND", raising=False)
    monkeypatch.delenv("LEAKS", raising=False)
    monkeypatch.setattr(manager_module, "_send_windows_shutdown", Mock(side_effect=helper_error))
    manager = FluentBitManager("/tmp/fluent-bit.yaml", shutdown_timeout=1)
    process = Mock()
    process.poll.return_value = None
    if wait_times_out:
        process.wait.side_effect = [manager_module.subprocess.TimeoutExpired("fluent-bit", 1), 0]
    else:
        process.wait.return_value = 0
    output = Mock()
    manager.process = process
    manager.target_pid = 123
    manager.output_handle = output

    manager.stop()

    assert process.wait.call_args_list[0].kwargs == {"timeout": 1}
    assert process.kill.call_count == int(wait_times_out)
    output.close.assert_called_once()
    assert manager.process is None
    assert manager.target_pid is None
    assert manager.output_handle is None


def test_start_uses_unique_valgrind_log_path(monkeypatch, tmp_path):
    monkeypatch.setattr(manager_module.platform, "system", lambda: "Linux")
    config_path = tmp_path / "fluent-bit.yaml"
    config_path.write_text("service:\n  flush: 1\n", encoding="utf-8")
    popen_calls = []

    monkeypatch.setenv("VALGRIND", "1")
    monkeypatch.setattr(manager_module.shutil, "which", lambda binary: binary)
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
        "/usr/bin/fluent-bit",
        "-c", str(config_path),
        "-l", str(tmp_path / "run-1" / "fluent_bit.log")
    ]]


@pytest.mark.parametrize("system", ["Windows", "Linux", "Darwin"])
def test_console_options_isolate_windows_reload(monkeypatch, system):
    monkeypatch.setattr(manager_module.platform, "system", lambda: system)
    startup_info = Mock(dwFlags=0)
    monkeypatch.setattr(manager_module.subprocess, "STARTUPINFO", lambda: startup_info, raising=False)
    monkeypatch.setattr(manager_module.subprocess, "STARTF_USESHOWWINDOW", 1, raising=False)
    monkeypatch.setattr(manager_module.subprocess, "SW_HIDE", 0, raising=False)
    monkeypatch.setattr(manager_module.subprocess, "CREATE_NEW_CONSOLE", 16, raising=False)

    options = manager_module._console_options()

    if system == "Windows":
        assert options == {"creationflags": 16, "startupinfo": startup_info}
        assert startup_info.dwFlags == 1
        assert startup_info.wShowWindow == 0
    else:
        assert options == {}


@pytest.mark.parametrize("system,log_message,skipped", [
    ("Windows", "shared listener ports are not supported on this platform", True),
    ("Windows", "could not bind address", False),
    ("Linux", "shared listener ports are not supported on this platform", False),
])
def test_startup_skips_only_unsupported_windows_listeners(monkeypatch, tmp_path,
                                                        system, log_message, skipped):
    monkeypatch.setattr(manager_module.platform, "system", lambda: system)
    manager = FluentBitManager(str(tmp_path / "config.yaml"))
    manager.http_monitoring_port = "2020"
    manager.log_file = str(tmp_path / "fluent-bit.log")
    (tmp_path / "fluent-bit.log").write_text(log_message, encoding="utf-8")
    manager.process = Mock(returncode=1)
    manager.process.poll.return_value = 1

    expected = pytest.skip.Exception if skipped else manager_module.FluentBitStartupError
    with pytest.raises(expected):
        manager.wait_for_fluent_bit()


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
