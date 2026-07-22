import signal

import pytest

from utils import fluent_bit_manager as manager_module
from utils.fluent_bit_manager import FluentBitManager, FluentBitStartupError


class FakeProcess:
    def __init__(self, return_code=0):
        self.pid = 1234
        self.return_code = return_code
        self.returncode = None
        self.killed = False
        self.signals = []

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.returncode = self.return_code
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -signal.SIGKILL

    def send_signal(self, signal_number):
        self.signals.append(signal_number)


def _prepare_start(monkeypatch, tmp_path, process):
    config_path = tmp_path / "fluent-bit.yaml"
    binary_path = tmp_path / "fluent-bit"
    config_path.write_text("service:\n  flush: 1\n", encoding="utf-8")
    binary_path.write_text("binary", encoding="utf-8")
    binary_path.chmod(0o755)

    monkeypatch.setenv("LEAKS", "1")
    monkeypatch.setattr(manager_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        manager_module.shutil,
        "which",
        lambda command: "/usr/bin/leaks" if command == "leaks" else None,
    )
    monkeypatch.setattr(manager_module, "find_available_port", lambda starting_port: 40200)
    monkeypatch.setattr(manager_module.requests, "get", lambda url, timeout: FakeResponse())
    monkeypatch.setattr(FluentBitManager, "get_version_info", lambda self: ("vtest", "commit"))
    monkeypatch.setattr(FluentBitManager, "_wait_for_leaks_target_pid", lambda self: 4321)
    monkeypatch.setattr(manager_module, "wait_for_port_to_be_free", lambda port, timeout: None)

    popen_calls = []

    def fake_popen(command, stdout=None, stderr=None, text=None):
        popen_calls.append(
            {
                "command": command,
                "output_path": stdout.name,
                "stderr": stderr,
                "text": text,
            }
        )
        return process

    monkeypatch.setattr(manager_module.subprocess, "Popen", fake_popen)

    return config_path, binary_path, popen_calls


class FakeResponse:
    status_code = 200

    def json(self):
        return {"uptime_sec": 2}


def test_leaks_supervisor_signals_fluent_bit_target(monkeypatch, tmp_path):
    process = FakeProcess()
    config_path, binary_path, popen_calls = _prepare_start(monkeypatch, tmp_path, process)
    delivered_signals = []
    monkeypatch.setattr(
        manager_module.os,
        "kill",
        lambda pid, signal_number: delivered_signals.append((pid, signal_number)),
    )

    manager = FluentBitManager(str(config_path), str(binary_path))
    manager.start()

    assert manager.target_pid == 4321
    assert popen_calls[0]["command"] == [
        "/usr/bin/leaks",
        "--quiet",
        "--fullStacks",
        "--atExit",
        "--",
        "/bin/sh",
        "-c",
        manager_module.LEAKS_EXEC_SCRIPT,
        "fluent-bit-leaks-target",
        manager.leaks_target_pid_file,
        manager.log_file,
        str(binary_path),
        "-c",
        str(config_path),
        "-l",
        manager.log_file,
    ]
    assert popen_calls[0]["output_path"] == manager.leaks_log_file

    manager.send_sighup()
    manager.stop()

    assert delivered_signals == [
        (4321, signal.SIGHUP),
        (4321, signal.SIGTERM),
    ]
    assert process.signals == []
    assert process.returncode == 0


def test_leaks_strict_fails_when_leaks_reports_leak(monkeypatch, tmp_path):
    process = FakeProcess(return_code=1)
    config_path, binary_path, _ = _prepare_start(monkeypatch, tmp_path, process)
    monkeypatch.setenv("LEAKS_STRICT", "1")
    monkeypatch.setattr(manager_module.os, "kill", lambda pid, signal_number: None)

    manager = FluentBitManager(str(config_path), str(binary_path))
    manager.start()

    with pytest.raises(AssertionError, match="memory leaks were detected"):
        manager.stop()


def test_leaks_supervisor_failure_still_terminates_target(monkeypatch):
    process = FakeProcess(return_code=255)
    process.returncode = 255
    delivered_signals = []
    monkeypatch.setenv("LEAKS", "1")
    monkeypatch.setattr(
        manager_module.os,
        "kill",
        lambda pid, signal_number: delivered_signals.append((pid, signal_number)),
    )

    manager = FluentBitManager("/tmp/fluent-bit.yaml", "/tmp/fluent-bit")
    manager.process = process
    manager.target_pid = 4321

    manager.stop()

    assert delivered_signals == [(4321, signal.SIGTERM)]


def test_leaks_rejects_non_macos_host(monkeypatch):
    monkeypatch.setattr(manager_module.platform, "system", lambda: "Linux")
    manager = FluentBitManager("/tmp/fluent-bit.yaml", "/tmp/fluent-bit")

    with pytest.raises(FluentBitStartupError, match="only supported on macOS"):
        manager._build_leaks_command(["/tmp/fluent-bit"])


def test_results_directories_are_unique_for_concurrent_supervisors(tmp_path):
    manager = FluentBitManager("/tmp/fluent-bit.yaml", "/tmp/fluent-bit")

    first = manager.create_results_directory(tmp_path)
    second = manager.create_results_directory(tmp_path)

    assert first != second
