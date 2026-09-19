from types import SimpleNamespace

import pytest
import requests

from utils import fluent_bit_manager as manager_module
from utils.fluent_bit_manager import FluentBitManager, FluentBitStartupError


def prepare_manager(monkeypatch):
    manager = FluentBitManager.__new__(FluentBitManager)
    manager.process = None
    manager.http_monitoring_port = 12345
    manager.log_file = 'startup-test.log'
    clock = [0]
    monkeypatch.setattr(manager_module, 'time', SimpleNamespace(
        time=lambda: clock[0], sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds)))
    return manager, clock


@pytest.mark.parametrize('error', [requests.ReadTimeout, requests.ConnectTimeout, requests.ConnectionError])
def test_startup_retries_transient_health_failure(monkeypatch, error):
    manager, clock = prepare_manager(monkeypatch)
    calls = []

    def get(url, timeout):
        calls.append((url, timeout))
        if len(calls) == 1:
            raise error('not ready')
        return SimpleNamespace(status_code=200, json=lambda: {'uptime_sec': 2})

    monkeypatch.setattr(manager_module.requests, 'get', get)
    assert manager.wait_for_fluent_bit(timeout=3)
    assert len(calls) == 2 and clock[0] == 1


def test_startup_timeout_still_has_a_deadline(monkeypatch):
    manager, clock = prepare_manager(monkeypatch)

    def get(url, timeout):
        raise requests.ReadTimeout('still not ready')

    monkeypatch.setattr(manager_module.requests, 'get', get)
    with pytest.raises(FluentBitStartupError, match='did not start within 3 seconds'):
        manager.wait_for_fluent_bit(timeout=3)
    assert clock[0] == 3


def test_startup_does_not_hide_process_exit(monkeypatch):
    manager, _ = prepare_manager(monkeypatch)
    manager.process = SimpleNamespace(poll=lambda: 1, returncode=1)
    with pytest.raises(FluentBitStartupError, match='exited early with code 1'):
        manager.wait_for_fluent_bit(timeout=3)


def test_startup_does_not_hide_unexpected_errors(monkeypatch):
    manager, _ = prepare_manager(monkeypatch)

    def get(url, timeout):
        raise RuntimeError('unexpected')

    monkeypatch.setattr(manager_module.requests, 'get', get)
    with pytest.raises(RuntimeError, match='unexpected'):
        manager.wait_for_fluent_bit(timeout=3)
