"""Exercise systemd snapshots through the real node exporter and OTLP output."""

import asyncio
from concurrent.futures import Future
from contextlib import contextmanager
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time

import pytest

if sys.platform != "linux":
    pytest.skip("The systemd collector requires Linux", allow_module_level=True)

from dbus_next import Message, MessageType, Variant
from dbus_next.aio import MessageBus

from server.otlp_server import data_storage, otlp_server_run, stop_otlp_server
from utils.test_service import FluentBitTestService


class SystemdManager:
    """Serve only the systemd calls used by the collector, on a private bus."""

    def __init__(self):
        self.units = ("keep.service", "gone.service", "gone.socket", "gone.timer")
        self.unloaded = False
        self.service_type = "simple"
        self.tasks = 7
        self.fail_list = False

    def handle(self, message):
        if message.message_type != MessageType.METHOD_CALL:
            return None
        if message.member == "ListUnits":
            if self.fail_list:
                return Message.new_error(message, "org.freedesktop.DBus.Error.Failed", "test failure")
            units = [
                [name, name, "not-found" if self.unloaded else "loaded",
                 "active", "running", "", f"/units/{index}", 0, "", "/"]
                for index, name in enumerate(self.units)
            ]
            return Message.new_method_return(message, "a(ssssssouso)", [units])
        if message.interface == "org.freedesktop.DBus.Properties" and message.member == "Get":
            properties = {
                "Version": Variant("s", "252"),
                "SystemState": Variant("s", "running"),
                "Type": Variant("s", self.service_type),
                "NRestarts": Variant("u", 3),
                "TasksCurrent": Variant("t", self.tasks),
                "TasksMax": Variant("t", self.tasks),
                "NAccepted": Variant("u", 10),
                "NConnections": Variant("u", 2),
                "NRefused": Variant("u", 0),
                "LastTriggerUSec": Variant("t", 1_700_000_000_000_000),
                "ActiveEnterTimestamp": Variant("t", 1_600_000_000_000_000),
            }
            return Message.new_method_return(message, "v", [properties[message.body[1]]])
        return None


@contextmanager
def private_systemd_bus():
    if shutil.which("dbus-daemon") is None:
        pytest.skip("systemd integration tests require dbus-daemon")

    daemon = subprocess.Popen(
        ["dbus-daemon", "--session", "--nofork", "--address=unix:tmpdir=/tmp", "--print-address=1"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    loop = asyncio.new_event_loop()
    ready = Future()
    manager = SystemdManager()

    async def serve(address):
        bus = await MessageBus(bus_address=address).connect()
        bus.add_message_handler(manager.handle)
        await bus.request_name("org.freedesktop.systemd1")
        ready.set_result(bus)
        await bus.wait_for_disconnect()

    def run(address):
        try:
            loop.run_until_complete(serve(address))
        except Exception as exc:
            if not ready.done():
                ready.set_exception(exc)
            else:
                raise
        finally:
            loop.close()

    thread = None
    bus = None
    try:
        address = daemon.stdout.readline().strip()
        assert address, daemon.stderr.read()
        thread = threading.Thread(target=run, args=(address,), daemon=True)
        thread.start()
        bus = ready.result(timeout=10)
        yield address, manager
    finally:
        if bus is not None:
            loop.call_soon_threadsafe(bus.disconnect)
        if thread is not None:
            thread.join(timeout=10)
        daemon.terminate()
        daemon.communicate(timeout=10)


def points(request):
    result = {}
    for resource in request.resource_metrics:
        for scope in resource.scope_metrics:
            for metric in scope.metrics:
                for point in getattr(metric, metric.WhichOneof("data")).data_points:
                    labels = tuple(sorted((attr.key, attr.value.string_value) for attr in point.attributes))
                    result[metric.name, labels] = point
    return result


def named(snapshot, name):
    return {key: point for key, point in snapshot.items() if key[0] == name}


@pytest.fixture
def systemd_service():
    with private_systemd_bus() as (address, manager):
        def start_receiver(service):
            otlp_server_run(service.test_suite_http_port)
            service.wait_for_http_endpoint(f"http://127.0.0.1:{service.test_suite_http_port}/ping")

        service = FluentBitTestService(
            str(Path(__file__).parents[1] / "config/systemd_otlp.yaml"),
            extra_env={"DBUS_SYSTEM_BUS_ADDRESS": address},
            data_storage=data_storage,
            data_keys=["metrics", "requests"],
            pre_start=start_receiver,
            post_stop=lambda _: stop_otlp_server(),
        )
        try:
            service.start()
            yield service, manager
        finally:
            service.stop()


def wait_snapshot(service, after=0, metric="node_systemd_units"):
    def latest():
        for request in reversed(list(data_storage["metrics"])):
            snapshot = points(request)
            candidates = named(snapshot, metric).values()
            if any(point.time_unix_nano > after for point in candidates):
                return snapshot
        return None

    return service.wait_for_condition(latest, timeout=20, interval=0.1, description="systemd OTLP snapshot")


def test_systemd_unchanged_values_have_fresh_timestamps(systemd_service):
    service, _ = systemd_service
    first = wait_snapshot(service)
    second = wait_snapshot(service, after=max(point.time_unix_nano for point in first.values()))
    assert first.keys() == second.keys()
    assert named(first, "node_systemd_service_restart_total")
    assert named(first, "node_systemd_timer_last_trigger_seconds")
    for key, old in first.items():
        new = second[key]
        assert new.time_unix_nano > old.time_unix_nano, key
        assert new.as_double == old.as_double, key
        assert new.start_time_unix_nano == old.start_time_unix_nano, key
        assert ("host", "test-host") in key[1]


@pytest.mark.parametrize("change", ["removed", "unloaded", "empty", "labels_and_tasks"])
def test_systemd_expires_unobserved_series(systemd_service, change):
    service, manager = systemd_service
    first = wait_snapshot(service)
    assert any(("name", "gone.socket") in labels for _, labels in first)
    assert any(("name", "gone.timer") in labels for _, labels in first)
    assert named(first, "node_systemd_unit_tasks_current")

    if change == "removed":
        manager.units = ("keep.service",)
    elif change == "unloaded":
        manager.unloaded = True
    elif change == "empty":
        manager.units = ()
    else:
        manager.service_type = "oneshot"
        manager.tasks = 2**64 - 1

    # The summary timestamp distinguishes a completed new scan from queued output.
    second = wait_snapshot(service, after=time.time_ns())
    if change == "labels_and_tasks":
        assert not named(second, "node_systemd_unit_tasks_current")
        assert not named(second, "node_systemd_unit_tasks_max")
        assert not any(("type", "simple") in labels for _, labels in second)
        assert any(("type", "oneshot") in labels for _, labels in second)
    else:
        unit_names = {dict(labels)["name"] for _, labels in second if "name" in dict(labels)}
        assert unit_names == ({"keep.service"} if change == "removed" else set())

    # Expiration must not remove the global systemd samples.
    assert named(second, "node_systemd_version")
    assert named(second, "node_systemd_system_running")
    assert len(named(second, "node_systemd_units")) == 5

    # Removed series must be collectable again with fresh timestamps.
    manager.units = ("keep.service", "gone.service", "gone.socket", "gone.timer")
    manager.unloaded = False
    manager.service_type = "simple"
    manager.tasks = 7
    restored = wait_snapshot(service, after=time.time_ns())
    assert restored.keys() == first.keys()
    for key, old in first.items():
        assert restored[key].time_unix_nano > old.time_unix_nano, key
        assert restored[key].as_double == old.as_double, key


def test_systemd_failed_scan_does_not_expire_series(systemd_service):
    service, manager = systemd_service
    first = wait_snapshot(service)
    manager.fail_list = True
    manager.units = ()
    second = wait_snapshot(service, after=time.time_ns(), metric="node_systemd_version")
    assert first.keys() == second.keys()
    for key, old in first.items():
        if "name" in dict(key[1]):
            assert second[key].time_unix_nano == old.time_unix_nano

    manager.fail_list = False
    recovered = wait_snapshot(service, after=time.time_ns())
    assert not any("name" in dict(labels) for _, labels in recovered)
