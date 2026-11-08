"""Core log inventory accounting, independent of the future FTS window store."""
import re
import socket

import pytest
import requests
import yaml

from test_fts_state_prerequisites import compile_probe
from test_fts_records import send, rows, log_text, pack, event_time
from utils.test_service import FluentBitTestService


@pytest.fixture(scope="module", params=[False, True], ids=["normal", "windows"])
def hold_dso(request, tmp_path_factory):
    return compile_probe(tmp_path_factory, "hold", "windows" if request.param else False)


@pytest.fixture(scope="module")
def parity_dsos(tmp_path_factory):
    return [compile_probe(tmp_path_factory, "hold", mode) for mode in (False, "windows")]


def start(tmp_path, library, threaded=False, storage="memory"):
    tmp_path.mkdir(parents=True, exist_ok=True)
    config = tmp_path / "hold.yaml"
    config.write_text(yaml.safe_dump({
        "plugins": [str(library)],
        "service": {"flush": 0.2, "grace": 1, "storage.path": str(tmp_path / "storage"),
                    "http_server": True, "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {
            "inputs": [{"name": "forward", "port": "${FLUENT_BIT_TEST_LISTENER_PORT}",
                        "threaded": threaded, "storage.type": storage,
                        "buffer_chunk_size": "1M", "buffer_max_size": "4M",
                        "processors": {"logs": [{"name": "hold_probe"},
                            {"name": "fts", "code": 'function process(log) local n = log.body:get("visits") or 0; log.body:set("visits", n + 1) end'}]}}],
            "outputs": [{"name": "stdout", "match": "*", "format": "json_lines"}]}}))
    service = FluentBitTestService(str(config))
    service.start()
    return service


def metrics(service):
    response = requests.get(f"http://127.0.0.1:{service.flb.http_monitoring_port}/api/v2/metrics/prometheus", timeout=10)
    response.raise_for_status()
    values = {}
    for line in response.text.splitlines():
        if line.startswith("fluentbit_processor_") and 'processor="hold_probe"' in line:
            assert 'scope="input"' in line and 'stage="0"' in line and 'signal="logs"' in line, line
            values[line.split("{", 1)[0].removeprefix("fluentbit_processor_")] = float(line.rsplit(" ", 1)[-1])
    return values


def wait_counts(service, input_count, output_count, dropped, held, total):
    expected = {"items_in_total": input_count, "items_out_total": output_count,
                "items_drop_total": dropped, "items_held_current": held, "items_held_total": total}
    def check():
        value = metrics(service)
        return value if all(value.get(key) == count for key, count in expected.items()) else None
    actual = service.wait_for_condition(check, timeout=30, description=str(expected))
    assert input_count == output_count + dropped + held
    return actual


@pytest.mark.parametrize("threaded", [False, True])
@pytest.mark.parametrize("storage", ["memory", "filesystem"])
def test_hold_release_busy_discard_and_underflow(tmp_path, hold_dso, threaded, storage):
    service = start(tmp_path, hold_dso, threaded, storage)
    try:
        send(service, [{"action": "keep"}] * 2)
        wait_counts(service, 2, 2, 0, 0, 0)
        send(service, [{"action": "hold"}] * 3)
        wait_counts(service, 5, 2, 0, 3, 3)
        send(service, [{"action": "hold"}] * 2)
        wait_counts(service, 7, 2, 0, 5, 5)
        send(service, {"action": "drop"})
        wait_counts(service, 8, 2, 1, 5, 5)
        send(service, {"action": "underflow"})
        counts = wait_counts(service, 9, 2, 2, 5, 5)
        assert counts["accounting_errors_total"] == 2
        send(service, {"action": "release"})
        wait_counts(service, 10, 7, 3, 0, 5)
        expected = "hold_probe_retry ret=-2 intact=1 inventory=2"
        assert expected in log_text(service, expected)
        send(service, [{"action": "hold"}] * 2)
        wait_counts(service, 12, 7, 3, 2, 7)
        send(service, {"action": "stop"})
        wait_counts(service, 13, 7, 6, 0, 7)
        send(service, {"action": "keep"})
        wait_counts(service, 14, 8, 6, 0, 7)
        service.wait_for_condition(lambda: len(rows(service)) == 8, timeout=30)
        assert all(row["visits"] == 1 for row in rows(service))
        diagnostic = "invalid retention accounting operation"
        assert log_text(service, diagnostic).count(diagnostic) == 1
    finally:
        service.stop()
    assert "hold_probe_exit inventory=0" in log_text(service, "hold_probe_exit inventory=0")


@pytest.mark.parametrize("threaded", [False, True])
def test_normal_and_processing_windows_have_identical_inventory(tmp_path, parity_dsos, threaded):
    snapshots = []
    callbacks = []
    for index, library in enumerate(parity_dsos):
        service = start(tmp_path / str(index), library, threaded)
        try:
            send(service, [{"action": "keep"}] * 3)
            wait_counts(service, 3, 3, 0, 0, 0)
            send(service, [{"action": "hold", "padding": "x" * 32}] * 2050)
            wait_counts(service, 2053, 3, 0, 2050, 2050)
            send(service, [{"action": "drop"}] * 4)
            wait_counts(service, 2057, 3, 4, 2050, 2050)
            send(service, {"action": "stop"})
            result = wait_counts(service, 2058, 3, 2055, 0, 2050)
            snapshots.append({key: value for key, value in result.items() if key != "invocations_total"})
        finally:
            service.stop()
        callbacks.append(int(re.search(r"hold_probe_exit inventory=0 calls=(\d+)", log_text(service)).group(1)))
    assert snapshots[0] == snapshots[1]
    assert callbacks[1] > callbacks[0], callbacks


def test_group_markers_are_not_held_records(tmp_path, hold_dso):
    service = start(tmp_path, hold_dso)
    try:
        entries = [
            [[event_time(0xFFFFFFFF), {"schema": "otlp", "resource_id": 0, "scope_id": 0}],
             {"resource": {"attributes": {"service.name": "probe"}}, "scope": {"name": "s"}}],
            [[event_time(1700000000), {"otlp": {}}], {"action": "hold"}],
            [[event_time(1700000000), {"otlp": {}}], {"action": "hold"}],
            [[event_time(0xFFFFFFFE), {}], {}],
        ]
        with socket.create_connection(("127.0.0.1", service.flb_listener_port), timeout=30) as connection:
            connection.sendall(pack(["stream", entries]))
        wait_counts(service, 2, 0, 0, 2, 2)
        send(service, {"action": "stop"})
        wait_counts(service, 3, 0, 3, 0, 2)
        assert rows(service) == []
    finally:
        service.stop()


def test_one_batch_contains_keep_hold_and_drop(tmp_path, hold_dso):
    service = start(tmp_path, hold_dso)
    try:
        send(service, [{"action": "mixed", "id": index} for index in range(3)])
        wait_counts(service, 3, 1, 1, 1, 1)
        send(service, {"action": "release"})
        wait_counts(service, 4, 2, 2, 0, 1)
        service.wait_for_condition(lambda: len(rows(service)) == 2, timeout=30)
        assert [row["id"] for row in rows(service)] == [0, 1]
        assert all(row["visits"] == 1 for row in rows(service))
    finally:
        service.stop()
