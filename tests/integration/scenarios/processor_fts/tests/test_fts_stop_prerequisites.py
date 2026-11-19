"""Input-only stop hook, including partial init, active loop and reload."""
import re

import pytest
import yaml

from test_fts_state_prerequisites import compile_probe
from test_fts_recipes import rejected_startup
from test_fts_records import rows, log_text
from utils.test_service import FluentBitTestService


@pytest.fixture(scope="module")
def stop_dso(tmp_path_factory):
    return compile_probe(tmp_path_factory, "stop")


def config_file(tmp_path, library, threaded, modes):
    config = tmp_path / "stop.yaml"
    config.write_text(yaml.safe_dump({
        "plugins": [str(library)],
        "service": {"flush": 0.2, "grace": 1, "hot_reload": True,
                    "http_server": True, "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {
            "inputs": [{"name": "dummy", "threaded": threaded, "dummy": '{"message":"probe"}',
                        "interval_sec": 0, "interval_nsec": 100000000,
                        "processors": {"logs": [{"name": "stop_probe", "mode": mode} for mode in modes]}}],
            "outputs": [{"name": "stdout", "match": "*", "format": "json_lines"}]}}))
    return config


def assert_stopped(text, mode, count=1):
    assert text.count(f"stop_probe_stop mode={mode} count=1 owner=1") == count, text
    assert text.count(f"stop_probe_exit mode={mode} stops=1 stable=1") == count, text
    assert "stop_probe_bad_tick" not in text, text


@pytest.mark.parametrize("threaded", [False, True])
@pytest.mark.parametrize("mode", ["normal", "early", "error"])
def test_stop_owner_once_and_timer_quiet(tmp_path, stop_dso, threaded, mode):
    service = FluentBitTestService(str(config_file(tmp_path, stop_dso, threaded, [mode])))
    try:
        service.start()
        service.wait_for_condition(lambda: len(rows(service)) >= 6, timeout=30)
        if mode == "early":
            text = log_text(service)
            assert re.search(r"stop_probe_quiet elapsed=\d+ stable=1", text), text
    finally:
        service.stop()
    text = log_text(service)
    assert_stopped(text, mode)
    if mode == "error":
        assert "input stop failed for unit 'stop_probe'" in text, text


@pytest.mark.parametrize("threaded", [False, True])
def test_stop_partial_initialization(tmp_path, stop_dso, threaded):
    config = config_file(tmp_path, stop_dso, threaded, ["normal", "fail", "unreached"])
    text = rejected_startup(config, tmp_path)
    assert_stopped(text, "normal")
    assert_stopped(text, "fail")
    assert "mode=unreached" not in text, text


@pytest.mark.parametrize("threaded", [False, True])
def test_stop_old_pipeline_on_reload(tmp_path, stop_dso, threaded):
    config = config_file(tmp_path, stop_dso, threaded, ["normal"])
    service = FluentBitTestService(str(config))
    try:
        service.start()
        service.wait_for_condition(lambda: len(rows(service)) >= 2, timeout=30)
        service.flb.trigger_http_reload()
        service.flb.wait_for_hot_reload_count(1, timeout=30)
        service.wait_for_condition(lambda: log_text(service).count("stop_probe_init mode=normal") == 2,
                                   timeout=30)
        assert_stopped(log_text(service), "normal")
    finally:
        service.stop()
    assert_stopped(log_text(service), "normal", count=2)
