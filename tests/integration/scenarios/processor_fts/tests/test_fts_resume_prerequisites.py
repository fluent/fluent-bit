"""Release ownership experiment; this is not production HOLD accounting."""
import pytest
import re
import yaml

from test_fts_state_prerequisites import compile_probe
from test_fts_records import rows, log_text
from utils.test_service import FluentBitTestService


@pytest.fixture(scope="module")
def resume_dso(tmp_path_factory):
    return compile_probe(tmp_path_factory, "resume")


@pytest.mark.parametrize("threaded", [False, True])
@pytest.mark.parametrize("input_name", ["dummy", "tail"])
@pytest.mark.parametrize("storage", ["memory", "filesystem"])
def test_queue_ownership_continuation(tmp_path, resume_dso, threaded, input_name, storage):
    source = {"name": input_name, "threaded": threaded, "storage.type": storage}
    if input_name == "dummy":
        source.update(dummy='{"message":"probe"}', samples=1)
    else:
        path = tmp_path / "input.log"
        path.write_text("probe\n")
        source.update(path=str(path), read_from_head=True, refresh_interval=1)
    source["processors"] = {"logs": [
        {"name": "resume_probe"},
        {"name": "fts", "code": 'function process(log) local n = log.body:get("visits") or 0; log.body:set("visits", n + 1) end'}]}
    config = tmp_path / "resume.yaml"
    config.write_text(yaml.safe_dump({
        "plugins": [str(resume_dso)],
        "service": {"flush": 2, "grace": 1, "storage.path": str(tmp_path / "storage"),
                    "http_server": True, "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {"inputs": [source], "outputs": [
            {"name": "stdout", "match": "*", "format": "json_lines"}]}}))
    service = FluentBitTestService(str(config))
    try:
        service.start()
        service.wait_for_condition(lambda: len(rows(service)) >= 2, timeout=30)
    finally:
        service.stop()
    text = log_text(
        service, "resume_first ret=0 cleared=1", "resume_second ret=-2 intact=1",
        "resume_retry ret=0 cleared=1 owner=1", "resume_exit calls=1 releases=1 pending=0",
    )
    assert "resume_first ret=0 cleared=1" in text, text
    assert "resume_second ret=-2 intact=1" in text, text
    assert "resume_retry ret=0 cleared=1 owner=1" in text, text
    assert "resume_exit calls=1 releases=1 pending=0" in text, text
    assert "resume_reentered" not in text, text
    assert len(rows(service)) == 2, text
    assert [row["visits"] for row in rows(service)] == [1, 1], text


@pytest.fixture(scope="module")
def pause_dso(tmp_path_factory):
    return compile_probe(tmp_path_factory, "pause")


@pytest.mark.parametrize("threaded", [False, True])
def test_pause_preserves_queue_before_and_during_drain(tmp_path, pause_dso, threaded):
    storage = "memory"
    source = {"name": "dummy", "dummy": '{"message":"pause"}', "samples": 1,
              "threaded": threaded, "storage.type": storage, "mem_buf_limit": "1", "processors": {"logs": [
        {"name": "pause_probe"}, {"name": "pause_probe"},
        {"name": "fts", "code": 'function process(log) local n = log.body:get("visits"); log.body:set("visits", n and n:number()+1 or 1) end'}]}}
    config = tmp_path / "pause.yaml"
    config.write_text(yaml.safe_dump({"plugins": [str(pause_dso)],
        "service": {"flush": 2, "grace": 1, "storage.path": str(tmp_path / "storage"),
                    "http_server": True, "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {"inputs": [source], "outputs": [{"name": "stdout", "match": "*", "format": "json_lines"}]}}))
    service = FluentBitTestService(str(config))
    try:
        service.start()
        service.wait_for_condition(lambda: len(rows(service)) == 3, timeout=30)
    finally:
        service.stop()
    text = log_text(
        service, "pause_inventory stage=0 pending=3", "pause_exit stage=0 calls=1", "pause_exit stage=1 calls=3",
    )
    assert "pause_inventory stage=0 pending=3" in text, text
    # Engine flushing may resume the input before the owner timer observes it.
    assert re.search(r"pause_inventory stage=1 pending=[0-2]\b", text), text
    assert "could not ingest deferred worker payload" not in text, text
    assert "pause_exit stage=0 calls=1" in text, text
    assert "pause_exit stage=1 calls=3" in text, text
    assert len(rows(service)) == 3 and all(row["visits"] == 1 for row in rows(service)), text
