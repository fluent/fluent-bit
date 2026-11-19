"""Characterize legacy scripts before introducing isolated recipe blocks.

These assertions document hazards in arbitrary scripts, not desired recipe
behavior. Recipe tests must separately prove isolation and rollback.
"""
from pathlib import Path

import pytest
import yaml

from test_fts_records import start_service, send, rows
from test_fts_signals import SignalRunner, metric
from utils.fluent_bit_manager import FluentBitManager
from utils.network import find_available_port

from fts_test_utils import read_log


@pytest.mark.parametrize("placement", ["input", "output"])
@pytest.mark.parametrize("hazard", ["caught_error", "helper_override"])
def test_legacy_script_composition_hazards(tmp_path, placement, hazard):
    operations = {
        "caught_error": '''
          local ok = pcall(function()
            log.body:set("partial", "committed")
            error("synthetic failure")
          end)
          assert(not ok)
        ''',
        "helper_override": '''
          local function first() fb.redact = function() end end
          local function second() fb.redact(log.body, {"password"}) end
          first(); second()
        ''',
    }
    code = ('local fb = require("fluentbit")\nfunction process(log)\n' +
            operations[hazard] + '\nend')
    service = start_service(tmp_path, code, placement)
    try:
        send(service, {"password": "synthetic", "control": "preserved"})
        result = service.wait_for_condition(lambda: rows(service), timeout=30)
        assert len(result) == 1
        assert result[0]["control"] == "preserved"
        if hazard == "caught_error":
            assert result[0]["partial"] == "committed"
        else:
            assert result[0]["password"] == "synthetic"
    finally:
        service.stop()


@pytest.mark.parametrize("placement", ["input", "output"])
@pytest.mark.parametrize("order", ["scale_first", "merge_first"])
def test_histogram_nine_ms_composition(tmp_path, placement, order):
    scale = 'fb.scale_metric(record, 0.001, "s")'
    merge = ('local bounds = fb.array(); bounds:append(BOUND); '
             'fb.merge_histogram_buckets(record, bounds)')
    operations = (scale + '; ' + merge.replace('BOUND', '0.009')
                  if order == "scale_first" else
                  merge.replace('BOUND', '9.0') + '; ' + scale)
    code = ('local fb = require("fluentbit")\nfunction process(record)\n'
            'if record.name == "control" then return end\n' + operations + '\nend')
    port = find_available_port()
    source = {"name": "opentelemetry", "port": port}
    output = {"name": "stdout", "match": "*", "format": "otlp_json"}
    (source if placement == "input" else output)["processors"] = {
        "metrics": [{"name": "fts", "code": code, "error_mode": "keep"}]}
    config = tmp_path / "histogram.yaml"
    config.write_text(yaml.safe_dump({"service": {
        "flush": 0.2, "grace": 1, "http_server": True,
        "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {"inputs": [source], "outputs": [output]}}))
    manager = FluentBitManager(str(config))
    try:
        manager.start()
        runner = SignalRunner(manager, port, "metrics")
        point = metric("histogram", "probe")["histogram"]["dataPoints"][0]
        point["explicitBounds"] = [9.0, 10.0]
        _, result = runner.run("bad_order_probe", "histogram", points=[point])
        target = next(item for _, _, item in result if item["name"] != "control")
        assert len([item for _, _, item in result if item["name"] == "control"]) == 1
        actual = target["histogram"]["dataPoints"][0]
        if order == "scale_first":
            assert actual["explicitBounds"] == [9.0, 10.0]
            assert [int(v) for v in actual["bucketCounts"]] == [1, 1, 1]
            assert "new bounds must be a subset" in read_log(manager.log_file, "new bounds must be a subset")
        else:
            assert actual["explicitBounds"] == [9.0 * 0.001]
            assert [int(v) for v in actual["bucketCounts"]] == [1, 2]
            assert target["unit"] == "s"
    finally:
        manager.stop()
