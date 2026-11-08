"""A protected callback error drops only its record, preserving the batch."""

import json
from pathlib import Path

import pytest
import yaml

from utils.test_service import FluentBitTestService


@pytest.mark.parametrize("error_value", ['"record-redaction-error"', "{}", "nil", "false"])
@pytest.mark.parametrize("context", ["filter", "processor"])
@pytest.mark.parametrize("extended", [False, True])
@pytest.mark.parametrize("errors", [[1], [3], [6], [1, 2, 3, 4, 5, 6]])
def test_protected_error_is_record_local(tmp_path, context, extended, errors, error_value):
    """Preserve redactions and explicit drops around errors of any Lua value type."""
    args = "tag, timestamp, group, metadata, record" if extended else "tag, timestamp, record"
    returns = "2, timestamp, metadata, record" if extended else "2, timestamp, record"
    error_table = ", ".join(f"[{index}] = true" for index in errors)
    code = f"""
local index = 0
local errors = {{{error_table}}}
function redact({args})
    index = index + 1
    record.index = index
    if errors[index] then
        record.card = "partial mutation"
        error({error_value})
    end
    record.card = "[REDACTED]"
    if index == 2 then
        return -1, timestamp, record
    end
    return {returns}
end
"""
    lua = {"name": "lua", "call": "redact", "code": code, "time_as_table": extended}
    dummy = {"name": "dummy", "tag": "redaction.test", "copies": 6, "samples": 1,
             "fixed_timestamp": True, "start_time_sec": 1700000000, "start_time_nsec": 0,
             "dummy": json.dumps({"card": "5555444433332222"})}
    pipeline = {"inputs": [dummy],
                "outputs": [{"name": "stdout", "match": "*", "format": "json_lines"}]}
    if context == "processor":
        dummy["processors"] = {"logs": [lua]}
    else:
        lua["match"] = "*"
        pipeline["filters"] = [lua]
    config = tmp_path / "fluent-bit.yaml"
    config.write_text(yaml.safe_dump({
        "service": {"flush": 0.2, "grace": 1, "http_server": True,
                    "http_listen": "127.0.0.1",
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": pipeline,
    }))
    expected = [{"date": 1700000000.0, "card": "[REDACTED]", "index": index}
                for index in range(1, 7) if index not in errors and index != 2]
    service = FluentBitTestService(str(config))

    def batch_finished():
        """Wait for every callback error and all surviving records to reach the log."""
        text = Path(service.flb.log_file).read_text()
        records = [json.loads(line) for line in text.splitlines() if line.startswith("{")]
        return text.count("dropping record") == len(errors) and records == expected

    try:
        service.start()
        service.wait_for_condition(
            batch_finished, timeout=30, description="complete Lua batch output",
        )
    finally:
        service.stop()

    text = Path(service.flb.log_file).read_text()
    records = [json.loads(line) for line in text.splitlines() if line.startswith("{")]
    assert records == expected
    assert text.count("dropping record") == len(errors)
    if error_value != '"record-redaction-error"':
        assert "(non-string error)" in text
