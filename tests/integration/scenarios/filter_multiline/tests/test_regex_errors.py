"""Regex errors must not start or extend a multiline group."""
import json
from pathlib import Path

import pytest
import yaml

from utils.test_service import FluentBitTestService


def emitted_logs(path):
    logs = []
    for line in Path(path).read_text().splitlines():
        if line.startswith("{"):
            logs.append(json.loads(line)["log"].rstrip("\n"))
    return logs


@pytest.mark.parametrize("state", ["start", "continuation"])
def test_multiline_regex_error_is_not_a_match(tmp_path, state):
    hostile = "a" * 64 + "!"
    expensive = r"/^(a+)+\1$/"
    start = expensive if state == "start" else "/^BEGIN$/"
    continuation = "/^ CONT$/" if state == "start" else expensive
    inputs = [hostile, " CONT", "END"] if state == "start" else ["BEGIN", hostile, "END"]
    parser = tmp_path / "parsers.conf"
    parser.write_text(
        "[MULTILINE_PARSER]\n"
        "    name bounded\n"
        "    type regex\n"
        "    flush_timeout 1000\n"
        f'    rule "start_state" "{start}" "cont"\n'
        f'    rule "cont" "{continuation}" "cont"\n'
    )
    config = {
        "service": {"flush": 0.1, "grace": 2, "log_level": "error",
                    "parsers_file": str(parser), "http_server": "on",
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {
            "inputs": [{"name": "dummy", "tag": "test", "samples": 1,
                        "dummy": " ".join(json.dumps({"log": text}) for text in inputs)}],
            "filters": [{"name": "multiline", "match": "*", "buffer": "on",
                         "multiline.key_content": "log", "multiline.parser": "bounded",
                         "flush_ms": 1000}],
            "outputs": [{"name": "stdout", "match": "*", "format": "json_lines"}],
        },
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config))
    service = FluentBitTestService(str(config_path))
    try:
        service.start()
        service.wait_for_condition(
            lambda: len(emitted_logs(service.flb.log_file)) >= len(inputs),
            timeout=30, description="separate records after a multiline regex error",
        )
    finally:
        service.stop()
    assert sorted(emitted_logs(service.flb.log_file)) == sorted(inputs)
    assert "[regex] search failed: -17" in Path(service.flb.log_file).read_text()
