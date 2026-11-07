"""Regex exhaustion must finish promptly and leave the pipeline usable."""
import json
from pathlib import Path

import pytest
import yaml

from utils.test_service import FluentBitTestService


ROOT = Path(__file__).resolve().parents[5]


def shipped_pattern(filename, name):
    selected = False
    for line in (ROOT / "conf" / filename).read_text().splitlines():
        fields = line.strip().split(None, 1)
        if not fields:
            continue
        if fields[0] == "[PARSER]":
            selected = False
        elif fields[0] == "Name":
            selected = fields[1] == name
        elif fields[0] == "Regex" and selected:
            return fields[1]
    raise AssertionError(f"Missing parser {name}")


@pytest.mark.parametrize("case", ["nested", "backreference", "kube-custom", "ambassador", "bounded-repeat"])
def test_regex_budget(tmp_path, case):
    if case in ("nested", "backreference"):
        pattern = r"^(?<value>a+)+\k<value>$" if case == "backreference" else "^(?<value>a+)+$"
        hostile = "a" * 64 + "!"
        valid = "aaaa"
        capture = "value"
    elif case == "bounded-repeat":
        pattern = "^(?<value>a|aa){3,10}b$"
        hostile = "a" * 21 + "b"
        valid = "a" * 15 + "b"
        capture = "value"
    elif case == "kube-custom":
        pattern = shipped_pattern("parsers.conf", case)
        hostile = "a" * 2800 + "_ns_container-" + "G" * 64 + ".log"
        valid = "pod_ns_container-" + "a" * 64 + ".log"
        capture = "pod_name"
    else:
        pattern = shipped_pattern("parsers_ambassador.conf", case)
        hostile = 'x [] "GET ' + "\\a" * 40 + ' HTTP/1.1" 200'
        valid = 'x [] "GET / HTTP/1.1" 200 - 0 0 1 1 "-" "agent" "id" "host" "upstream"'
        capture = "method"
    parser = tmp_path / "parsers.conf"
    parser.write_text(f"[PARSER]\n    Name bounded\n    Format regex\n    Regex {pattern}\n")
    config = {
        "service": {"flush": 0.1, "grace": 1, "log_level": "error",
                    "parsers_file": str(parser), "http_server": "on",
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {
            "inputs": [{"name": "dummy", "tag": "test", "samples": 1,
                        "dummy": " ".join(json.dumps({"log": text})
                                          for text in [hostile, valid])}],
            "filters": [{"name": "parser", "match": "*", "key_name": "log",
                         "parser": "bounded", "reserve_data": True}],
            "outputs": [{"name": "stdout", "match": "*", "format": "json_lines"}],
        },
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config))
    service = FluentBitTestService(str(config_path))
    try:
        service.start()
        service.wait_for_condition(
            lambda: f'"{capture}":' in Path(service.flb.log_file).read_text(),
            timeout=30, description="valid record parsed after regex exhaustion",
        )
    finally:
        service.stop()
    log = Path(service.flb.log_file).read_text()
    if case == "backreference":
        assert "[regex] search failed: -17" in log
    else:
        assert "[regex] search failed:" not in log

    if case == "bounded-repeat":
        records = [json.loads(line) for line in log.splitlines() if line.startswith("{")]
        assert [record["value"] for record in records if "value" in record] == ["aa"]
