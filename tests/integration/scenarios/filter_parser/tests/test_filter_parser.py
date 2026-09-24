"""Parser selection works in the filter pipeline and input/output processors."""
import json
import os
from pathlib import Path
import subprocess

import pytest
import yaml

from utils.fluent_bit_manager import _resolve_binary_path
from utils.valgrind import assert_valgrind_clean


PARSERS = """[PARSER]
    Name envelope
    Format json
[PARSER]
    Name structured
    Format json
    Time_Key time
    Time_Format %Y-%m-%dT%H:%M:%S
    Time_Keep On
[PARSER]
    Name keyvalue
    Format logfmt
"""


def run_pipeline(tmp_path, records, options, placement="input", valid=True,
                 preceding=None, extra_parsers=""):
    parsers = tmp_path / "parsers.conf"
    parsers.write_text(PARSERS + extra_parsers)
    source = tmp_path / "records.jsonl"
    source.write_text("".join(json.dumps(record) + "\n" for record in records))
    stage = {"name": "parser", "key_name": "MESSAGE", **options}
    input_config = {"name": "tail", "path": str(source), "parser": "envelope",
                    "read_from_head": True, "exit_on_eof": True, "tag": "test"}
    output_config = {"name": "stdout", "match": "*", "format": "json_lines",
                     "json_date_key": "event_time"}
    pipeline = {"inputs": [input_config], "outputs": [output_config]}
    if placement == "filter":
        pipeline["filters"] = [{**stage, "match": "*"}]
    else:
        target = input_config if placement == "input" else output_config
        target["processors"] = {"logs": [*(preceding or []), stage]}
    return run_configuration(tmp_path, {
        "service": {"flush": 0.1, "grace": 1, "parsers_file": str(parsers)},
        "pipeline": pipeline,
    }, valid=valid)


def run_configuration(tmp_path, configuration, valid=True, env=None):
    if isinstance(configuration, Path):
        config = configuration
    else:
        config = tmp_path / "fluent-bit.yaml"
        config.write_text(yaml.safe_dump(configuration))
    command = [_resolve_binary_path(), "-c", str(config)]
    memory = os.environ.get("VALGRIND") == "1"
    memlog = tmp_path / "valgrind.log"
    if memory:
        command = ["valgrind", "--leak-check=full", "--show-leak-kinds=all",
                   "--error-exitcode=99", f"--log-file={memlog}"] + command
    result = subprocess.run(command, capture_output=True, text=True, timeout=60, env=env)
    (tmp_path / "fluent-bit.log").write_text(result.stdout + result.stderr)
    if memory:
        assert "ERROR SUMMARY:" in memlog.read_text()
        assert_valgrind_clean(memlog)
    if not valid:
        assert result.returncode != 0, result.stdout + result.stderr
        return result.stderr
    assert result.returncode == 0, result.stdout + result.stderr
    return [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]


def test_systemd_record_parser_processor(tmp_path):
    """Replay the systemd PoC with a self-contained input processor configuration."""
    config_file = Path(__file__).resolve().parents[1] / "config" / "systemd_record_parser.yaml"
    message = ('192.168.1.100 - - [21/Nov/2025:20:30:15 +0000] '
               '"GET /api/users HTTP/1.1" 200 1234')
    common = {"SYSTEMD_UNIT": "test-parser.service", "PRIORITY": "6"}
    unchanged = [
        {**common, "MESSAGE": message, "FLUENT_BIT_PARSER": "unknown"},
        {**common, "MESSAGE": "invalid nginx message", "FLUENT_BIT_PARSER": "nginx"},
        {**common, "MESSAGE": message},
    ]
    records = [{**common, "MESSAGE": message, "FLUENT_BIT_PARSER": "nginx"}, *unchanged]
    source = tmp_path / "journal-records.jsonl"
    source.write_text("".join(json.dumps(record) + "\n" for record in records))

    # Replay journal-shaped records without requiring access to a host journal.
    output = run_configuration(tmp_path, config_file,
                               env={**os.environ, "PARSER_TEST_RECORDS": str(source)})
    assert len(output) == len(records)
    assert output[0] == {
        **common, "date": 1763757015.0, "remote": "192.168.1.100",
        "method": "GET", "path": "/api/users", "code": "200", "size": "1234",
    }
    for record in output[1:]:
        record.pop("date")
    assert output[1:] == unchanged


@pytest.mark.parametrize("placement", ["input", "filter", "output"])
def test_dynamic_selection_and_fallback(tmp_path, placement):
    records = [
        {"MESSAGE": '{"answer":42,"nested":{"items":["a",null,true]}}',
         "FLUENT_BIT_PARSER": "structured", "_SYSTEMD_UNIT": "example.service"},
        {"MESSAGE": "answer=second", "FLUENT_BIT_PARSER": "keyvalue"},
    ]
    unchanged = [
        {"MESSAGE": '{"answer":42}'},
        *[{"MESSAGE": '{"answer":42}', "FLUENT_BIT_PARSER": selector}
          for selector in ("unknown", "", None, 12, [], {}, "structured\0suffix")],
        {"MESSAGE": "invalid json", "FLUENT_BIT_PARSER": "structured"},
        {"MESSAGE": 42, "FLUENT_BIT_PARSER": "structured"},
        {"FLUENT_BIT_PARSER": "structured"},
        {"MESSAGE": "{}", "fluent_bit_parser": "structured"},
    ]
    output = run_pipeline(tmp_path, records + unchanged, {
        "parser_key": "FLUENT_BIT_PARSER", "reserve_data": True,
        "preserve_parser_key": False,
    }, placement)
    assert len(output) == len(records + unchanged)
    for record in output:
        record.pop("event_time")
    assert output[:2] == [
        {"answer": 42, "nested": {"items": ["a", None, True]},
         "_SYSTEMD_UNIT": "example.service"},
        {"answer": "second"},
    ]
    assert output[2:] == unchanged


@pytest.mark.parametrize("reserve,preserve,selector", [
    (True, False, True), (True, True, False),
    (False, False, True), (False, True, False),
])
def test_preservation_and_timestamp(tmp_path, reserve, preserve, selector):
    message = '{"time":"2020-01-02T03:04:05","value":"ok"}'
    source = {"MESSAGE": message, "selector": "structured", "extra": "keep"}
    output = run_pipeline(tmp_path, [source], {
        "parser_key": "selector", "reserve_data": reserve,
        "preserve_key": preserve, "preserve_parser_key": selector,
    })
    expected = {"time": "2020-01-02T03:04:05", "value": "ok", "event_time": 1577934245.0}
    if reserve:
        expected["extra"] = "keep"
        if selector:
            expected["selector"] = "structured"
    if preserve:
        expected["MESSAGE"] = message
    assert output == [expected]


def test_static_parser_and_nested_payload(tmp_path):
    output = run_pipeline(tmp_path, [{"payload": {"message": '{"value":true}'}}], {
        "key_name": "$payload['message']", "parser": "structured",
    })
    assert len(output) == 1
    output[0].pop("event_time")
    assert output == [{"value": True}]


def test_dynamic_parser_and_nested_payload(tmp_path):
    output = run_pipeline(tmp_path, [{"payload": {"message": '{"value":true}'},
                                      "selector": "structured"}], {
        "key_name": "$payload['message']", "parser_key": "selector",
    })
    assert len(output) == 1
    output[0].pop("event_time")
    assert output == [{"value": True}]


def test_default_selector_preservation(tmp_path):
    output = run_pipeline(tmp_path, [{"MESSAGE": "{}", "selector": "structured"}], {
        "parser_key": "selector", "reserve_data": True,
    })
    assert len(output) == 1
    output[0].pop("event_time")
    assert output == [{"selector": "structured"}]


def test_multiline_then_dynamic_parser(tmp_path):
    output = run_pipeline(tmp_path, [
        {"MESSAGE": '{"value":', "selector": "structured"},
        {"MESSAGE": '42}', "selector": "structured"},
    ], {"parser_key": "selector"}, preceding=[{
        "name": "multiline", "multiline.key_content": "MESSAGE",
        "multiline.parser": "json_lines", "buffer": False,
    }], extra_parsers='''[MULTILINE_PARSER]
    Name json_lines
    Type regex
    Flush_Timeout 1000
    Rule "start_state" "/^\\{/" "cont"
    Rule "cont" "/^[0-9]/" "cont"
''')
    assert len(output) == 1
    output[0].pop("event_time")
    assert output == [{"value": 42}]


@pytest.mark.parametrize("options", [
    {"parser": "structured", "parser_key": "selector"},
    {"parser_key": ""}, {"parser_key": "MESSAGE"}, {},
])
def test_invalid_configuration(tmp_path, options):
    error = run_pipeline(tmp_path, [{"MESSAGE": "{}"}], options, valid=False)
    assert "parser" in error.lower()
