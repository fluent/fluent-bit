"""Run the FTS examples under examples/fts and compare with their expected output."""
import json
from pathlib import Path

import pytest
import requests
import yaml

from utils.test_service import FluentBitTestService


EXAMPLES = Path(__file__).resolve().parents[5] / "examples" / "fts"
SIGNALS = {"resourceLogs": "logs", "resourceMetrics": "metrics", "resourceSpans": "traces"}


def example_config(tmp_path, example):
    """Load an example configuration and adapt only what the test harness needs."""
    config = yaml.safe_load((example / "fluent-bit.yaml").read_text())
    service = config.setdefault("service", {})
    service.update({"http_server": True, "http_listen": "127.0.0.1",
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}", "grace": 1})
    source = config["pipeline"]["inputs"][0]
    if source["name"] == "opentelemetry":
        source["port"] = "${FLUENT_BIT_TEST_LISTENER_PORT}"
    for processors in source.get("processors", {}).values():
        for processor in processors:
            if "script" in processor:
                processor["script"] = str(example / processor["script"])
    path = tmp_path / f"{example.name}.yaml"
    path.write_text(yaml.safe_dump(config))
    return path


def printed_json(service):
    text = Path(service.flb.log_file).read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines() if line.startswith("{")]


def test_quickstart_example(tmp_path):
    example = EXAMPLES / "quickstart"
    expected = json.loads((example / "expected-output.json").read_text())
    service = FluentBitTestService(str(example_config(tmp_path, example)))
    try:
        service.start()
        output = service.wait_for_condition(lambda: printed_json(service), timeout=30)
    finally:
        service.stop()
    assert output == expected


@pytest.mark.parametrize("name", ["logs-redaction", "metrics-normalization", "traces-filtering"])
def test_otlp_example(tmp_path, name):
    example = EXAMPLES / name
    payload = json.loads((example / "input.json").read_text())
    expected = json.loads((example / "expected-output.json").read_text())
    signal = SIGNALS[next(iter(payload))]
    service = FluentBitTestService(str(example_config(tmp_path, example)))
    try:
        service.start()
        response = requests.post(f"http://127.0.0.1:{service.flb_listener_port}/v1/{signal}",
                                 json=payload, timeout=15)
        assert response.status_code in (200, 201), response.text
        output = service.wait_for_condition(lambda: printed_json(service), timeout=30)
    finally:
        service.stop()
    log = Path(service.flb.log_file).read_text(encoding="utf-8")
    assert "policy failed" not in log
    assert output == expected
