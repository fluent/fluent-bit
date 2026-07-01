import json
import os
from pathlib import Path

import pytest

from utils.data_utils import read_file
from utils.fluent_bit_manager import FluentBitStartupError
from utils.test_service import FluentBitTestService


class Service:
    def __init__(self, config_file):
        self.config_file = os.path.abspath(config_file)
        self.service = FluentBitTestService(self.config_file)

    def start(self):
        self.service.start()
        self.flb = self.service.flb

    def stop(self):
        self.service.stop()

    def wait_for_log_contains(self, text, timeout=10):
        return self.service.wait_for_condition(
            lambda: read_file(self.flb.log_file) if text in read_file(self.flb.log_file) else None,
            timeout=timeout,
            interval=0.5,
            description=f"log text {text!r}",
        )


def _find_json_line(log_text, needle):
    for line in log_text.splitlines():
        if needle in line and line.lstrip().startswith("{"):
            return json.loads(line)
    raise AssertionError(f"Could not find JSON line containing {needle!r}")


def _build_environment_mapping_config():
    return """service:
  flush: 1
  grace: 1
  log_level: info
  http_server: on
  http_port: ${FLUENT_BIT_HTTP_MONITORING_PORT}

env:
  environment_secret: mapping-secret

pipeline:
  inputs:
    - name: dummy
      tag: config.env
      dummy: '{"secret":"${environment_secret}","source":"dummy"}'
      samples: 1

  outputs:
    - name: stdout
      match: '*'
      format: json_lines
      json_date_key: false
"""


def _build_environment_extended_value_config():
    return """service:
  flush: 1
  grace: 1
  log_level: info
  http_server: on
  http_port: ${FLUENT_BIT_HTTP_MONITORING_PORT}

env:
  - name: environment_secret
    value: object-secret

pipeline:
  inputs:
    - name: dummy
      tag: config.env
      dummy: '{"secret":"${environment_secret}","source":"dummy"}'
      samples: 1

  outputs:
    - name: stdout
      match: '*'
      format: json_lines
      json_date_key: false
"""


def _build_environment_extended_uri_config(secret_file):
    secret_uri = Path(secret_file).resolve().as_uri()

    return f"""service:
  flush: 1
  grace: 1
  log_level: info
  http_server: on
  http_port: ${{FLUENT_BIT_HTTP_MONITORING_PORT}}

env:
  - name: environment_secret
    uri: {secret_uri}

pipeline:
  inputs:
    - name: dummy
      tag: config.env
      dummy: '{{"secret":"${{environment_secret}}","source":"dummy"}}'
      samples: 1

  outputs:
    - name: stdout
      match: '*'
      format: json_lines
      json_date_key: false
"""


def _build_environment_missing_file_config(secret_file):
    secret_uri = Path(secret_file).resolve().as_uri()

    return f"""service:
  flush: 1
  grace: 1
  log_level: info
  http_server: on
  http_port: ${{FLUENT_BIT_HTTP_MONITORING_PORT}}

env:
  - name: environment_secret
    uri: {secret_uri}

pipeline:
  inputs:
    - name: dummy
      tag: config.env
      dummy: '{{"secret":"${{environment_secret}}","source":"dummy"}}'
      samples: 1

  outputs:
    - name: stdout
      match: '*'
      format: json_lines
      json_date_key: false
"""


def _build_extended_env_refresh_config(secret_file):
    secret_uri = Path(secret_file).resolve().as_uri()

    return f"""service:
  flush: 1
  grace: 1
  log_level: info
  http_server: on
  http_port: ${{FLUENT_BIT_HTTP_MONITORING_PORT}}

env:
  - name: dynamic_secret
    uri: {secret_uri}
    refresh_interval: 1

pipeline:
  inputs:
    - name: dummy
      tag: config.env
      dummy: '{{"secret":"${{dynamic_secret}}","source":"dummy"}}'
      fixed_timestamp: off
      copies: 1

  outputs:
    - name: stdout
      match: '*'
      format: json_lines
      json_date_key: false
"""


def _write_config(tmp_path, name, contents):
    config_file = tmp_path / name
    config_file.write_text(contents, encoding="utf-8")
    return config_file


def test_environment_mapping_values_apply_through_pipeline(tmp_path):
    config_file = _write_config(
        tmp_path,
        "environment_mapping.yaml",
        _build_environment_mapping_config(),
    )

    service = Service(str(config_file))
    service.start()
    log_text = service.wait_for_log_contains("mapping-secret", timeout=15)
    service.stop()

    payload = _find_json_line(log_text, "mapping-secret")
    assert payload["secret"] == "mapping-secret"
    assert payload["source"] == "dummy"


def test_environment_extended_name_value_apply_through_pipeline(tmp_path):
    config_file = _write_config(
        tmp_path,
        "environment_extended_value.yaml",
        _build_environment_extended_value_config(),
    )

    service = Service(str(config_file))
    service.start()
    log_text = service.wait_for_log_contains("object-secret", timeout=15)
    service.stop()

    payload = _find_json_line(log_text, "object-secret")
    assert payload["secret"] == "object-secret"
    assert payload["source"] == "dummy"


def test_environment_extended_file_value_applies_at_startup(tmp_path):
    secret_file = tmp_path / "environment_secret.txt"

    secret_file.write_text("file-secret", encoding="utf-8")
    config_file = _write_config(
        tmp_path,
        "environment_extended_uri.yaml",
        _build_environment_extended_uri_config(secret_file),
    )

    service = Service(str(config_file))
    service.start()
    log_text = service.wait_for_log_contains("file-secret", timeout=15)
    service.stop()

    payload = _find_json_line(log_text, "file-secret")
    assert payload["secret"] == "file-secret"
    assert payload["source"] == "dummy"


def test_environment_missing_file_fails_startup(tmp_path):
    missing_file = tmp_path / "missing_environment_secret.txt"
    config_file = _write_config(
        tmp_path,
        "environment_missing_file.yaml",
        _build_environment_missing_file_config(missing_file),
    )

    service = Service(str(config_file))

    with pytest.raises(FluentBitStartupError):
        service.start()

    service.stop()


def test_environment_extended_file_values_refresh_through_pipeline(tmp_path):
    secret_file = tmp_path / "dynamic_secret.txt"

    secret_file.write_text("first-secret", encoding="utf-8")
    config_file = _write_config(
        tmp_path,
        "environment_extended_refresh.yaml",
        _build_extended_env_refresh_config(secret_file),
    )

    service = Service(str(config_file))
    service.start()

    try:
        first_log = service.wait_for_log_contains("first-secret", timeout=15)
        first_payload = _find_json_line(first_log, "first-secret")
        assert first_payload["secret"] == "first-secret"

        secret_file.write_text("second-secret", encoding="utf-8")

        second_log = service.wait_for_log_contains("second-secret", timeout=15)
        second_payload = _find_json_line(second_log, "second-secret")
        assert second_payload["secret"] == "second-secret"
    finally:
        service.stop()
