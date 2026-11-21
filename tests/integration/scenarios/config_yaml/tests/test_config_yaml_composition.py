"""Exercise composition through the real binary and the suite's memory checker."""
import json

import pytest
import requests

from utils.data_utils import read_file
from utils.fluent_bit_manager import FluentBitStartupError
from utils.test_service import FluentBitTestService


@pytest.mark.parametrize("merge_first", [False, True])
def test_included_defaults_and_explicit_overrides(tmp_path, merge_first):
    fragments = tmp_path / "fragments"
    fragments.mkdir()
    (fragments / "base.yaml").write_text("""defaults:
  service: &service
    flush: 60
    grace: 1
    log_level: invalid_inherited_value
    http_server: on
    http_port: ${FLUENT_BIT_HTTP_MONITORING_PORT}
  output: &output
    name: stdout
    match: '*'
    format: json_lines
  later: &later
    name: null
  tag: &tag composition.original
  input: &input
    name: dummy
    tag: *tag
    dummy: '{"message":"composed-record"}'
    samples: 1
  rebound: &tag composition.rebound
""", encoding="utf-8")
    (fragments / "nested.yaml").write_text("""includes:
  - base.yaml
defaults:
  nested: &nested
    <<: *service
    grace: 2
""", encoding="utf-8")
    merge = "  <<: *nested\n"
    explicit = "  flush: 1\n  log_level: info\n"
    config = tmp_path / "main.yaml"
    config.write_text(
        "includes:\n  - fragments/nested.yaml\nservice:\n"
        + (merge + explicit if merge_first else explicit + merge)
        + """pipeline:
  inputs:
    - *input
    - <<: *input
      tag: *tag
  outputs:
    - <<:
        - *output
        - *later
""", encoding="utf-8")
    service = FluentBitTestService(str(config))
    try:
        service.start()
        service.wait_for_condition(
            lambda: read_file(service.flb.log_file).count('"message":"composed-record"') == 2,
            timeout=20,
            description="both records from aliased input defaults",
        )
        def flushed_metrics():
            metrics = requests.get(
                f"http://127.0.0.1:{service.flb.http_monitoring_port}/api/v1/metrics",
                timeout=5,
            ).json()
            if metrics["output"]["stdout.0"]["proc_records"] == 2:
                return metrics
            return None

        metrics = service.wait_for_condition(
            flushed_metrics, timeout=15, description="completed output accounting"
        )
        assert metrics["input"]["dummy.0"]["records"] == 1, json.dumps(metrics)
        assert metrics["input"]["dummy.1"]["records"] == 1, json.dumps(metrics)
        assert metrics["output"]["stdout.0"]["proc_records"] == 2, json.dumps(metrics)
        assert metrics["output"]["stdout.0"]["errors"] == 0
        assert metrics["output"]["stdout.0"]["retries"] == 0
    finally:
        service.stop()


@pytest.mark.parametrize("contents,diagnostic", [
    ("service: {<<: *missing}\n", "unresolved alias"),
    ("defaults:\n  a: &a\n    - *a\n", "recursive alias"),
    ("defaults: {a: &a {<<: *a}}\n", "recursive alias"),
    ("service: {<<: 1}\n", "merge operand"),
    ("service:\n  <<:\n    - flush: 1\n    - bad\n", "merge operand"),
    ("defaults: []\n", "defaults must be a mapping"),
    ("&root\nincludes:\n  - *root\n", "recursive alias"),
    ("service: {flush: 1}\nservice: {grace: 1}\n", "duplicated definition"),
    ("includes:\n  - service.yaml\nservice: {grace: 1}\n", "duplicated definition"),
    ("includes:\n  - cycle.yaml\n", "already included"),
    ("defaults: {a: *later, b: &later value}\n", "unresolved alias"),
    ("defaults:\n  a: &a\n    includes:\n      - service.yaml\n<<: *a\n", "literal root entries"),
])
def test_invalid_composition(tmp_path, contents, diagnostic):
    config = tmp_path / "main.yaml"
    config.write_text(contents, encoding="utf-8")
    (tmp_path / "service.yaml").write_text("service: {flush: 1}\n", encoding="utf-8")
    (tmp_path / "cycle.yaml").write_text("includes:\n  - main.yaml\n", encoding="utf-8")
    service = FluentBitTestService(str(config))
    try:
        with pytest.raises(FluentBitStartupError):
            service.start()
        log = read_file(service.flb.log_file)
        assert diagnostic in log
        assert ".yaml" in log
    finally:
        service.stop()


def test_alias_expansion_is_bounded(tmp_path):
    config = tmp_path / "main.yaml"
    lines = ["defaults:", "  a0: &a0", "    - x"]
    for level in range(1, 23):
        lines.extend([f"  a{level}: &a{level}",
                      f"    - *a{level - 1}", f"    - *a{level - 1}"])
    # The resolver stores a graph; replay into variants must also have a budget.
    lines += ["pipeline:", "  inputs:", "    - name: dummy", "      test: *a22"]
    config.write_text("\n".join(lines) + "\n", encoding="utf-8")
    service = FluentBitTestService(str(config), shutdown_timeout=60)
    try:
        with pytest.raises(FluentBitStartupError):
            service.start()
        assert "limit exceeded" in read_file(service.flb.log_file)
    finally:
        service.stop()


def test_literal_include_list_expands_before_binding_next_item(tmp_path):
    (tmp_path / "first.yaml").write_text("""defaults:
  frozen: &frozen {log_level: *level}
  next: &next_file second.yaml
""", encoding="utf-8")
    (tmp_path / "second.yaml").write_text("""defaults:
  level: &level error
""", encoding="utf-8")
    (tmp_path / "third.yaml").write_text("""pipeline:
  outputs:
    - name: stdout
      match: '*'
      format: json_lines
""", encoding="utf-8")
    config = tmp_path / "main.yaml"
    config.write_text("""defaults:
  level: &level info
includes:
  - first.yaml
  - *next_file
  - &level third.yaml
  - optional/*.yaml
defaults: *frozen
service:
  <<: *frozen
  flush: 1
  grace: 1
  http_server: on
  http_port: ${FLUENT_BIT_HTTP_MONITORING_PORT}
pipeline:
  inputs:
    - name: dummy
      dummy: '{"message":"include-order-verified"}'
      samples: 1
""", encoding="utf-8")
    service = FluentBitTestService(str(config))
    try:
        service.start()
        service.wait_for_condition(
            lambda: '"message":"include-order-verified"' in read_file(service.flb.log_file),
            timeout=20,
            description="record from pipeline composed in include order",
        )
    finally:
        service.stop()


@pytest.mark.parametrize("limit", ["files", "nodes", "depth"])
def test_composition_resource_limits(tmp_path, limit):
    config = tmp_path / "main.yaml"
    if limit == "files":
        fragments = tmp_path / "fragments"
        fragments.mkdir()
        # Empty files consume no YAML nodes or input bytes. The entry file counts
        # toward the file limit, so the last of these 4096 includes must fail.
        for index in range(4096):
            (fragments / f"{index:04}.yaml").touch()
        contents = "includes:\n  - 'fragments/*.yaml'\n"
        diagnostic = "included file limit"
    elif limit == "nodes":
        contents = "defaults:\n  items:\n" + "    - x\n" * 65536
        diagnostic = "input size or nesting limit"
    else:
        contents = ("defaults:\n  items:\n"
                    + "".join(" " * (4 + 2 * level) + "-\n" for level in range(127))
                    + " " * 258 + "- x\n")
        diagnostic = "input size or nesting limit"
    config.write_text(contents, encoding="utf-8")
    service = FluentBitTestService(str(config), shutdown_timeout=60)
    try:
        with pytest.raises(FluentBitStartupError):
            service.start()
        assert diagnostic in read_file(service.flb.log_file)
    finally:
        service.stop()
