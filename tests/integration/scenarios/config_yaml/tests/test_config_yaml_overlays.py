import subprocess

import pytest
import requests

from utils.data_utils import read_file
from utils.fluent_bit_manager import FluentBitManager, FluentBitStartupError
from utils.test_service import FluentBitTestService


BASE = """includes:
  - $overlay service.yaml
  - $overlay site.yaml
service:
  flush: 1
  grace: 1
  http_server: on
  http_port: ${FLUENT_BIT_HTTP_MONITORING_PORT}
  telemetry:
    metrics:
      logs:
        tag_records:
          enabled: false
pipeline:
  inputs:
    - name: dummy
      alias: app
      tag: base
      samples: 1
      dummy: '{"layer":"base"}'
  outputs:
    - name: stdout
      match: site
      format: json_lines
"""

SERVICE = """defaults:
  cap: &limit 1
service:
  telemetry:
    metrics:
      logs:
        tag_records:
          enabled: true
          max_series: *limit
pipeline:
  inputs:
    - name: dummy
      alias: app
      tag: intermediate
"""

SITE = """defaults:
  cap: &limit 2
service:
  telemetry:
    metrics:
      logs:
        tag_records:
          max_series: *limit
pipeline:
  inputs:
    - name: dummy
      alias: app
      tag: site
"""


@pytest.mark.parametrize("version,ordinary_first", [("1.1", True), (None, False), ("1.2", False)])
def test_overlay_reconciles_inputs_and_nested_service(tmp_path, version, ordinary_first):
    master = tmp_path / "main.yaml"
    directive = f"%YAML {version}\n---\n" if version else ""
    ordinary = "  - fragment.yaml\n"
    overlay = "  - $overlay service.yaml\n"
    entries = ordinary + overlay if ordinary_first else overlay + ordinary
    (tmp_path / "fragment.yaml").write_text(
        "defaults:\n  shadow: &origin wrong\n---\ndefaults:\n  input_tag: &input_tag base\n",
        encoding="utf-8"
    )
    base = BASE.replace(overlay, entries).replace("tag: base", "tag: *input_tag")
    base = "defaults:\n  record: &origin '{\"layer\":\"base\"}'\n" + base.replace(
        """dummy: '{"layer":"base"}'""", "dummy: *origin"
    )
    master.write_text(base, encoding="utf-8")
    (tmp_path / "service.yaml").write_text(directive + SERVICE, encoding="utf-8")
    (tmp_path / "site.yaml").write_text(directive + SITE, encoding="utf-8")
    service = FluentBitTestService(str(master))
    try:
        if version == "1.2":
            control = tmp_path / "control.yaml"
            control.write_text(directive + "service:\n  flush: 1\n", encoding="utf-8")
            binary = FluentBitManager(str(control)).binary_absolute_path
            probe = subprocess.run([binary, "--dry-run", "-c", str(control)],
                                   capture_output=True, text=True, timeout=30)
            if probe.returncode:
                assert "found incompatible YAML document" in probe.stderr
                with pytest.raises(FluentBitStartupError):
                    service.start()
                log = read_file(service.flb.log_file)
                assert "service.yaml at line 1, column 1: found incompatible YAML document" in log
                return
        service.start()
        service.wait_for_condition(
            lambda: '"layer":"base"' in read_file(service.flb.log_file),
            timeout=15, description="base record routed by overlay tag",
        )
        url = f"http://127.0.0.1:{service.flb.http_monitoring_port}/api/v1/metrics"
        inputs = requests.get(url, timeout=5).json()["input"]
        assert list(inputs) == ["app"]
        assert inputs["app"]["records"] == 1
        metrics = f"http://127.0.0.1:{service.flb.http_monitoring_port}/api/v2/metrics/prometheus"
        service.wait_for_condition(
            lambda: 'fluentbit_input_logs_tag_records_total{name="app"' in
            requests.get(metrics, timeout=5).text,
            timeout=15, description="nested enabled setting inherited from first overlay",
        )
    finally:
        service.stop()


def test_nested_overlay_before_next_sibling(tmp_path):
    master = tmp_path / "main.yaml"
    sites = tmp_path / "sites"
    sites.mkdir()
    master.write_text(BASE.replace("$overlay service.yaml", "$overlay sites/site3.yaml"),
                      encoding="utf-8")
    (sites / "site3.yaml").write_text("includes:\n  - $overlay site4.yaml\n" + SERVICE +
                                     """      dummy: '{"layer":"parent"}'\n""", encoding="utf-8")
    (sites / "site4.yaml").write_text(SITE.replace("tag: site", "tag: nested") +
                                     """      dummy: '{"layer":"child"}'\n""", encoding="utf-8")
    (tmp_path / "site.yaml").write_text(SITE, encoding="utf-8")
    service = FluentBitTestService(str(master))
    try:
        service.start()
        service.wait_for_condition(
            lambda: '"layer":"child"' in read_file(service.flb.log_file),
            timeout=15, description="child payload routed by the later sibling's tag",
        )
    finally:
        service.stop()


@pytest.mark.parametrize("patch,diagnostic", [
    ("includes:\n  - $overlay ./site.yaml\n", "already included"),
    (SITE.replace("name: dummy", "name: tail"), "plugin mismatch"),
    (SITE.replace("alias: app", "alias: app\n      Alias: other"), "at most one nonempty alias"),
    (SITE + "    - name: dummy\n      alias: app\n", "duplicate input alias 'app'"),
    (SITE.replace("alias: app", "alias: fresh") + "    - name: dummy\n      alias: fresh\n",
     "duplicate input alias 'fresh'"),
    ("service: {flush: 1}\n---\nservice: {flush: 2}\n", "expected one YAML document"),
    ("service: {flush: 1}\nservice: {grace: 1}\n", "duplicated definition"),
    ("service: {flush: *base_flush}\n", "unresolved alias"),
    ("pipeline:\n  outputs:\n    - name: stdout\n", "unsupported overlay section"),
])
def test_invalid_overlay(tmp_path, patch, diagnostic):
    master = tmp_path / "main.yaml"
    master.write_text(BASE.replace("flush: 1", "flush: &base_flush 1"), encoding="utf-8")
    (tmp_path / "service.yaml").write_text(SERVICE, encoding="utf-8")
    (tmp_path / "site.yaml").write_text(patch, encoding="utf-8")
    service = FluentBitTestService(str(master))
    try:
        with pytest.raises(FluentBitStartupError):
            service.start()
        assert diagnostic in read_file(service.flb.log_file)
    finally:
        service.stop()


def test_duplicate_alias_in_base(tmp_path):
    master = tmp_path / "main.yaml"
    master.write_text(BASE.replace("  outputs:", "    - name: dummy\n      alias: app\n  outputs:"),
                      encoding="utf-8")
    service = FluentBitTestService(str(master))
    try:
        with pytest.raises(FluentBitStartupError):
            service.start()
        assert "duplicate input alias 'app'" in read_file(service.flb.log_file)
    finally:
        service.stop()


@pytest.mark.parametrize("paths,diagnostic", [
    ("  - $overlay\n", "$overlay requires a file path"),
    ("  - $overlay missing.yaml\n", "could not apply overlay 'missing.yaml'"),
    ("  - $overlay site.yaml\n" * 4096, "overlay include limit exceeded"),
], ids=["empty-path", "missing-file", "file-limit"])
def test_invalid_overlay_include(tmp_path, paths, diagnostic):
    master = tmp_path / "main.yaml"
    master.write_text("includes:\n" + paths, encoding="utf-8")
    service = FluentBitTestService(str(master))
    try:
        with pytest.raises(FluentBitStartupError):
            service.start()
        assert diagnostic in read_file(service.flb.log_file)
    finally:
        service.stop()


@pytest.mark.parametrize("base_processors,overlay_processors,valid", [
    ("sequence", None, False),
    ("mapping", "sequence", False),
    ("sequence", "mapping", True),
])
def test_input_processors_shape(tmp_path, base_processors, overlay_processors, valid):
    shapes = {"sequence": "\n        - name: content_modifier", "mapping": " {}"}
    main = BASE[BASE.index("service:"):]
    main = main.replace("      tag: base", "      processors:" + shapes[base_processors] + "\n      tag: site")
    if overlay_processors:
        main = "includes:\n  - $overlay site.yaml\n" + main
        (tmp_path / "site.yaml").write_text(
            SITE + "      processors:" + shapes[overlay_processors] + "\n", encoding="utf-8"
        )
    master = tmp_path / "main.yaml"
    master.write_text(main, encoding="utf-8")
    service = FluentBitTestService(str(master))
    try:
        if valid:
            service.start()
            service.wait_for_condition(lambda: '"layer":"base"' in read_file(service.flb.log_file),
                                       timeout=15, description="record from reconciled input")
        else:
            with pytest.raises(FluentBitStartupError):
                service.start()
            assert "processors must be a mapping" in read_file(service.flb.log_file)
    finally:
        service.stop()


@pytest.mark.parametrize("replacement", ["modify", "unknown_routed_processor"])
def test_overlay_processors_on_routed_input(tmp_path, replacement):
    main = BASE.replace("  - $overlay service.yaml\n", "").replace(
        "      tag: base", """      tag: site
      processors:
        logs:
          - name: replaced_processor
      routes:
        logs:
          - name: default
            to:
              outputs:
                - name: stdout"""
    )
    patch = """pipeline:
  inputs:
    - name: dummy
      alias: app
      processors:
        - name: modify
          set: layer intermediate
        - name: modify
          rename: layer routed_layer
"""
    master = tmp_path / "main.yaml"
    master.write_text(main, encoding="utf-8")
    (tmp_path / "site.yaml").write_text(patch.replace("name: modify", "name: " + replacement, 1),
                                       encoding="utf-8")
    service = FluentBitTestService(str(master))
    try:
        if replacement == "unknown_routed_processor":
            with pytest.raises(FluentBitStartupError):
                service.start()
            assert "cannot load processor 'unknown_routed_processor'" in read_file(service.flb.log_file)
            return
        service.start()
        service.wait_for_condition(lambda: '"routed_layer":"intermediate"' in read_file(service.flb.log_file),
                                   timeout=15, description="record transformed by both routed input processors")
    finally:
        service.stop()
