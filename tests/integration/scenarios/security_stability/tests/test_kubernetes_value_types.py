"""Malformed stream values must not be treated as MessagePack strings."""
from pathlib import Path

import pytest
import yaml

from utils.test_service import FluentBitTestService


@pytest.mark.parametrize("value", [None, False, 1, {}, []])
def test_kubernetes_non_string_stream(tmp_path, value):
    import json

    config = tmp_path / "kube-types.yaml"
    config.write_text(yaml.safe_dump({
        "service": {"flush": 0.2, "grace": 1, "http_server": True,
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {
            "inputs": [{"name": "dummy", "samples": 1,
                        "tag": "kube.var.log.containers.pod_default_container-" + "a" * 64 + ".log",
                        "dummy": json.dumps({"stream": value, "log": "type-guard-control"})}],
            "filters": [{"name": "kubernetes", "match": "kube.*", "use_tag_for_meta": True,
                         "merge_log": True}],
            "outputs": [{"name": "stdout", "match": "*", "format": "json_lines"}],
        },
    }))
    service = FluentBitTestService(str(config))
    try:
        service.start()
        service.wait_for_condition(
            lambda: '"log":"type-guard-control"' in Path(service.flb.log_file).read_text(),
            timeout=20, description="record with a non-string stream value")
        assert service.flb.process.poll() is None
    finally:
        service.stop()
