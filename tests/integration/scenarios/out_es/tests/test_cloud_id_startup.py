"""Validate Cloud ID buffer boundaries through output initialization."""
import base64
from pathlib import Path

import pytest

from utils.fluent_bit_manager import FluentBitStartupError
from utils.test_service import FluentBitTestService


@pytest.mark.parametrize("decoded", [b"r$" + b"B" * 254, b"r$" + b"B" * 300, b"missing-separator"])
def test_cloud_id_invalid_startup(tmp_path, decoded):
    cloud_id = "test:" + base64.b64encode(decoded).decode()
    config = tmp_path / "es.conf"
    config.write_text(f"""
[SERVICE]
    Flush 0.2
    Grace 1
    HTTP_Server On
    HTTP_Port ${{FLUENT_BIT_HTTP_MONITORING_PORT}}
[INPUT]
    Name dummy
    Samples 1
[OUTPUT]
    Name es
    Match *
    Cloud_ID {cloud_id}
""")
    service = FluentBitTestService(str(config))
    try:
        with pytest.raises(FluentBitStartupError):
            service.start()
        assert "cannot extract cloud_host" in Path(service.flb.log_file).read_text()
    finally:
        service.stop()


@pytest.mark.parametrize("host", [b"example", b"example:9243"])
def test_cloud_id_valid_startup(tmp_path, host):
    cloud_id = "test:" + base64.b64encode(b"invalid$" + host + b"$kibana").decode()
    config = tmp_path / "valid-es.conf"
    config.write_text(f"""
[SERVICE]
    Flush 1
    Grace 1
    Log_Level debug
    HTTP_Server On
    HTTP_Port ${{FLUENT_BIT_HTTP_MONITORING_PORT}}
[INPUT]
    Name dummy
    Tag control
    Samples 1
[OUTPUT]
    Name es
    Match unused
    Cloud_ID {cloud_id}
[OUTPUT]
    Name null
    Match control
""")
    service = FluentBitTestService(str(config))
    try:
        service.start()
        assert "extracted cloud_host:" in Path(service.flb.log_file).read_text()
    finally:
        service.stop()
