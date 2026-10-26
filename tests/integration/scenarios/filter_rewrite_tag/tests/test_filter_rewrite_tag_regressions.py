import json
from collections import Counter
from pathlib import Path

import pytest
import yaml

from utils.fluent_bit_manager import FluentBitStartupError
from utils.test_service import FluentBitTestService


@pytest.mark.parametrize("chain", ["single", "forward", "reverse", "cycle-forward", "cycle-reverse"])
@pytest.mark.parametrize("storage", ["memory", "filesystem"])
def test_pending_emitter_records_drain_at_eof(tmp_path, chain, storage):
    source = tmp_path / "source.log"
    source.write_text("hello\n" * 1000)
    filters = [{"name": "rewrite_tag", "match": "source",
                "rule": f"$log ^hello$ {'routed' if chain == 'single' else 'middle'} false"}]
    if chain != "single":
        filters.append({"name": "rewrite_tag", "match": "middle",
                        "rule": f"$log ^hello$ {'source' if chain.startswith('cycle') else 'routed'} false"})
        if chain in ("reverse", "cycle-reverse"):
            filters.reverse()
    config = {
        "service": {"flush": 0.2, "grace": 1, "log_level": "error",
                    "http_server": "on", "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {
            "inputs": [{"name": "tail", "tag": "source", "path": str(source),
                        "read_from_head": True, "exit_on_eof": True}],
            "filters": filters,
            "outputs": [{"name": "counter", "match": "*" if chain.startswith("cycle") else "routed",
                         "workers": 0}],
        },
    }
    config["service"]["storage.path"] = str(tmp_path / "storage")
    config["pipeline"]["inputs"][0]["storage.type"] = storage
    for rewrite in filters:
        rewrite["emitter_storage.type"] = storage
    config_path = tmp_path / "eof.yaml"
    config_path.write_text(yaml.safe_dump(config))
    service = FluentBitTestService(str(config_path))
    # EOF intentionally stops this finite input before the health check completes.
    with pytest.raises(FluentBitStartupError, match="exited early with code 0"):
        service.start()
    delivered = 0
    for line in Path(service.flb.log_file).read_text().splitlines():
        try:
            delivered += json.loads(line).get("log_records", 0)
        except (ValueError, AttributeError):
            pass
    assert delivered == 1000
    if chain.startswith("cycle"):
        assert "emitter cycle detected" in Path(service.flb.log_file).read_text()
