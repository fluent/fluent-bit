"""Run the documented timestamp recipe against present and missing sources."""

from pathlib import Path

import pytest
import yaml

from test_fts_recipe_catalog import block, logs
from test_fts_records import rows, send


@pytest.mark.parametrize("placement", ["input", "output"])
def test_documented_timestamp_missing_policy(tmp_path, placement):
    root = Path(__file__).resolve().parents[5]
    guide = (root / "documentation/fts/blocks.md").read_text()
    section = guide.split("### 3. `logs.parse_timestamp`", 1)[1].split("### 4.", 1)[0]
    example = yaml.safe_load(section.split("```yaml\n", 1)[1].split("```", 1)[0])
    step = block("logs.parse_timestamp", **example["with"])
    inputs = [{"timestamp": "2038-01-19T03:14:08Z"}, {"message": "missing timestamp"}]

    with logs(tmp_path, [step], placement) as service:
        send(service, inputs)
        actual = service.wait_for_condition(lambda: rows(service), timeout=30)
        assert len(actual) == 2
        assert actual[0].pop("date") == 2147483648
        assert actual[1].pop("date") == 1700000000
        assert actual == inputs
