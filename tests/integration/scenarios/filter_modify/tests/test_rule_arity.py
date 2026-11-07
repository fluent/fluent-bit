"""Malformed modify rules must fail startup instead of becoming Rename rules."""

import json
from pathlib import Path

import pytest

from utils.fluent_bit_manager import FluentBitStartupError
from utils.test_service import FluentBitTestService


def make_service(tmp_path, rule):
    config = tmp_path / "modify.conf"
    config.write_text(f"""[SERVICE]
    Flush 0.2
    Grace 1
    HTTP_Server On
    HTTP_Listen 127.0.0.1
    HTTP_Port ${{FLUENT_BIT_HTTP_MONITORING_PORT}}
[INPUT]
    Name dummy
    Tag modify.test
    Dummy {{"credit_card":"4111111111111111","ssn":"123-45-6789"}}
[FILTER]
    Name modify
    Match *
    Condition Key_exists credit_card
    Condition Key_value_equals ssn 123-45-6789
    Set ssn REDACTED
    {rule}
[OUTPUT]
    Name stdout
    Match *
    Format json_lines
""")
    return FluentBitTestService(str(config))


@pytest.mark.parametrize("operation", [
    "Set", "Add", "Rename", "Hard_rename", "Copy",
    "Hard_copy", "Remove", "Remove_wildcard", "Remove_regex", "Move_to_start",
    "Move_to_end",
])
def test_three_token_rule_rejected(tmp_path, operation):
    service = make_service(tmp_path, f"{operation} credit_card XXXX XXXX")
    try:
        with pytest.raises(FluentBitStartupError):
            service.start()
        logs = Path(service.flb.log_file).read_text()
        assert f"invalid config for {operation.lower()}" in logs.lower()
        assert "4111111111111111" not in logs
    finally:
        service.stop()


@pytest.mark.parametrize("rule", [
    "Set credit_card", "Set credit_card XXXX XXXX XXXX", "Remove credit_card extra",
])
def test_other_invalid_arities_rejected(tmp_path, rule):
    service = make_service(tmp_path, rule)
    try:
        with pytest.raises(FluentBitStartupError):
            service.start()
    finally:
        service.stop()


@pytest.mark.parametrize("value, expected", [
    ("REDACTED", "REDACTED"), ('"XXXX XXXX"', "XXXX XXXX"),
    ("'XXXX XXXX'", "XXXX XXXX"),
])
def test_set_redacts_with_valid_arity(tmp_path, value, expected):
    service = make_service(tmp_path, f"Set credit_card {value}")

    def records():
        return [json.loads(line) for line in Path(service.flb.log_file).read_text().splitlines()
                if line.startswith("{")]

    try:
        service.start()
        output = service.wait_for_condition(records, timeout=20)
        assert all(record["credit_card"] == expected and record["ssn"] == "REDACTED"
                   and "XXXX" not in record for record in output)
    finally:
        service.stop()


@pytest.mark.parametrize("rule, expected", [
    ("Remove credit_card", {"ssn": "REDACTED"}),
    ("Rename credit_card card", {"ssn": "REDACTED", "card": "4111111111111111"}),
])
def test_valid_remove_and_rename(tmp_path, rule, expected):
    service = make_service(tmp_path, rule)

    def records():
        return [json.loads(line) for line in Path(service.flb.log_file).read_text().splitlines()
                if line.startswith("{")]

    try:
        service.start()
        output = service.wait_for_condition(records, timeout=20)
        for record in output:
            record.pop("date")
            assert record == expected
    finally:
        service.stop()
