import os
import re

import requests

from utils.test_service import FluentBitTestService


METRIC_RE = re.compile(
    r'^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)\{(?P<labels>[^}]*)\}\s+(?P<value>[-+0-9.eE]+)$'
)


class Service:
    def __init__(self, config_file):
        self.config_file = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../config", config_file)
        )
        self.service = FluentBitTestService(self.config_file)

    def start(self):
        self.service.start()
        self.flb = self.service.flb

    def stop(self):
        self.service.stop()

    def metrics(self, expected=None):
        url = f"http://127.0.0.1:{self.flb.http_monitoring_port}/api/v2/metrics/prometheus"
        return self.service.wait_for_condition(
            lambda: response.text
            if (
                (response := requests.get(url, timeout=2)).status_code == 200
                and (expected is None or expected in response.text)
            )
            else None,
            timeout=10,
            interval=0.5,
            description="prometheus metrics",
        )


def _labels_to_dict(labels):
    result = {}
    for item in labels.split(","):
        key, value = item.split("=", 1)
        result[key] = value.strip('"')
    return result


def _metric_value(metrics, metric_name, **labels):
    for line in metrics.splitlines():
        match = METRIC_RE.match(line)
        if not match or match.group("name") != metric_name:
            continue
        if _labels_to_dict(match.group("labels")) == labels:
            return float(match.group("value"))
    return None


def _metric_series(metrics, metric_name):
    """Return a list of (labels_dict, value) for every series of metric_name."""
    series = []
    for line in metrics.splitlines():
        match = METRIC_RE.match(line)
        if not match or match.group("name") != metric_name:
            continue
        series.append(
            (_labels_to_dict(match.group("labels")), float(match.group("value")))
        )
    return series


def _run_until_value(config_file, metric_name, predicate, **labels):
    """Start a service and wait until the metric value satisfies `predicate`."""
    service = Service(config_file)
    try:
        service.start()
        url = (
            f"http://127.0.0.1:{service.flb.http_monitoring_port}"
            "/api/v2/metrics/prometheus"
        )

        def check():
            response = requests.get(url, timeout=2)
            if response.status_code != 200:
                return None
            value = _metric_value(response.text, metric_name, **labels)
            if value is not None and predicate(value):
                return response.text
            return None

        return service.service.wait_for_condition(
            check,
            timeout=15,
            interval=0.5,
            description=f"{metric_name} value condition",
        )
    finally:
        service.stop()


def _run_with_metrics(config_file, expected=None):
    service = Service(config_file)
    try:
        service.start()
        return service.metrics(expected=expected)
    finally:
        service.stop()


def test_input_tag_records_enabled_by_service_yaml():
    metrics = _run_with_metrics(
        "tag_records_enabled.yaml",
        expected='fluentbit_input_logs_tag_records_total{name="tag_records_dummy"',
    )

    value = _metric_value(
        metrics,
        "fluentbit_input_logs_tag_records_total",
        name="tag_records_dummy",
        tag="tag.records.one",
    )
    assert value == 1


def test_input_tag_records_disabled_by_default():
    metrics = _run_with_metrics("tag_records_disabled.yaml")

    assert "fluentbit_input_logs_tag_records_total" not in metrics
    assert "fluentbit_input_logs_tag_records_untracked_total" not in metrics


def test_input_tag_records_respects_global_max_series():
    metrics = _run_with_metrics(
        "tag_records_max_series.yaml",
        expected="fluentbit_input_logs_tag_records_untracked_total",
    )

    # With max_series=1 and two inputs each producing one tag, exactly one
    # (name, tag) series must be tracked and exactly one must be rejected with
    # the "max_series" reason. Which input wins the single slot depends on
    # ingestion ordering, so assert the invariant rather than a specific input.
    tracked = _metric_series(metrics, "fluentbit_input_logs_tag_records_total")
    assert len(tracked) == 1

    rejected = [
        labels
        for labels, value in _metric_series(
            metrics, "fluentbit_input_logs_tag_records_untracked_total"
        )
        if labels.get("reason") == "max_series" and value >= 1
    ]
    assert len(rejected) == 1

    # The rejected input must be the one that did NOT get the tracked slot.
    tracked_name = tracked[0][0]["name"]
    assert rejected[0]["name"] != tracked_name


def test_input_tag_records_respects_tag_length_limit():
    metrics = _run_with_metrics(
        "tag_records_max_tag_length.yaml",
        expected="fluentbit_input_logs_tag_records_untracked_total",
    )

    assert (
        _metric_value(
            metrics,
            "fluentbit_input_logs_tag_records_untracked_total",
            name="tag_records_long_tag",
            reason="tag_length_limit",
        )
        == 1
    )
    assert "fluentbit_input_logs_tag_records_total" not in metrics


def test_input_tag_records_can_be_disabled_per_input():
    metrics = _run_with_metrics("tag_records_input_override.yaml")

    assert "fluentbit_input_logs_tag_records_total" not in metrics
    assert "fluentbit_input_logs_tag_records_untracked_total" not in metrics


def test_input_tag_records_counter_accumulates():
    # The counter is monotonic; with a continuously emitting input the value
    # must climb past the first record, proving records are added (not reset).
    metrics = _run_until_value(
        "tag_records_accumulate.yaml",
        "fluentbit_input_logs_tag_records_total",
        lambda value: value >= 2,
        name="tag_records_accumulate",
        tag="tag.records.acc",
    )

    value = _metric_value(
        metrics,
        "fluentbit_input_logs_tag_records_total",
        name="tag_records_accumulate",
        tag="tag.records.acc",
    )
    assert value >= 2


def test_input_tag_records_tracks_multiple_tags():
    metrics = _run_with_metrics(
        "tag_records_multi_tag.yaml",
        expected='tag="tag.records.beta"',
    )

    alpha = _metric_value(
        metrics,
        "fluentbit_input_logs_tag_records_total",
        name="tag_records_multi_a",
        tag="tag.records.alpha",
    )
    beta = _metric_value(
        metrics,
        "fluentbit_input_logs_tag_records_total",
        name="tag_records_multi_b",
        tag="tag.records.beta",
    )

    assert alpha is not None and alpha >= 1
    assert beta is not None and beta >= 1

    # Two distinct (name, tag) series must be tracked independently.
    series = _metric_series(metrics, "fluentbit_input_logs_tag_records_total")
    tags = {labels["tag"] for labels, _ in series}
    assert {"tag.records.alpha", "tag.records.beta"} <= tags

    # No series should have been rejected under the default limits.
    assert "fluentbit_input_logs_tag_records_untracked_total" not in metrics


def test_input_tag_records_can_be_enabled_per_input_only():
    # Service-level telemetry is disabled (default). Only the input that opts
    # in must export tag record metrics; the other input must export nothing.
    metrics = _run_with_metrics(
        "tag_records_input_enable.yaml",
        expected='name="tag_records_enabled_input"',
    )

    enabled = _metric_value(
        metrics,
        "fluentbit_input_logs_tag_records_total",
        name="tag_records_enabled_input",
        tag="tag.records.on",
    )
    assert enabled is not None and enabled >= 1

    # The input that did not opt in must not appear in any tag record series.
    for labels, _ in _metric_series(metrics, "fluentbit_input_logs_tag_records_total"):
        assert labels.get("name") != "tag_records_default_input"
    for labels, _ in _metric_series(
        metrics, "fluentbit_input_logs_tag_records_untracked_total"
    ):
        assert labels.get("name") != "tag_records_default_input"


def test_input_tag_records_nested_block_disables_input():
    # An input can override the service setting using the SAME nested block
    # style as the service section (telemetry: -> metrics: -> tag_records:).
    # Service is enabled; the nested block disables one input only.
    metrics = _run_with_metrics(
        "tag_records_input_nested_disable.yaml",
        expected='name="tag_records_nested_control"',
    )

    control = _metric_value(
        metrics,
        "fluentbit_input_logs_tag_records_total",
        name="tag_records_nested_control",
        tag="tag.records.nested.on",
    )
    assert control is not None and control >= 1

    # The nested-block-disabled input must not appear at all.
    for labels, _ in _metric_series(metrics, "fluentbit_input_logs_tag_records_total"):
        assert labels.get("name") != "tag_records_nested_off"
    for labels, _ in _metric_series(
        metrics, "fluentbit_input_logs_tag_records_untracked_total"
    ):
        assert labels.get("name") != "tag_records_nested_off"


def test_input_tag_records_nested_block_enables_input():
    # Service-level telemetry is off. An input enables it using the nested
    # block form. This also guards against the previous regression where a
    # nested block inside an input aborted startup.
    metrics = _run_with_metrics(
        "tag_records_input_nested_enable.yaml",
        expected='name="tag_records_nested_enabled"',
    )

    enabled = _metric_value(
        metrics,
        "fluentbit_input_logs_tag_records_total",
        name="tag_records_nested_enabled",
        tag="tag.records.nested.enable",
    )
    assert enabled is not None and enabled >= 1

    # The input that did not opt in must not be tracked.
    for labels, _ in _metric_series(metrics, "fluentbit_input_logs_tag_records_total"):
        assert labels.get("name") != "tag_records_nested_default"
