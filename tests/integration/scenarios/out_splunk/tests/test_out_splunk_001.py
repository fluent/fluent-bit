import os

import pytest
import requests

from server.http_server import configure_http_response, data_storage, http_server_run
from utils.test_service import FluentBitTestService


class Service:
    def __init__(self, config_file):
        self.config_file = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../config", config_file)
        )
        self.service = FluentBitTestService(
            self.config_file,
            data_storage=data_storage,
            data_keys=["payloads", "requests"],
            pre_start=self._start_receiver,
            post_stop=self._stop_receiver,
        )

    def _start_receiver(self, service):
        http_server_run(service.test_suite_http_port)
        configure_http_response(status_code=200, body={"text": "Success", "code": 0})
        self.service.wait_for_http_endpoint(
            f"http://127.0.0.1:{service.test_suite_http_port}/ping",
            timeout=10,
            interval=0.5,
        )

    def _stop_receiver(self, service):
        try:
            requests.post(
                f"http://127.0.0.1:{service.test_suite_http_port}/shutdown",
                timeout=2,
            )
        except requests.RequestException:
            pass

    def start(self):
        self.service.start()

    def stop(self):
        self.service.stop()

    def wait_for_requests(self, minimum_count, timeout=10):
        if os.environ.get("VALGRIND"):
            timeout = max(timeout * 3, 30)

        return self.service.wait_for_condition(
            lambda: data_storage["requests"]
            if len(data_storage["requests"]) >= minimum_count
            else None,
            timeout=timeout,
            interval=0.5,
            description=f"{minimum_count} outbound Splunk requests",
        )


@pytest.mark.parametrize(
    ("config_file", "expected_query", "expected_event_type"),
    [
        ("out_splunk_default.yaml", "", dict),
        (
            "out_splunk_auto_extract_timestamp.yaml",
            "auto_extract_timestamp=true",
            dict,
        ),
        (
            "out_splunk_auto_extract_timestamp_event_key.yaml",
            "auto_extract_timestamp=true",
            str,
        ),
    ],
    ids=["default", "auto_extract_timestamp", "auto_extract_timestamp_event_key"],
)
def test_out_splunk_auto_extract_timestamp(
    config_file, expected_query, expected_event_type
):
    service = Service(config_file)
    service.start()

    try:
        requests_seen = service.wait_for_requests(1)
    finally:
        service.stop()

    first_request = requests_seen[0]
    assert first_request["path"] == "/services/collector/event"
    assert first_request["query_string"] == expected_query
    assert first_request["headers"].get("Authorization") == "Splunk secret-token"
    assert isinstance(first_request["json"]["event"], expected_event_type)
    assert ("time" in first_request["json"]) == (expected_query == "")
