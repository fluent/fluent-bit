import logging
import os
import re

import requests

from server.http_server import (
    configure_http_response,
    configure_oauth_token_response,
    data_storage,
    http_server_run,
)
from utils.test_service import FluentBitTestService

logger = logging.getLogger(__name__)

METRIC_RE = re.compile(
    r'^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)\{(?P<labels>[^}]*)\}\s+(?P<value>[-+0-9.eE]+)$'
)
UNCOMPRESSED_PAYLOAD_SIZE_METRIC = (
    "fluentbit_azure_logs_ingestion_uncompressed_payload_size_bytes"
)
HTTP_PAYLOAD_SIZE_METRIC = "fluentbit_azure_logs_ingestion_http_payload_size_bytes"
PAYLOAD_SIZE_BUCKETS = [
    262144,
    524288,
    786432,
    1048576,
    1310720,
    1572864,
    1835008,
    2097152,
]


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
    series = []
    for line in metrics.splitlines():
        match = METRIC_RE.match(line)
        if match and match.group("name") == metric_name:
            series.append(
                (_labels_to_dict(match.group("labels")), float(match.group("value")))
            )
    return series


class Service:
    def __init__(self, config_file, initial_http_status=200):
        self.config_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "../config", config_file))
        cert_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../in_splunk/certificate"))
        self.tls_crt_file = os.path.join(cert_dir, "certificate.pem")
        self.tls_key_file = os.path.join(cert_dir, "private_key.pem")
        self.oauth_server_port = None
        self.initial_http_status = initial_http_status
        self.service = FluentBitTestService(
            self.config_file,
            data_storage=data_storage,
            data_keys=["payloads", "requests"],
            extra_env={
                "CERTIFICATE_TEST": self.tls_crt_file,
                "PRIVATE_KEY_TEST": self.tls_key_file,
            },
            pre_start=self._start_receiver,
            post_stop=self._stop_receiver,
        )

    def _start_receiver(self, service):
        self.oauth_server_port = service.allocate_port_env("TEST_SUITE_OAUTH_PORT")
        http_server_run(self.oauth_server_port)
        http_server_run(
            service.test_suite_http_port,
            use_tls=True,
            tls_crt_file=self.tls_crt_file,
            tls_key_file=self.tls_key_file,
            reset_state=False,
        )
        configure_http_response(status_code=self.initial_http_status)

        def _http_ready():
            try:
                response = requests.get(
                    f"http://127.0.0.1:{self.oauth_server_port}/ping",
                    timeout=1,
                )
                return response.status_code == 200
            except requests.RequestException:
                return False

        def _https_ready():
            try:
                response = requests.get(
                    f"https://localhost:{service.test_suite_http_port}/ping",
                    timeout=1,
                    verify=self.tls_crt_file,
                )
                return response.status_code == 200
            except requests.RequestException:
                return False

        self.service.wait_for_condition(
            _http_ready,
            timeout=10,
            interval=0.5,
            description="azure logs ingestion oauth receiver readiness",
        )

        self.service.wait_for_condition(
            _https_ready,
            timeout=10,
            interval=0.5,
            description="azure logs ingestion receiver readiness",
        )

    def _stop_receiver(self, service):
        try:
            if self.oauth_server_port is not None:
                requests.post(
                    f"http://127.0.0.1:{self.oauth_server_port}/shutdown",
                    timeout=2,
                )
        except requests.RequestException:
            pass

        try:
            requests.post(
                f"https://localhost:{service.test_suite_http_port}/shutdown",
                timeout=2,
                verify=self.tls_crt_file,
            )
        except requests.RequestException:
            pass

    def start(self):
        self.service.start()
        self.flb = self.service.flb
        self.flb_listener_port = self.service.flb_listener_port
        self.test_suite_http_port = self.service.test_suite_http_port

    def stop(self):
        self.service.stop()

    def wait_for_requests(self, minimum_count, timeout=10):
        return self.service.wait_for_condition(
            lambda: data_storage["requests"] if len(data_storage["requests"]) >= minimum_count else None,
            timeout=timeout,
            interval=0.5,
            description=f"{minimum_count} azure logs ingestion requests",
        )

    def wait_for_data_responses(self, minimum_count, timeout=10):
        return self.service.wait_for_condition(
            lambda: requests_seen
            if len(
                requests_seen := [
                    request
                    for request in data_storage["requests"]
                    if request.get("response_completed")
                ]
            )
            >= minimum_count
            else None,
            timeout=timeout,
            interval=0.5,
            description=f"{minimum_count} completed azure logs ingestion responses",
        )

    def metrics(self, expected, timeout=10):
        url = (
            f"http://127.0.0.1:{self.flb.http_monitoring_port}"
            "/api/v2/metrics/prometheus"
        )
        return self.service.wait_for_condition(
            lambda: response.text
            if (
                (response := requests.get(url, timeout=2)).status_code == 200
                and expected in response.text
            )
            else None,
            timeout=timeout,
            interval=0.5,
            description=f"prometheus metric {expected}",
        )


def test_out_azure_logs_ingestion_legacy_oauth2_and_payload_format():
    service = Service("out_azure_logs_ingestion_oauth2.yaml", initial_http_status=500)
    service.start()
    try:
        configure_oauth_token_response(
            status_code=200,
            body={
                "access_token": "oauth-access-token",
                "token_type": "Bearer",
                "expires_in": 300,
            },
        )

        requests_seen = service.wait_for_requests(2, timeout=15)
        configure_http_response(status_code=200, body={"status": "received"})
        requests_seen = service.wait_for_requests(3, timeout=15)
        service.wait_for_data_responses(2, timeout=15)
        metrics = service.metrics(
            f'{HTTP_PAYLOAD_SIZE_METRIC}_count{{name="azure_logs_ingestion.0"}} 2'
        )
    finally:
        service.stop()

    token_request = next(request for request in requests_seen if request["path"] == "/oauth/token")
    data_requests = [
        request
        for request in requests_seen
        if request["path"] == "/dataCollectionRules/dcr-suite/streams/Custom-suite_CL"
    ]
    data_request = data_requests[-1]
    assert [request["response_status"] for request in data_requests] == [500, 200]

    assert token_request["method"] == "POST"
    assert "grant_type=client_credentials" in token_request["raw_data"]
    assert "scope=https://monitor.azure.com/.default" in token_request["raw_data"]
    assert "client_id=suite-client" in token_request["raw_data"]
    assert "client_secret=suite-secret" in token_request["raw_data"]

    assert data_request["method"] == "POST"
    assert data_request["query_string"] == "api-version=2021-11-01-preview"
    assert data_request["headers"].get("Authorization") == "Bearer oauth-access-token"
    assert data_request["headers"].get("Content-Encoding") == "gzip"
    assert data_request["headers"].get("Content-Type") == "application/json"

    payload = data_request["json"]
    assert isinstance(payload, list)
    assert len(payload) == 1
    assert payload[0]["message"] == "hello from azure logs ingestion"
    assert payload[0]["source"] == "dummy"
    assert payload[0]["level"] == "info"
    assert isinstance(payload[0]["@timestamp"], (int, float))

    output_name = "azure_logs_ingestion.0"
    expected_uncompressed_size = sum(
        len(request["decoded_data"].encode("utf-8")) for request in data_requests
    )
    expected_http_size = sum(
        int(request["headers"]["Content-Length"]) for request in data_requests
    )

    for metric_name, expected_size in [
        (UNCOMPRESSED_PAYLOAD_SIZE_METRIC, expected_uncompressed_size),
        (HTTP_PAYLOAD_SIZE_METRIC, expected_http_size),
    ]:
        assert f"# TYPE {metric_name} histogram" in metrics
        assert _metric_value(metrics, f"{metric_name}_count", name=output_name) == 2
        assert _metric_value(metrics, f"{metric_name}_sum", name=output_name) == expected_size

        bucket_series = [
            (labels["le"], value)
            for labels, value in _metric_series(metrics, f"{metric_name}_bucket")
            if labels.get("name") == output_name
        ]
        assert bucket_series == [
            *[(f"{bucket}.0", 2) for bucket in PAYLOAD_SIZE_BUCKETS],
            ("+Inf", 2),
        ]
