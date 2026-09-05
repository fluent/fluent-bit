import base64
import logging
import os
import random
import re
import signal
import sqlite3
import tempfile
import time

import pytest
import requests

from server.http_server import (
    configure_http_response,
    configure_oauth_token_response,
    data_storage,
    http_server_run,
)
from utils.fluent_bit_manager import FluentBitStartupError
from utils.test_service import FluentBitTestService

logger = logging.getLogger(__name__)

METRIC_RE = re.compile(
    r'^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)\{(?P<labels>[^}]*)\}\s+'
    r'(?P<value>[-+0-9.eE]+)$'
)
UNCOMPRESSED_PAYLOAD_SIZE_METRIC = (
    "fluentbit_azure_logs_ingestion_uncompressed_payload_size_bytes"
)
HTTP_PAYLOAD_SIZE_METRIC = "fluentbit_azure_logs_ingestion_http_payload_size_bytes"
HTTP_PAYLOAD_SIZE_MIN_METRIC = "fluentbit_azure_logs_ingestion_http_payload_size_min_bytes"
SMALL_REQUEST_BUCKET = "204800.0"


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


class Service:
    def __init__(
        self,
        config_file,
        buffer_dir=None,
        buffer_limit="4M",
        buffer_key="suite-buffer",
        initial_http_status=None,
        receiver_port=None,
    ):
        if os.path.isabs(config_file):
            self.config_file = config_file
        else:
            self.config_file = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "../config", config_file)
            )
        cert_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../in_splunk/certificate"))
        self.tls_crt_file = os.path.join(cert_dir, "certificate.pem")
        self.tls_key_file = os.path.join(cert_dir, "private_key.pem")
        self.oauth_server_port = None
        self.buffer_dir_owner = None
        self.initial_http_status = initial_http_status
        self.receiver_port = receiver_port
        if buffer_dir is None:
            self.buffer_dir_owner = tempfile.TemporaryDirectory(prefix="azure-li-batch-")
            buffer_dir = self.buffer_dir_owner.name
        self.buffer_dir = buffer_dir
        self.service = FluentBitTestService(
            self.config_file,
            data_storage=data_storage,
            data_keys=["payloads", "requests"],
            extra_env={
                "CERTIFICATE_TEST": self.tls_crt_file,
                "PRIVATE_KEY_TEST": self.tls_key_file,
                "AZURE_LOGS_INGESTION_BUFFER_DIR": self.buffer_dir,
                "AZURE_LOGS_INGESTION_BUFFER_LIMIT": buffer_limit,
                "AZURE_LOGS_INGESTION_BUFFER_KEY": buffer_key,
            },
            pre_start=self._start_receiver,
            post_stop=self._stop_receiver,
        )

    def _start_receiver(self, service):
        if self.receiver_port is not None:
            service.test_suite_http_port = self.receiver_port
            service._allocated_ports.add(self.receiver_port)
            service._set_env("TEST_SUITE_HTTP_PORT", str(self.receiver_port))
        self.oauth_server_port = service.allocate_port_env("TEST_SUITE_OAUTH_PORT")
        http_server_run(self.oauth_server_port)
        http_server_run(
            service.test_suite_http_port,
            use_tls=True,
            tls_crt_file=self.tls_crt_file,
            tls_key_file=self.tls_key_file,
            reset_state=False,
        )
        if self.initial_http_status is not None:
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
        if self.buffer_dir_owner is not None:
            self.buffer_dir_owner.cleanup()

    def wait_for_requests(self, minimum_count, timeout=10):
        return self.service.wait_for_condition(
            lambda: data_storage["requests"] if len(data_storage["requests"]) >= minimum_count else None,
            timeout=timeout,
            interval=0.5,
            description=f"{minimum_count} azure logs ingestion requests",
        )

    def metrics(self, expected, timeout=10):
        url = (
            f"http://127.0.0.1:{self.flb.http_monitoring_port}"
            "/api/v2/metrics/prometheus"
        )

        def _expected_metric():
            response = requests.get(url, timeout=2)
            if response.status_code == 200 and expected in response.text:
                return response.text
            return None

        return self.service.wait_for_condition(
            _expected_metric,
            timeout=timeout,
            interval=0.5,
            description=f"Prometheus metric {expected}",
        )

    def wait_for_log(self, text, timeout=10):
        def _contains_text():
            log_file = self.service.flb.log_file
            if not log_file or not os.path.exists(log_file):
                return None
            with open(log_file, "r", encoding="utf-8", errors="replace") as handle:
                contents = handle.read()
            return contents if text in contents else None

        return self.service.wait_for_condition(
            _contains_text,
            timeout=timeout,
            interval=0.5,
            description=f"Fluent Bit log containing {text!r}",
        )


def test_out_azure_logs_ingestion_legacy_oauth2_and_payload_format():
    service = Service("out_azure_logs_ingestion_oauth2.yaml")
    service.start()
    configure_http_response(status_code=200, body={"status": "received"})
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    requests_seen = service.wait_for_requests(2, timeout=15)
    service.stop()

    token_request = next(request for request in requests_seen if request["path"] == "/oauth/token")
    data_request = next(
        request
        for request in requests_seen
        if request["path"] == "/dataCollectionRules/dcr-suite/streams/Custom-suite_CL"
    )

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


def test_out_azure_logs_ingestion_reports_payload_size_histograms():
    service = Service(
        "out_azure_logs_ingestion_oauth2.yaml",
        initial_http_status=500,
    )
    service.start()
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    try:
        service.wait_for_requests(2, timeout=15)
        configure_http_response(status_code=200, body={"status": "received"})
        requests_seen = service.wait_for_requests(3, timeout=15)
        metrics = service.metrics(
            f'{HTTP_PAYLOAD_SIZE_METRIC}_count{{name="azure_logs_ingestion.0",'
            f'dcr_id="dcr-suite"}} 2'
        )
    finally:
        service.stop()

    data_requests = _data_requests(requests_seen)
    output_name = "azure_logs_ingestion.0"
    metric_labels = {"name": output_name, "dcr_id": "dcr-suite"}
    expected_uncompressed_size = sum(
        len(request["decoded_data"].encode("utf-8")) for request in data_requests
    )
    expected_http_size = sum(
        int(request["headers"]["Content-Length"]) for request in data_requests
    )

    assert len(data_requests) == 2
    for metric_name, expected_size in (
        (UNCOMPRESSED_PAYLOAD_SIZE_METRIC, expected_uncompressed_size),
        (HTTP_PAYLOAD_SIZE_METRIC, expected_http_size),
    ):
        assert f"# TYPE {metric_name} histogram" in metrics
        assert _metric_value(metrics, f"{metric_name}_count", **metric_labels) == 2
        assert _metric_value(metrics, f"{metric_name}_sum", **metric_labels) == expected_size
        assert _metric_value(
            metrics,
            f"{metric_name}_bucket",
            le=SMALL_REQUEST_BUCKET,
            **metric_labels,
        ) == 2

    assert _metric_value(
        metrics, HTTP_PAYLOAD_SIZE_MIN_METRIC, **metric_labels
    ) == min(int(request["headers"]["Content-Length"]) for request in data_requests)


@pytest.mark.parametrize("buffer_key", [".", ".."])
def test_out_azure_logs_ingestion_rejects_special_buffer_keys(buffer_key):
    service = Service(
        "out_azure_logs_ingestion_buffering.yaml",
        buffer_key=buffer_key,
    )
    try:
        with pytest.raises(FluentBitStartupError):
            service.start()
    finally:
        service.stop()


def test_out_azure_logs_ingestion_rejects_multiple_buffer_workers():
    config_path = _hot_reload_config()
    with open(config_path, encoding="utf-8") as handle:
        config = handle.read()
    config = config.replace(
        "      buffering_enabled: on\n",
        "      buffering_enabled: on\n      workers: 2\n",
        1,
    )
    with open(config_path, "w", encoding="utf-8") as handle:
        handle.write(config)

    service = Service(config_path)
    try:
        with pytest.raises(FluentBitStartupError):
            service.start()
    finally:
        service.stop()
        os.unlink(config_path)


def test_out_azure_logs_ingestion_rejects_second_process_for_shared_root():
    first = Service("out_azure_logs_ingestion_buffering.yaml")
    first.start()
    second = Service(
        "out_azure_logs_ingestion_buffering.yaml",
        buffer_dir=first.buffer_dir,
        buffer_key="second-process",
    )
    try:
        with pytest.raises(FluentBitStartupError):
            second.start()
    finally:
        second.stop()
        first.stop()


def test_out_azure_logs_ingestion_batches_multiple_engine_flushes():
    service = Service("out_azure_logs_ingestion_buffering.yaml")
    service.start()
    configure_http_response(status_code=204, body="")
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    rng = random.Random(13254)
    records = []
    try:
        for index in range(2):
            record = {
                "id": str(index),
                "message": base64.b64encode(rng.randbytes(1800)).decode("ascii"),
            }
            records.append(record)
            response = requests.post(
                f"http://127.0.0.1:{service.flb_listener_port}/",
                json=record,
                timeout=5,
            )
            assert response.status_code == 201
            if index == 0:
                time.sleep(1.5)
                data_requests = [
                    item for item in data_storage["requests"]
                    if item["path"].startswith("/dataCollectionRules/")
                ]
                assert data_requests == []

        requests_seen = service.wait_for_requests(2, timeout=15)
    finally:
        service.stop()

    data_requests = [
        item for item in requests_seen
        if item["path"] == "/dataCollectionRules/dcr-suite/streams/Custom-suite_CL"
    ]
    assert len(data_requests) == 1
    request = data_requests[0]
    assert request["headers"].get("Content-Encoding") == "gzip"
    assert int(request["headers"]["Content-Length"]) <= 5000
    assert [item["id"] for item in request["json"]] == [item["id"] for item in records]
    assert len(request["json"]) == 2


def test_out_azure_logs_ingestion_uses_ratio_to_reduce_exact_probes():
    service = Service("out_azure_logs_ingestion_buffering.yaml")
    service.start()
    configure_http_response(status_code=204, body="")
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    rng = random.Random(13260)
    records = []
    try:
        for index in range(4):
            record = {
                "id": str(index),
                "message": base64.b64encode(rng.randbytes(1800)).decode("ascii"),
            }
            records.append(record)
            response = requests.post(
                f"http://127.0.0.1:{service.flb_listener_port}/",
                json=record,
                timeout=5,
            )
            assert response.status_code == 201
            time.sleep(1.5)

        def _all_records_delivered():
            requests_seen = list(data_storage["requests"])
            delivered = sum(len(request["json"]) for request in _data_requests(requests_seen))
            return requests_seen if delivered == 4 else None

        requests_seen = service.service.wait_for_condition(
            _all_records_delivered,
            timeout=20,
            interval=0.5,
            description="ratio-estimated buffered records",
        )
        log_path = service.service.flb.log_file
    finally:
        service.stop()

    data_requests = _data_requests(requests_seen)
    delivered_ids = [record["id"] for request in data_requests for record in request["json"]]
    assert delivered_ids == [record["id"] for record in records]
    with open(log_path, "r", encoding="utf-8", errors="replace") as handle:
        log_contents = handle.read()
    callback_records = [
        int(records)
        for records in re.findall(r"buffered callback records=(\d+)", log_contents)
    ]
    probe_events = [
        (int(records), int(probes), float(ratio))
        for records, probes, ratio in re.findall(
            r"planned durable request records=(\d+) probes=(\d+) "
            r"ratio=([0-9.]+)",
            log_contents,
        )
    ]

    assert sum(callback_records) == 4
    assert sum(records for records, _, _ in probe_events) == 4
    assert len(probe_events) < len(callback_records)
    assert 0 < sum(probes for _, probes, _ in probe_events) <= 8
    assert any(ratio < 1.0 for _, _, ratio in probe_events)
    assert "deferred exact probe using compression ratio" in log_contents


def test_out_azure_logs_ingestion_reaches_default_compressed_target():
    service = Service("out_azure_logs_ingestion_buffering_default_sizes.yaml")
    service.start()
    configure_http_response(status_code=204, body="")
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    rng = random.Random(1325400)
    records = []
    try:
        for index in range(100):
            record = {
                "id": str(index),
                "message": base64.b64encode(rng.randbytes(10000)).decode("ascii"),
            }
            records.append(record)
            response = requests.post(
                f"http://127.0.0.1:{service.flb_listener_port}/",
                json=record,
                timeout=5,
            )
            assert response.status_code == 201
        requests_seen = service.wait_for_requests(2, timeout=45)
    finally:
        service.stop()

    data_requests = _data_requests(requests_seen)
    assert len(data_requests) == 1
    compressed_size = int(data_requests[0]["headers"]["Content-Length"])
    assert 900000 <= compressed_size <= 1048576
    delivered_ids = [record["id"] for record in data_requests[0]["json"]]
    assert delivered_ids == [record["id"] for record in records[: len(delivered_ids)]]


def _send_buffering_records(service, count, seed, byte_count=1800):
    rng = random.Random(seed)
    records = []
    for index in range(count):
        record = {
            "id": str(index),
            "message": base64.b64encode(rng.randbytes(byte_count)).decode("ascii"),
        }
        records.append(record)
        response = requests.post(
            f"http://127.0.0.1:{service.flb_listener_port}/",
            json=record,
            timeout=5,
        )
        assert response.status_code == 201
    return records


def _data_requests(requests_seen):
    return [
        item for item in requests_seen
        if item["path"] == "/dataCollectionRules/dcr-suite/streams/Custom-suite_CL"
    ]


def _quarantine_count(buffer_dir, buffer_key="suite-buffer"):
    database = os.path.join(buffer_dir, ".azure_logs_ingestion.db")
    with sqlite3.connect(database) as connection:
        return connection.execute(
            "SELECT COUNT(*) FROM azli_requests "
            "WHERE instance_key=? AND state=5",
            (buffer_key,),
        ).fetchone()[0]


def test_out_azure_logs_ingestion_rolls_over_at_record_boundaries():
    service = Service(
        "out_azure_logs_ingestion_buffering_default_sizes.yaml",
        buffer_limit="16M",
    )
    service.start()
    configure_http_response(status_code=204, body="")
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    try:
        records = _send_buffering_records(service, 3, 13257, byte_count=700000)
        requests_seen = service.wait_for_requests(4, timeout=30)
    finally:
        service.stop()

    data_requests = _data_requests(requests_seen)
    assert len(data_requests) == 3
    assert all(int(item["headers"]["Content-Length"]) <= 1048576 for item in data_requests)
    delivered_ids = [record["id"] for request in data_requests for record in request["json"]]
    assert delivered_ids == [record["id"] for record in records]


def test_out_azure_logs_ingestion_timeout_flushes_underfilled_file():
    service = Service("out_azure_logs_ingestion_buffering.yaml")
    service.start()
    configure_http_response(status_code=204, body="")
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    try:
        response = requests.post(
            f"http://127.0.0.1:{service.flb_listener_port}/",
            json={"id": "timeout", "message": "underfilled\nwith embedded newline"},
            timeout=5,
        )
        assert response.status_code == 201
        requests_seen = service.wait_for_requests(2, timeout=15)
    finally:
        service.stop()

    data_requests = _data_requests(requests_seen)
    assert len(data_requests) == 1
    assert int(data_requests[0]["headers"]["Content-Length"]) < 3000
    assert [record["id"] for record in data_requests[0]["json"]] == ["timeout"]
    assert data_requests[0]["json"][0]["message"] == "underfilled\nwith embedded newline"


def test_out_azure_logs_ingestion_retries_buffered_file_after_500():
    service = Service("out_azure_logs_ingestion_buffering.yaml")
    service.start()
    configure_http_response(status_code=500, body={"error": "temporary"})
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    try:
        _send_buffering_records(service, 2, 13255)
        first_attempt = list(service.wait_for_requests(2, timeout=15))
        configure_http_response(status_code=204, body="")
        requests_seen = service.wait_for_requests(3, timeout=15)
        metrics = service.metrics(
            f'{HTTP_PAYLOAD_SIZE_METRIC}_count{{name="azure_logs_ingestion.0",'
            f'dcr_id="dcr-suite"}} 2'
        )
    finally:
        service.stop()

    data_requests = _data_requests(requests_seen)
    assert len(data_requests) == 2
    assert data_requests[0]["decoded_data"] == data_requests[1]["decoded_data"]
    assert data_requests[0]["headers"]["Content-Length"] == data_requests[1]["headers"]["Content-Length"]
    assert len(_data_requests(first_attempt)) == 1

    output_name = "azure_logs_ingestion.0"
    metric_labels = {"name": output_name, "dcr_id": "dcr-suite"}
    expected_uncompressed_size = sum(
        len(request["decoded_data"].encode("utf-8")) for request in data_requests
    )
    expected_http_size = sum(
        int(request["headers"]["Content-Length"]) for request in data_requests
    )
    assert _metric_value(
        metrics, f"{UNCOMPRESSED_PAYLOAD_SIZE_METRIC}_count", **metric_labels
    ) == 2
    assert _metric_value(
        metrics, f"{UNCOMPRESSED_PAYLOAD_SIZE_METRIC}_sum", **metric_labels
    ) == expected_uncompressed_size
    assert _metric_value(
        metrics, f"{HTTP_PAYLOAD_SIZE_METRIC}_count", **metric_labels
    ) == 2
    assert _metric_value(
        metrics, f"{HTTP_PAYLOAD_SIZE_METRIC}_sum", **metric_labels
    ) == expected_http_size
    assert _metric_value(
        metrics,
        f"{HTTP_PAYLOAD_SIZE_METRIC}_bucket",
        le=SMALL_REQUEST_BUCKET,
        **metric_labels,
    ) == 2
    assert _metric_value(
        metrics, HTTP_PAYLOAD_SIZE_MIN_METRIC, **metric_labels
    ) == min(int(request["headers"]["Content-Length"]) for request in data_requests)


def test_out_azure_logs_ingestion_retries_byte_identical_artifact_after_sigkill():
    with tempfile.TemporaryDirectory(prefix="azure-li-retry-recovery-") as buffer_dir:
        first = Service(
            "out_azure_logs_ingestion_buffering.yaml",
            buffer_dir=buffer_dir,
            initial_http_status=500,
        )
        first.start()
        configure_oauth_token_response(
            status_code=200,
            body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
        )
        try:
            _send_buffering_records(first, 2, 93255)
            requests_seen = first.wait_for_requests(2, timeout=15)
            first_hash = _data_requests(requests_seen)[0]["raw_sha256"]
            first.flb.send_signal(signal.SIGKILL)
            first.flb.process.wait(timeout=5)
        finally:
            first.stop()

        second = Service(
            "out_azure_logs_ingestion_buffering.yaml",
            buffer_dir=buffer_dir,
            initial_http_status=204,
            receiver_port=first.test_suite_http_port,
        )
        second.start()
        configure_oauth_token_response(
            status_code=200,
            body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
        )
        try:
            requests_seen = second.service.wait_for_condition(
                lambda: list(data_storage["requests"])
                if len(_data_requests(data_storage["requests"])) >= 1 else None,
                timeout=20,
                interval=0.5,
                description="byte-identical recovered request",
            )
        finally:
            second.stop()

    data_requests = _data_requests(requests_seen)
    assert len(data_requests) == 1
    assert data_requests[0]["raw_sha256"] == first_hash


def test_out_azure_logs_ingestion_quarantines_corrupt_request_artifact_on_recovery():
    with tempfile.TemporaryDirectory(prefix="azure-li-corrupt-request-") as buffer_dir:
        first = Service("out_azure_logs_ingestion_buffering.yaml", buffer_dir=buffer_dir)
        first.start()
        configure_http_response(status_code=500, body={"error": "retry"})
        configure_oauth_token_response(
            status_code=200,
            body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
        )
        try:
            _send_buffering_records(first, 2, 73256)
            first.wait_for_requests(2, timeout=15)
        finally:
            first.stop()

        database_path = os.path.join(buffer_dir, ".azure_logs_ingestion.db")
        with sqlite3.connect(database_path) as connection:
            connection.execute(
                "UPDATE azli_requests SET body_digest=zeroblob(32),state=1,next_retry=0 "
                "WHERE instance_key='suite-buffer'"
            )
            connection.commit()

        second = Service(
            "out_azure_logs_ingestion_buffering.yaml",
            buffer_dir=buffer_dir,
            receiver_port=first.test_suite_http_port,
        )
        second.start()
        try:
            second.wait_for_log("quarantining spans", timeout=10)
            with sqlite3.connect(database_path) as connection:
                state = connection.execute(
                    "SELECT state,reason FROM azli_requests "
                    "WHERE instance_key='suite-buffer'"
                ).fetchone()
            assert state == (5, "artifact_corrupt")
            assert _data_requests(data_storage["requests"]) == []
        finally:
            second.stop()


def test_out_azure_logs_ingestion_quarantines_413_without_replay():
    service = Service("out_azure_logs_ingestion_buffering.yaml")
    service.start()
    configure_http_response(status_code=413, body={"error": "too large"})
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    try:
        _send_buffering_records(service, 2, 13256)
        requests_seen = service.wait_for_requests(2, timeout=15)
        time.sleep(2.5)
        assert len(_data_requests(data_storage["requests"])) == 1
        assert _quarantine_count(service.buffer_dir) == 1
    finally:
        service.stop()

    assert len(_data_requests(requests_seen)) == 1


def test_out_azure_logs_ingestion_quarantine_remains_terminal_after_restart():
    with tempfile.TemporaryDirectory(prefix="azure-li-quarantine-recovery-") as buffer_dir:
        first = Service("out_azure_logs_ingestion_buffering.yaml", buffer_dir=buffer_dir)
        first.start()
        configure_http_response(status_code=413, body={"error": "too large"})
        configure_oauth_token_response(
            status_code=200,
            body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
        )
        try:
            _send_buffering_records(first, 2, 93256)
            first.wait_for_requests(2, timeout=15)
            first.service.wait_for_condition(
                lambda: _quarantine_count(buffer_dir) == 1,
                timeout=10,
                description="durable quarantine state",
            )
        finally:
            first.stop()

        second = Service(
            "out_azure_logs_ingestion_buffering.yaml",
            buffer_dir=buffer_dir,
            receiver_port=first.test_suite_http_port,
        )
        second.start()
        configure_http_response(status_code=204, body="")
        configure_oauth_token_response(
            status_code=200,
            body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
        )
        try:
            time.sleep(3)
            assert _data_requests(data_storage["requests"]) == []
            assert _quarantine_count(buffer_dir) == 1
        finally:
            second.stop()


def test_out_azure_logs_ingestion_recovers_underfilled_active_file():
    with tempfile.TemporaryDirectory(prefix="azure-li-recovery-") as buffer_dir:
        first = Service("out_azure_logs_ingestion_buffering.yaml", buffer_dir=buffer_dir)
        first.start()
        configure_http_response(status_code=204, body="")
        configure_oauth_token_response(
            status_code=200,
            body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
        )
        record = {"id": "recovered", "message": "small and underfilled"}
        try:
            response = requests.post(
                f"http://127.0.0.1:{first.flb_listener_port}/",
                json=record,
                timeout=5,
            )
            assert response.status_code == 201
            first.wait_for_log("buffered callback records=1", timeout=10)
            assert _data_requests(data_storage["requests"]) == []
            first.flb.send_signal(signal.SIGKILL)
            first.flb.process.wait(timeout=5)
        finally:
            first.stop()

        second = Service(
            "out_azure_logs_ingestion_buffering.yaml",
            buffer_dir=buffer_dir,
            receiver_port=first.test_suite_http_port,
        )
        second.start()
        configure_http_response(status_code=204, body="")
        configure_oauth_token_response(
            status_code=200,
            body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
        )
        try:
            requests_seen = second.wait_for_requests(2, timeout=15)
        finally:
            second.stop()

    data_requests = _data_requests(requests_seen)
    assert len(data_requests) == 1
    assert [item["id"] for item in data_requests[0]["json"]] == ["recovered"]


def test_out_azure_logs_ingestion_serializes_slow_uploads():
    service = Service("out_azure_logs_ingestion_buffering.yaml")
    service.start()
    configure_http_response(status_code=204, body="", delay_seconds=3)
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    rng = random.Random(13258)
    try:
        for index in range(3):
            response = requests.post(
                f"http://127.0.0.1:{service.flb_listener_port}/",
                json={
                    "id": f"slow-{index}",
                    "message": base64.b64encode(rng.randbytes(4000)).decode("ascii"),
                },
                timeout=5,
            )
            assert response.status_code == 201
            if index == 0:
                service.wait_for_requests(2, timeout=15)
            else:
                time.sleep(1.5)
            assert len(_data_requests(data_storage["requests"])) <= index + 1

        def _all_slow_records_delivered():
            requests_seen = list(data_storage["requests"])
            data_requests = _data_requests(requests_seen)
            delivered = [
                record["id"]
                for request in data_requests
                for record in request["json"]
            ]
            return requests_seen if delivered == ["slow-0", "slow-1", "slow-2"] else None

        requests_seen = service.service.wait_for_condition(
            _all_slow_records_delivered,
            timeout=20,
            interval=0.5,
            description="serialized slow-upload records",
        )
    finally:
        service.stop()

    data_requests = _data_requests(requests_seen)
    assert 2 <= len(data_requests) <= 3
    assert [record["id"] for request in data_requests for record in request["json"]] == [
        "slow-0",
        "slow-1",
        "slow-2",
    ]


def _hot_reload_config(base_name="out_azure_logs_ingestion_buffering.yaml"):
    source = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../config", base_name)
    )
    handle = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
    with open(source, encoding="utf-8") as source_handle:
        text = source_handle.read()
    with handle:
        text = text.replace(
            "  flush: 1\n",
            "  flush: 1\n  hot_reload: on\n  hot_reload.timeout: 15\n",
            1,
        )
        handle.write(text)
    return handle.name


@pytest.mark.parametrize("reload_method", ["http", "sighup"])
def test_out_azure_logs_ingestion_hot_reload_recovers_queued_chunks(reload_method):
    config_path = _hot_reload_config()
    service = Service(config_path)
    service.start()
    configure_http_response(status_code=204, body="")
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    try:
        before = requests.post(
            f"http://127.0.0.1:{service.flb_listener_port}/",
            json={"id": "before-reload", "message": "queued before reload"},
            timeout=5,
        )
        assert before.status_code == 201
        service.wait_for_log("buffered callback records=1", timeout=10)

        if reload_method == "http":
            service.flb.trigger_http_reload()
        else:
            service.flb.send_sighup()
        service.flb.wait_for_hot_reload_count(1, timeout=20)

        after = requests.post(
            f"http://127.0.0.1:{service.flb_listener_port}/",
            json={"id": "after-reload", "message": "queued after reload"},
            timeout=5,
        )
        assert after.status_code == 201
        requests_seen = service.wait_for_requests(2, timeout=20)
    finally:
        service.stop()
        os.unlink(config_path)

    delivered = [
        record["id"]
        for request in _data_requests(requests_seen)
        for record in request["json"]
    ]
    assert delivered == ["before-reload", "after-reload"]


def test_out_azure_logs_ingestion_repeated_hot_reload_applies_credentials():
    config_path = _hot_reload_config()
    service = Service(config_path)
    service.start()
    configure_http_response(status_code=204, body="")
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )
    expected_ids = []

    try:
        for generation in range(1, 6):
            with open(config_path, encoding="utf-8") as handle:
                config = handle.read()
            config = re.sub(
                r"client_secret: suite-secret(?:-\d+)?",
                f"client_secret: suite-secret-{generation}",
                config,
            )
            pending_path = f"{config_path}.tmp"
            with open(pending_path, "w", encoding="utf-8") as handle:
                handle.write(config)
            os.replace(pending_path, config_path)

            service.flb.trigger_http_reload()
            service.flb.wait_for_hot_reload_count(generation, timeout=20)
            record_id = f"generation-{generation}"
            expected_ids.append(record_id)
            response = requests.post(
                f"http://127.0.0.1:{service.flb_listener_port}/",
                json={"id": record_id, "message": "credential reload"},
                timeout=5,
            )
            assert response.status_code == 201

            def _generation_delivered():
                data_requests = _data_requests(data_storage["requests"])
                delivered = [
                    record["id"]
                    for request in data_requests
                    for record in request["json"]
                ]
                return delivered if record_id in delivered else None

            service.service.wait_for_condition(
                _generation_delivered,
                timeout=30,
                interval=0.25,
                description=f"delivery from generation {generation}",
            )
    finally:
        service.stop()
        os.unlink(config_path)

    delivered = [
        record["id"]
        for request in _data_requests(data_storage["requests"])
        for record in request["json"]
    ]
    oauth_bodies = [
        request["raw_data"]
        for request in data_storage["requests"]
        if request["path"] == "/oauth/token"
    ]
    assert delivered == expected_ids
    assert len(set(delivered)) == len(expected_ids)
    for generation in range(1, 6):
        assert any(
            f"client_secret=suite-secret-{generation}" in body
            for body in oauth_bodies
        )


def test_out_azure_logs_ingestion_hot_reload_during_suspended_upload():
    config_path = _hot_reload_config(
        "out_azure_logs_ingestion_buffering_short_timeout.yaml"
    )
    service = Service(config_path)
    service.start()
    configure_http_response(status_code=204, body="", hang_before_response=True)
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    try:
        response = requests.post(
            f"http://127.0.0.1:{service.flb_listener_port}/",
            json={"id": "inflight-reload", "message": "x" * 4000},
            timeout=5,
        )
        assert response.status_code == 201
        first_requests = service.wait_for_requests(2, timeout=15)
        assert len(_data_requests(first_requests)) == 1

        service.flb.trigger_http_reload()
        service.flb.wait_for_hot_reload_count(1, timeout=20)
        configure_http_response(status_code=204, body="", hang_before_response=False)

        def _retry_acked():
            data_requests = _data_requests(data_storage["requests"])
            if len(data_requests) < 2:
                return None
            database = os.path.join(service.buffer_dir, ".azure_logs_ingestion.db")
            with sqlite3.connect(database) as connection:
                pending = connection.execute(
                    "SELECT COUNT(*) FROM azli_requests "
                    "WHERE instance_key='suite-buffer' AND state<>5"
                ).fetchone()[0]
                sources = connection.execute(
                    "SELECT COUNT(*) FROM azli_sources "
                    "WHERE instance_key='suite-buffer'"
                ).fetchone()[0]
            return data_requests if pending == 0 and sources == 0 else None

        data_requests = service.service.wait_for_condition(
            _retry_acked,
            timeout=20,
            interval=0.25,
            description="acknowledged retry after hot reload",
        )
    finally:
        service.stop()
        os.unlink(config_path)

    assert data_requests[0]["raw_sha256"] == data_requests[1]["raw_sha256"]
    assert [record["id"] for record in data_requests[1]["json"]] == ["inflight-reload"]


def test_out_azure_logs_ingestion_stops_while_upload_is_suspended():
    service = Service("out_azure_logs_ingestion_buffering_short_timeout.yaml")
    service.start()
    configure_http_response(status_code=204, body="", hang_before_response=True)
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    stopped = False
    try:
        response = requests.post(
            f"http://127.0.0.1:{service.flb_listener_port}/",
            json={"id": "suspended-stop", "message": "x" * 4000},
            timeout=5,
        )
        assert response.status_code == 201
        service.wait_for_requests(2, timeout=15)
        started = time.monotonic()
        service.stop()
        stopped = True
        assert time.monotonic() - started < 10
    finally:
        if not stopped:
            service.stop()


def test_out_azure_logs_ingestion_quarantines_uncompressed_singleton():
    service = Service("out_azure_logs_ingestion_buffering.yaml")
    service.start()
    configure_http_response(status_code=204, body="")
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    try:
        response = requests.post(
            f"http://127.0.0.1:{service.flb_listener_port}/",
            json={"id": "large-compressible", "message": "A" * 70000},
            timeout=5,
        )
        assert response.status_code == 201
        service.wait_for_log("quarantined record", timeout=10)
        time.sleep(1.5)
        assert _data_requests(data_storage["requests"]) == []
        with sqlite3.connect(
            os.path.join(service.buffer_dir, ".azure_logs_ingestion.db")
        ) as connection:
            assert connection.execute(
                "SELECT COUNT(*) FROM azli_sources "
                "WHERE instance_key='suite-buffer' AND has_quarantine=1"
            ).fetchone()[0] == 1
    finally:
        service.stop()


def test_out_azure_logs_ingestion_high_volume_survives_hot_reload():
    config_path = _hot_reload_config(
        "out_azure_logs_ingestion_buffering_high_volume.yaml"
    )
    with open(config_path, encoding="utf-8") as handle:
        config = handle.read()
    config = config.replace("      rate: 100000", "      rate: 10000")
    with open(config_path, "w", encoding="utf-8") as handle:
        handle.write(config)

    service = Service(
        config_path,
        buffer_key="suite-high-volume",
        initial_http_status=500,
    )
    service.start()
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    try:
        failed_requests = service.wait_for_requests(2, timeout=30)
        failed_before_ids = {
            record["id"]
            for request in _data_requests(failed_requests)
            for record in request["json"]
        }
        assert failed_before_ids
        with open(config_path, encoding="utf-8") as handle:
            config = handle.read()
        config = config.replace(
            "      dummy: '{\"message\":\"high-volume batching regression\"}'",
            "      dummy: '{\"message\":\"high-volume batching after reload\"}'",
        )
        pending_path = f"{config_path}.tmp"
        with open(pending_path, "w", encoding="utf-8") as handle:
            handle.write(config)
        os.replace(pending_path, config_path)

        service.flb.trigger_http_reload()
        service.flb.wait_for_hot_reload_count(1, timeout=30)
        data_storage["payloads"] = []
        data_storage["requests"] = []
        configure_http_response(status_code=204, body="")
        database_path = os.path.join(service.buffer_dir, ".azure_logs_ingestion.db")

        def _spool_drained_after_reload():
            with sqlite3.connect(database_path) as connection:
                sources = connection.execute(
                    "SELECT COUNT(*) FROM azli_sources WHERE instance_key='suite-high-volume'"
                ).fetchone()[0]
                requests_count = connection.execute(
                    "SELECT COUNT(*) FROM azli_requests "
                    "WHERE instance_key='suite-high-volume'"
                ).fetchone()[0]
            data_requests = _data_requests(data_storage["requests"])
            delivered = [
                record for request in data_requests for record in request["json"]
            ]
            before_ids = {
                record["id"] for record in delivered
                if record["message"] == "high-volume batching regression"
            }
            before_count = len(before_ids)
            after_count = sum(
                record["message"] == "high-volume batching after reload"
                for record in delivered
            )
            if (failed_before_ids.issubset(before_ids) and
                after_count >= 100000 and sources == 0 and requests_count == 0):
                return (delivered, data_requests, before_count, after_count)
            return None

        delivered, data_requests, before_count, after_count = service.service.wait_for_condition(
            _spool_drained_after_reload,
            timeout=120,
            interval=0.5,
            description="pre- and post-reload high-volume spool drain",
        )
    finally:
        service.stop()
        os.unlink(config_path)

    delivered_ids = [record["id"] for record in delivered]
    assert before_count >= len(failed_before_ids)
    assert after_count >= 100000
    assert len(set(delivered_ids)) == len(delivered_ids)
    assert all(
        int(request["headers"]["Content-Length"]) <= 1048576
        for request in data_requests
    )

def test_out_azure_logs_ingestion_high_volume_batches_and_stops_cleanly():
    service = Service("out_azure_logs_ingestion_buffering_high_volume.yaml")
    started = time.monotonic()
    service.start()
    configure_http_response(status_code=204, body="")
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    def _all_records_received():
        data_requests = _data_requests(data_storage["requests"])
        delivered = sum(len(request["json"]) for request in data_requests)
        return data_requests if delivered >= 100000 else None

    try:
        data_requests = service.service.wait_for_condition(
            _all_records_received,
            timeout=120,
            interval=0.25,
            description="100000 high-volume Azure records",
        )
        database_path = os.path.join(service.buffer_dir, ".azure_logs_ingestion.db")

        def _spool_drained():
            with sqlite3.connect(database_path) as connection:
                sources = connection.execute(
                    "SELECT COUNT(*) FROM azli_sources WHERE instance_key='suite-high-volume'"
                ).fetchone()[0]
                requests_count = connection.execute(
                    "SELECT COUNT(*) FROM azli_requests "
                    "WHERE instance_key='suite-high-volume'"
                ).fetchone()[0]
                receipts = connection.execute(
                    "SELECT COUNT(*) FROM azli_receipts "
                    "WHERE instance_key='suite-high-volume'"
                ).fetchone()[0]
            return receipts if sources == 0 and requests_count == 0 and receipts > 0 else None

        receipt_count = service.service.wait_for_condition(
            _spool_drained,
            timeout=20,
            interval=0.25,
            description="drained high-volume durable spool",
        )
        with sqlite3.connect(database_path) as connection:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        instance_root = os.path.join(service.buffer_dir, "suite-high-volume")
        source_files = os.listdir(os.path.join(instance_root, "sources"))
        request_files = os.listdir(os.path.join(instance_root, "requests"))
        allocated_bytes = 0
        for root, _, files in os.walk(service.buffer_dir):
            for name in files:
                info = os.stat(os.path.join(root, name))
                allocated_bytes += getattr(info, "st_blocks", 0) * 512 or info.st_size
        log_path = service.service.flb.log_file
    finally:
        stop_started = time.monotonic()
        service.stop()
        stop_elapsed = time.monotonic() - stop_started

    elapsed = time.monotonic() - started
    payloads = [record for request in data_requests for record in request["json"]]
    compressed_sizes = [int(request["headers"]["Content-Length"]) for request in data_requests]
    ids = [record["id"] for record in payloads]
    with open(log_path, "r", encoding="utf-8", errors="replace") as handle:
        log_contents = handle.read()
    callback_events = [
        int(records)
        for records in re.findall(r"buffered callback records=(\d+)", log_contents)
    ]
    plan_events = [
        (int(records), int(probes))
        for records, probes in re.findall(
            r"planned durable request records=(\d+) probes=(\d+)",
            log_contents,
        )
    ]

    assert len(payloads) == 100000
    assert len(set(ids)) == 100000
    assert receipt_count > 0
    assert integrity == "ok"
    assert source_files == []
    assert request_files == []
    assert allocated_bytes < 128 * 1024 * 1024
    assert all(size <= 1048576 for size in compressed_sizes)
    assert any(size >= 900000 for size in compressed_sizes)
    assert sum(callback_events) == 100000
    assert sum(records for records, _ in plan_events) == 100000
    assert 0 < sum(probes for _, probes in plan_events) < 100
    assert elapsed < 120
    assert stop_elapsed < 10


def test_out_azure_logs_ingestion_enforces_shared_aggregate_quota():
    service = Service(
        "out_azure_logs_ingestion_buffering_shared_quota.yaml",
        initial_http_status=500,
    )
    service.start()
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )
    try:
        service.wait_for_log("batch buffer full", timeout=20)
        with sqlite3.connect(
            os.path.join(service.buffer_dir, ".azure_logs_ingestion.db")
        ) as connection:
            used = connection.execute(
                "SELECT COALESCE((SELECT SUM(bytes) FROM azli_sources),0) + "
                "COALESCE((SELECT SUM(bytes) FROM azli_requests),0)"
            ).fetchone()[0]
            instances = connection.execute(
                "SELECT COUNT(*) FROM azli_instances WHERE instance_key IN ('quota-a','quota-b')"
            ).fetchone()[0]
        allocated_bytes = 0
        for root, _, files in os.walk(service.buffer_dir):
            for name in files:
                info = os.stat(os.path.join(root, name))
                allocated_bytes += getattr(info, "st_blocks", 0) * 512 or info.st_size
        assert instances == 2
        assert 0 < used <= 1450000
        assert allocated_bytes <= 1450000
    finally:
        service.stop()


def test_out_azure_logs_ingestion_buffer_exhaustion_retries_after_space_frees():
    service = Service(
        "out_azure_logs_ingestion_buffering.yaml",
        # Immutable source, exact gzip artifact, SQLite WAL and headroom are charged.
        buffer_limit="1700000",
    )
    service.start()
    configure_http_response(status_code=500, body={"error": "blocked"})
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    rng = random.Random(13259)
    records = [
        {
            "id": str(index),
            "message": base64.b64encode(
                rng.randbytes(40000 if index == 0 else 150000)
            ).decode("ascii"),
        }
        for index in range(2)
    ]

    try:
        first = requests.post(
            f"http://127.0.0.1:{service.flb_listener_port}/",
            json=records[0],
            timeout=5,
        )
        assert first.status_code == 201
        service.wait_for_requests(2, timeout=15)
        second = requests.post(
            f"http://127.0.0.1:{service.flb_listener_port}/",
            json=records[1],
            timeout=5,
        )
        assert second.status_code == 201

        service.wait_for_log("batch buffer full", timeout=10)
        configure_http_response(status_code=204, body="")
        service.service.wait_for_condition(
            lambda: len(_data_requests(data_storage["requests"])) >= 2,
            timeout=20,
            interval=0.5,
            description="blocked durable request to drain",
        )
        after_free = requests.post(
            f"http://127.0.0.1:{service.flb_listener_port}/",
            json={"id": "after-free", "message": "space is available"},
            timeout=5,
        )
        assert after_free.status_code == 201

        def _after_free_record_delivered():
            requests_seen = list(data_storage["requests"])
            delivered = [
                item["id"]
                for request in _data_requests(requests_seen)
                for item in request["json"]
            ]
            return requests_seen if "after-free" in delivered else None

        requests_seen = service.service.wait_for_condition(
            _after_free_record_delivered,
            timeout=20,
            interval=0.5,
            description="new buffered record delivered after space is freed",
        )
    finally:
        service.stop()

    data_requests = _data_requests(requests_seen)
    delivered_batches = [[item["id"] for item in request["json"]] for request in data_requests]
    flattened = [item for batch in delivered_batches for item in batch]
    assert len(delivered_batches) >= 3
    assert all(batch == ["0"] for batch in delivered_batches[:2])
    assert "after-free" in flattened
