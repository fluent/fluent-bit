import base64
import hashlib
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
LIFECYCLE_METRIC_PREFIX = "fluentbit_azure_logs_ingestion_"
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
        second_buffer_key="quota-b",
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
                "AZURE_LOGS_INGESTION_SECOND_BUFFER_KEY": second_buffer_key,
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

    def wait_for_log(self, text, timeout=10, count=1):
        def _contains_text():
            log_file = self.service.flb.log_file
            if not log_file or not os.path.exists(log_file):
                return None
            with open(log_file, "r", encoding="utf-8", errors="replace") as handle:
                contents = handle.read()
            return contents if contents.count(text) >= count else None

        return self.service.wait_for_condition(
            _contains_text,
            timeout=timeout,
            interval=0.5,
            description=f"Fluent Bit log containing {count} occurrence(s) of {text!r}",
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


@pytest.mark.parametrize("retry_setting", ["", "      retry_limit: 2\n"])
def test_out_azure_logs_ingestion_requires_unlimited_engine_retries(retry_setting):
    config_path = _config_replacing("      retry_limit: no_limits\n", retry_setting)
    service = Service(config_path)
    try:
        with pytest.raises(FluentBitStartupError):
            service.start()
    finally:
        service.stop()
        os.unlink(config_path)


def test_out_azure_logs_ingestion_rejects_legacy_record_range_schema():
    with tempfile.TemporaryDirectory(prefix="azure-li-legacy-schema-") as buffer_dir:
        database_path = os.path.join(buffer_dir, ".azure_logs_ingestion.db")
        with sqlite3.connect(database_path) as connection:
            connection.execute(
                "CREATE TABLE azli_sources("
                "source_pk INTEGER PRIMARY KEY,next_record INTEGER NOT NULL)"
            )
            connection.execute(
                "INSERT INTO azli_sources(source_pk,next_record) VALUES(1,4)"
            )
            connection.commit()

        service = Service(
            "out_azure_logs_ingestion_buffering.yaml",
            buffer_dir=buffer_dir,
        )
        try:
            with pytest.raises(FluentBitStartupError):
                service.start()
        finally:
            service.stop()

        with sqlite3.connect(database_path) as connection:
            assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
            assert connection.execute(
                "SELECT source_pk,next_record FROM azli_sources"
            ).fetchall() == [(1, 4)]


def test_out_azure_logs_ingestion_rejects_fstore_spool_schema():
    with tempfile.TemporaryDirectory(prefix="azure-li-fstore-schema-") as buffer_dir:
        database_path = os.path.join(buffer_dir, ".azure_logs_ingestion.db")
        with sqlite3.connect(database_path) as connection:
            connection.execute("PRAGMA user_version=2")

        service = Service(
            "out_azure_logs_ingestion_buffering.yaml",
            buffer_dir=buffer_dir,
        )
        try:
            with pytest.raises(FluentBitStartupError):
                service.start()
        finally:
            service.stop()

        with sqlite3.connect(database_path) as connection:
            assert connection.execute("PRAGMA user_version").fetchone()[0] == 2


@pytest.mark.parametrize(
    ("column", "value"),
    (("state", 6), ("record_count", 0)),
)
def test_out_azure_logs_ingestion_rejects_invalid_spool_state(column, value):
    with tempfile.TemporaryDirectory(prefix="azure-li-invalid-state-") as buffer_dir:
        slow_config = _config_replacing(
            "      batch_timeout: 5s", "      batch_timeout: 60s"
        )
        first = Service(slow_config, buffer_dir=buffer_dir)
        first.start()
        try:
            _post_chunk(first, [{"id": "invalid", "message": "durable source"}])
            first.wait_for_log("buffered whole chunk records=1", timeout=10)
        finally:
            first.stop()
            os.unlink(slow_config)

        database_path = os.path.join(buffer_dir, ".azure_logs_ingestion.db")
        with sqlite3.connect(database_path) as connection:
            connection.execute("PRAGMA ignore_check_constraints=ON")
            connection.execute(
                f"UPDATE azli_sources SET {column}=? "
                "WHERE instance_key='suite-buffer'",
                (value,),
            )
            connection.commit()

        second = Service(
            "out_azure_logs_ingestion_buffering.yaml",
            buffer_dir=buffer_dir,
            receiver_port=first.test_suite_http_port,
        )
        try:
            with pytest.raises(FluentBitStartupError):
                second.start()
        finally:
            second.stop()

        with sqlite3.connect(database_path) as connection:
            assert connection.execute(
                f"SELECT {column} FROM azli_sources "
                "WHERE instance_key='suite-buffer'"
            ).fetchone()[0] == value


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


def test_out_azure_logs_ingestion_rejects_duplicate_live_buffer_key():
    service = Service(
        "out_azure_logs_ingestion_buffering_shared_quota.yaml",
        second_buffer_key="quota-a",
    )
    try:
        with pytest.raises(FluentBitStartupError):
            service.start()
    finally:
        service.stop()


def test_out_azure_logs_ingestion_rejects_buffer_key_reuse_for_another_dcr():
    with tempfile.TemporaryDirectory(prefix="azure-li-destination-guard-") as buffer_dir:
        first = Service(
            "out_azure_logs_ingestion_buffering.yaml",
            buffer_dir=buffer_dir,
        )
        first.start()
        receiver_port = first.test_suite_http_port
        first.stop()

        config_path = _hot_reload_config()
        with open(config_path, encoding="utf-8") as handle:
            config = handle.read()
        config = config.replace("dcr_id: dcr-suite", "dcr_id: dcr-other", 1)
        with open(config_path, "w", encoding="utf-8") as handle:
            handle.write(config)

        second = Service(
            config_path,
            buffer_dir=buffer_dir,
            receiver_port=receiver_port,
        )
        try:
            with pytest.raises(FluentBitStartupError):
                second.start()
        finally:
            second.stop()
            os.unlink(config_path)


def _config_replacing(old, new):
    config_path = _hot_reload_config()
    with open(config_path, encoding="utf-8") as handle:
        config = handle.read()
    assert old in config
    with open(config_path, "w", encoding="utf-8") as handle:
        handle.write(config.replace(old, new))
    return config_path


def _config_replacing_in_file(config_path, old, new):
    with open(config_path, encoding="utf-8") as handle:
        config = handle.read()
    assert old in config
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as handle:
        handle.write(config.replace(old, new))
        return handle.name


def _post_chunk(service, records):
    response = requests.post(
        f"http://127.0.0.1:{service.flb_listener_port}/",
        json=records,
        timeout=10,
    )
    assert response.status_code == 201


def _spool_is_empty(buffer_dir, buffer_key):
    database = os.path.join(buffer_dir, ".azure_logs_ingestion.db")
    with sqlite3.connect(database) as connection:
        sources = connection.execute(
            "SELECT COUNT(*) FROM azli_sources WHERE instance_key=?",
            (buffer_key,),
        ).fetchone()[0]
        requests_count = connection.execute(
            "SELECT COUNT(*) FROM azli_requests WHERE instance_key=?",
            (buffer_key,),
        ).fetchone()[0]
    return sources == 0 and requests_count == 0


def _assert_empty_artifact_directories(buffer_dir, buffer_key):
    assert not os.path.exists(os.path.join(buffer_dir, buffer_key))


def test_out_azure_logs_ingestion_batches_multiple_engine_flushes():
    service = Service("out_azure_logs_ingestion_buffering.yaml")
    service.start()
    configure_http_response(status_code=204, body="")
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    rng = random.Random(13254)
    chunks = [
        [
            {
                "id": f"{chunk_index}-{record_index}",
                "message": base64.b64encode(rng.randbytes(1000)).decode("ascii"),
            }
            for record_index in range(2)
        ]
        for chunk_index in range(2)
    ]
    try:
        _post_chunk(service, chunks[0])
        first_log = service.wait_for_log("buffered whole chunk records=2", timeout=10)
        first_gzip_size = int(
            re.findall(r"buffered whole chunk records=2 .*gzip_bytes=(\d+)", first_log)[-1]
        )
        assert first_gzip_size < 3000
        assert _data_requests(data_storage["requests"]) == []

        second_started = time.monotonic()
        _post_chunk(service, chunks[1])
        requests_seen = service.wait_for_requests(2, timeout=10)
        assert time.monotonic() - second_started < 5
        service.wait_for_log("planned durable request chunks=2 records=4", timeout=10)
    finally:
        service.stop()

    data_requests = [
        item for item in requests_seen
        if item["path"] == "/dataCollectionRules/dcr-suite/streams/Custom-suite_CL"
    ]
    assert len(data_requests) == 1
    request = data_requests[0]
    assert request["headers"].get("Content-Encoding") == "gzip"
    assert 3000 <= int(request["headers"]["Content-Length"]) <= 5000
    assert [item["id"] for item in request["json"]] == [
        item["id"] for chunk in chunks for item in chunk
    ]
    assert len(request["json"]) == 4


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


def test_out_azure_logs_ingestion_rolls_over_at_whole_chunk_boundaries():
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

    rng = random.Random(13257)
    chunks = [
        [
            {
                "id": f"{chunk_index}-{record_index}",
                "message": base64.b64encode(rng.randbytes(350000)).decode("ascii"),
            }
            for record_index in range(2)
        ]
        for chunk_index in range(3)
    ]
    try:
        for chunk_index, chunk in enumerate(chunks):
            _post_chunk(service, chunk)
            service.wait_for_log(
                "buffered whole chunk records=2",
                timeout=10,
                count=chunk_index + 1,
            )
        requests_seen = service.wait_for_requests(4, timeout=35)
    finally:
        service.stop()

    data_requests = _data_requests(requests_seen)
    assert len(data_requests) == 3
    assert all(int(item["headers"]["Content-Length"]) <= 1048576 for item in data_requests)
    expected_ids = [[record["id"] for record in chunk] for chunk in chunks]
    delivered_ids = [[record["id"] for record in request["json"]]
                     for request in data_requests]
    assert delivered_ids == expected_ids


def test_out_azure_logs_ingestion_timeout_flushes_underfilled_file():
    service = Service("out_azure_logs_ingestion_buffering.yaml")
    service.start()
    configure_http_response(status_code=204, body="")
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    chunks = [
        [{"id": "timeout-0", "message": "first underfilled chunk"}],
        [{"id": "timeout-1", "message": "second underfilled chunk"}],
    ]
    try:
        _post_chunk(service, chunks[0])
        service.wait_for_log("buffered whole chunk records=1", timeout=10)
        assert _data_requests(data_storage["requests"]) == []
        time.sleep(2.5)

        second_started = time.monotonic()
        _post_chunk(service, chunks[1])
        service.wait_for_log("buffered whole chunk records=1", timeout=10, count=2)
        requests_seen = service.wait_for_requests(2, timeout=10)
        assert time.monotonic() - second_started < 4.5
    finally:
        service.stop()

    data_requests = _data_requests(requests_seen)
    assert len(data_requests) == 1
    assert int(data_requests[0]["headers"]["Content-Length"]) < 3000
    assert [record["id"] for record in data_requests[0]["json"]] == [
        record["id"] for chunk in chunks for record in chunk
    ]


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
            f'{LIFECYCLE_METRIC_PREFIX}delivered_records_total'
            f'{{name="azure_logs_ingestion.0",dcr_id="dcr-suite"}} 2'
        )
    finally:
        service.stop()

    data_requests = _data_requests(requests_seen)
    assert len(data_requests) == 2
    assert data_requests[0]["decoded_data"] == data_requests[1]["decoded_data"]
    assert data_requests[0]["raw_sha256"] == data_requests[1]["raw_sha256"]
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
    admitted_chunks = _metric_value(
        metrics, f"{LIFECYCLE_METRIC_PREFIX}admitted_chunks_total", **metric_labels
    )
    delivered_chunks = _metric_value(
        metrics, f"{LIFECYCLE_METRIC_PREFIX}delivered_chunks_total", **metric_labels
    )
    admitted_bytes = _metric_value(
        metrics, f"{LIFECYCLE_METRIC_PREFIX}admitted_bytes_total", **metric_labels
    )
    assert admitted_chunks > 0
    assert delivered_chunks == admitted_chunks
    assert _metric_value(
        metrics, f"{LIFECYCLE_METRIC_PREFIX}admitted_records_total", **metric_labels
    ) == 2
    assert _metric_value(
        metrics, f"{LIFECYCLE_METRIC_PREFIX}delivered_records_total", **metric_labels
    ) == 2
    assert _metric_value(
        metrics, f"{LIFECYCLE_METRIC_PREFIX}delivered_bytes_total", **metric_labels
    ) == admitted_bytes
    assert _metric_value(
        metrics, f"{LIFECYCLE_METRIC_PREFIX}queued_chunks", **metric_labels
    ) == 0
    assert _metric_value(
        metrics, f"{LIFECYCLE_METRIC_PREFIX}quota_limit_bytes", **metric_labels
    ) > 0
    assert _metric_value(
        metrics, f"{LIFECYCLE_METRIC_PREFIX}uploader_up", **metric_labels
    ) == 1
    assert _metric_value(
        metrics,
        f"{LIFECYCLE_METRIC_PREFIX}uploader_last_success_timestamp_seconds",
        **metric_labels,
    ) > 0


def test_out_azure_logs_ingestion_reports_admission_persistence_failure():
    service = Service("out_azure_logs_ingestion_buffering.yaml")
    service.start()
    configure_http_response(status_code=204, body="")
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    database = os.path.join(service.buffer_dir, ".azure_logs_ingestion.db")
    locker = sqlite3.connect(database, timeout=0, isolation_level=None)
    persistence_metric = f"{LIFECYCLE_METRIC_PREFIX}persistence_failures_total"
    recovery_metric = f"{LIFECYCLE_METRIC_PREFIX}degraded_recoveries_total"
    metric_labels = {"name": "azure_logs_ingestion.0", "dcr_id": "dcr-suite"}
    metrics_url = (
        f"http://127.0.0.1:{service.flb.http_monitoring_port}"
        "/api/v2/metrics/prometheus"
    )

    try:
        locker.execute("BEGIN IMMEDIATE")
        _post_chunk(service, [{"id": "locked", "message": "retry after sqlite lock"}])

        def _persistence_failure_observed():
            response = requests.get(metrics_url, timeout=2)
            value = _metric_value(response.text, persistence_metric, **metric_labels)
            return response.text if value is not None and value >= 1 else None

        metrics = service.service.wait_for_condition(
            _persistence_failure_observed,
            timeout=10,
            interval=0.05,
            description="admission persistence failure metric",
        )
        assert _metric_value(metrics, persistence_metric, **metric_labels) == 1
        assert _data_requests(data_storage["requests"]) == []
        assert locker.execute(
            "SELECT COUNT(*) FROM azli_sources WHERE instance_key='suite-buffer'"
        ).fetchone()[0] == 0

        locker.execute("ROLLBACK")
        locker.close()
        locker = None
        requests_seen = service.wait_for_requests(2, timeout=30)
        metrics = service.metrics(persistence_metric, timeout=10)
    finally:
        if locker is not None:
            try:
                locker.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            locker.close()
        service.stop()

    data_requests = _data_requests(requests_seen)
    assert len(data_requests) == 1
    assert [record["id"] for record in data_requests[0]["json"]] == ["locked"]
    assert _metric_value(metrics, persistence_metric, **metric_labels) == 1
    assert _metric_value(metrics, recovery_metric, **metric_labels) in (None, 0)


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


def _create_retry_spool(buffer_dir, seed):
    service = Service("out_azure_logs_ingestion_buffering.yaml", buffer_dir=buffer_dir)
    service.start()
    configure_http_response(status_code=500, body={"error": "retry"})
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )
    try:
        _send_buffering_records(service, 2, seed)
        service.wait_for_requests(2, timeout=15)
        return service.test_suite_http_port
    finally:
        service.stop()


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
            second.wait_for_log("quarantining corrupt request", timeout=10)
            with sqlite3.connect(database_path) as connection:
                state = connection.execute(
                    "SELECT state,reason FROM azli_requests "
                    "WHERE instance_key='suite-buffer'"
                ).fetchone()
            assert state == (5, "artifact_corrupt")
            assert _data_requests(data_storage["requests"]) == []
        finally:
            second.stop()


def test_out_azure_logs_ingestion_quarantines_corrupt_attached_source_before_replay():
    with tempfile.TemporaryDirectory(prefix="azure-li-corrupt-member-") as buffer_dir:
        receiver_port = _create_retry_spool(buffer_dir, 93256)
        database_path = os.path.join(buffer_dir, ".azure_logs_ingestion.db")
        replacement = b'[{"id":"valid-but-not-requested"}]'
        replacement_digest = hashlib.sha256(replacement).digest()
        with sqlite3.connect(database_path) as connection:
            assert connection.execute(
                "SELECT COUNT(*) FROM azli_sources WHERE request_pk IS NOT NULL"
            ).fetchone()[0] > 0
            connection.execute(
                "UPDATE azli_sources SET content=?,digest=?,json_bytes=? "
                "WHERE instance_key='suite-buffer' AND request_pk IS NOT NULL",
                (replacement, replacement_digest, len(replacement)),
            )
            connection.commit()

        second = Service(
            "out_azure_logs_ingestion_buffering.yaml",
            buffer_dir=buffer_dir,
            receiver_port=receiver_port,
        )
        second.start()
        try:
            second.wait_for_log("mismatched source membership", timeout=10)
            with sqlite3.connect(database_path) as connection:
                request_state = connection.execute(
                    "SELECT state,reason FROM azli_requests "
                    "WHERE instance_key='suite-buffer'"
                ).fetchone()
                source_states = connection.execute(
                    "SELECT DISTINCT state FROM azli_sources "
                    "WHERE instance_key='suite-buffer'"
                ).fetchall()
            assert request_state == (5, "source_membership_mismatch")
            assert source_states == [(3,)]
            assert _data_requests(data_storage["requests"]) == []
        finally:
            second.stop()


def test_out_azure_logs_ingestion_rejects_conflicting_active_receipt():
    with tempfile.TemporaryDirectory(prefix="azure-li-receipt-conflict-") as buffer_dir:
        receiver_port = _create_retry_spool(buffer_dir, 103256)
        database_path = os.path.join(buffer_dir, ".azure_logs_ingestion.db")
        with sqlite3.connect(database_path) as connection:
            connection.execute(
                "INSERT INTO azli_receipts(instance_key,source_id,digest,completed,"
                "expires,bytes) SELECT instance_key,source_id,zeroblob(32),"
                "strftime('%s','now'),strftime('%s','now')+86400,256 "
                "FROM azli_sources WHERE instance_key='suite-buffer' LIMIT 1"
            )
            connection.commit()

        second = Service(
            "out_azure_logs_ingestion_buffering.yaml",
            buffer_dir=buffer_dir,
            receiver_port=receiver_port,
        )
        try:
            with pytest.raises(FluentBitStartupError):
                second.start()
        finally:
            second.stop()

        with sqlite3.connect(database_path) as connection:
            assert connection.execute(
                "SELECT COUNT(*) FROM azli_receipts "
                "WHERE instance_key='suite-buffer' AND digest=zeroblob(32)"
            ).fetchone()[0] == 1


def test_out_azure_logs_ingestion_repairs_missing_acked_receipt_before_cleanup():
    with tempfile.TemporaryDirectory(prefix="azure-li-acked-receipt-") as buffer_dir:
        receiver_port = _create_retry_spool(buffer_dir, 113256)
        database_path = os.path.join(buffer_dir, ".azure_logs_ingestion.db")
        with sqlite3.connect(database_path) as connection:
            connection.execute(
                "UPDATE azli_sources SET state=2 WHERE instance_key='suite-buffer'"
            )
            connection.execute(
                "UPDATE azli_requests SET state=4 WHERE instance_key='suite-buffer'"
            )
            connection.execute(
                "DELETE FROM azli_receipts WHERE instance_key='suite-buffer'"
            )
            connection.commit()

        second = Service(
            "out_azure_logs_ingestion_buffering.yaml",
            buffer_dir=buffer_dir,
            receiver_port=receiver_port,
        )
        second.start()
        try:
            second.service.wait_for_condition(
                lambda: _spool_is_empty(buffer_dir, "suite-buffer"),
                timeout=10,
                interval=0.25,
                description="ACKED cleanup after receipt repair",
            )
        finally:
            second.stop()

        with sqlite3.connect(database_path) as connection:
            receipt = connection.execute(
                "SELECT length(digest),expires>completed,bytes "
                "FROM azli_receipts WHERE instance_key='suite-buffer'"
            ).fetchone()
        assert receipt == (32, 1, 256)
        assert _data_requests(data_storage["requests"]) == []


def test_out_azure_logs_ingestion_quarantines_corrupt_source_and_continues():
    with tempfile.TemporaryDirectory(prefix="azure-li-corrupt-source-") as buffer_dir:
        slow_config = _config_replacing("      batch_timeout: 5s", "      batch_timeout: 60s")
        first = Service(slow_config, buffer_dir=buffer_dir)
        first.start()
        configure_http_response(status_code=204, body="")
        configure_oauth_token_response(
            status_code=200,
            body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
        )
        try:
            _post_chunk(first, [{"id": "corrupt", "message": "preserve forensic payload"}])
            first.wait_for_log("buffered whole chunk records=1", timeout=10)
        finally:
            first.stop()
            os.unlink(slow_config)

        database_path = os.path.join(buffer_dir, ".azure_logs_ingestion.db")
        with sqlite3.connect(database_path) as connection:
            assert connection.execute(
                "SELECT COUNT(*) FROM azli_requests WHERE instance_key='suite-buffer'"
            ).fetchone()[0] == 0
            connection.execute(
                "UPDATE azli_sources SET content=zeroblob(length(content)) "
                "WHERE instance_key='suite-buffer'"
            )
            connection.commit()

        fast_config = _config_replacing(
            "      batch_target_size: 3000", "      batch_target_size: 100"
        )
        second = Service(
            fast_config,
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
            second.wait_for_log("quarantining corrupt source", timeout=10)
            _post_chunk(second, [{"id": "healthy", "message": "continues"}])
            requests_seen = second.wait_for_requests(2, timeout=15)
            with sqlite3.connect(database_path) as connection:
                quarantined = connection.execute(
                    "SELECT state,quarantine_reason FROM azli_sources "
                    "WHERE instance_key='suite-buffer' AND quarantine_reason IS NOT NULL"
                ).fetchall()
                assert quarantined == [(3, "content_corrupt")]
                assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        finally:
            second.stop()
            os.unlink(fast_config)

    assert [record["id"] for request in _data_requests(requests_seen)
            for record in request["json"]] == ["healthy"]


def test_out_azure_logs_ingestion_expires_receipts_and_reclaims_wal():
    config_path = _config_replacing(
        "      batch_timeout: 5s",
        "      batch_timeout: 5s\n      buffer_receipt_ttl: 3s",
    )
    metric_name = f"{LIFECYCLE_METRIC_PREFIX}uploader_last_success_timestamp_seconds"
    metric_labels = {"name": "azure_logs_ingestion.0", "dcr_id": "dcr-suite"}

    with tempfile.TemporaryDirectory(prefix="azure-li-receipt-expiry-") as buffer_dir:
        service = Service(config_path, buffer_dir=buffer_dir)
        service.start()
        configure_http_response(status_code=204, body="")
        configure_oauth_token_response(
            status_code=200,
            body={
                "access_token": "oauth-access-token",
                "token_type": "Bearer",
                "expires_in": 300,
            },
        )
        database_path = os.path.join(buffer_dir, ".azure_logs_ingestion.db")
        receiver_port = service.test_suite_http_port
        try:
            _post_chunk(service, [{"id": "receipt", "message": "expire me"}])
            service.wait_for_requests(2, timeout=15)

            def receipt_count(expected):
                with sqlite3.connect(database_path) as connection:
                    count = connection.execute(
                        "SELECT COUNT(*) FROM azli_receipts "
                        "WHERE instance_key='suite-buffer'"
                    ).fetchone()[0]
                return count == expected

            service.service.wait_for_condition(
                lambda: receipt_count(1), timeout=5, interval=0.2,
                description="durable completion receipt",
            )
            service.service.wait_for_condition(
                lambda: receipt_count(0), timeout=10, interval=0.5,
                description="runtime receipt expiry",
            )
            with sqlite3.connect(database_path) as connection:
                assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
                last_success = connection.execute(
                    "SELECT last_success FROM azli_instances "
                    "WHERE instance_key='suite-buffer'"
                ).fetchone()[0]
            assert last_success > 0
            metrics = service.metrics(metric_name)
            assert _metric_value(metrics, metric_name, **metric_labels) == last_success

            wal_path = f"{database_path}-wal"
            wal_size = os.path.getsize(wal_path) if os.path.exists(wal_path) else 0
            assert wal_size < 4 * 1024 * 1024
            _post_chunk(service, [{"id": "after-maintenance", "message": "still live"}])
            requests_seen = service.service.wait_for_condition(
                lambda: list(data_storage["requests"])
                if any(record.get("id") == "after-maintenance"
                       for request in _data_requests(data_storage["requests"])
                       for record in request["json"]) else None,
                timeout=15, interval=0.5,
                description="delivery after receipt and WAL maintenance",
            )
            with sqlite3.connect(database_path) as connection:
                latest_success = connection.execute(
                    "SELECT last_success FROM azli_instances "
                    "WHERE instance_key='suite-buffer'"
                ).fetchone()[0]
            assert latest_success >= last_success
            last_success = latest_success
        finally:
            service.stop()

        assert any(record["id"] == "after-maintenance"
                   for request in _data_requests(requests_seen)
                   for record in request["json"])

        restarted = Service(
            config_path,
            buffer_dir=buffer_dir,
            receiver_port=receiver_port,
        )
        try:
            restarted.start()
            metrics = restarted.metrics(metric_name)
            assert _metric_value(metrics, metric_name, **metric_labels) == last_success
        finally:
            restarted.stop()

    os.unlink(config_path)


def test_out_azure_logs_ingestion_expires_receipts_for_all_shared_instances():
    config_path = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            "../config/out_azure_logs_ingestion_buffering_shared_quota.yaml",
        )
    )
    with open(config_path, encoding="utf-8") as handle:
        config = handle.read()
    config = config.replace(
        "      upload_retry_base: 1\n",
        "      upload_retry_base: 1\n      buffer_receipt_ttl: 30s\n",
    )
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as handle:
        handle.write(config)
        temporary_config = handle.name

    service = Service(temporary_config, buffer_limit="4M")
    service.start()
    configure_http_response(status_code=204, body="")
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )
    database_path = os.path.join(service.buffer_dir, ".azure_logs_ingestion.db")
    try:
        service.wait_for_requests(3, timeout=20)

        def receipt_counts():
            with sqlite3.connect(database_path) as connection:
                return dict(
                    connection.execute(
                        "SELECT instance_key,COUNT(*) FROM azli_receipts "
                        "GROUP BY instance_key"
                    ).fetchall()
                )

        service.service.wait_for_condition(
            lambda: receipt_counts()
            if receipt_counts().get("quota-a", 0) > 0 and
               receipt_counts().get("quota-b", 0) > 0 else None,
            timeout=10,
            interval=0.25,
            description="receipts for both shared instances",
        )
        service.service.wait_for_condition(
            lambda: True if receipt_counts() == {} else None,
            timeout=45,
            interval=0.5,
            description="root-wide receipt expiry",
        )
    finally:
        service.stop()
        os.unlink(temporary_config)


@pytest.mark.parametrize(
    ("status_code", "reason"),
    [(400, "permanent"), (413, "http_413")],
)
def test_out_azure_logs_ingestion_quarantines_permanent_response_without_replay(
    status_code, reason
):
    service = Service("out_azure_logs_ingestion_buffering.yaml")
    service.start()
    configure_http_response(status_code=status_code, body={"error": "permanent"})
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
        with sqlite3.connect(
            os.path.join(service.buffer_dir, ".azure_logs_ingestion.db")
        ) as connection:
            state = connection.execute(
                "SELECT state,reason FROM azli_requests "
                "WHERE instance_key='suite-buffer'"
            ).fetchone()
        assert state == (5, reason)
        metrics = service.metrics(
            f'{LIFECYCLE_METRIC_PREFIX}quarantined_records_total'
            f'{{name="azure_logs_ingestion.0",dcr_id="dcr-suite"}} 2'
        )
    finally:
        service.stop()

    metric_labels = {"name": "azure_logs_ingestion.0", "dcr_id": "dcr-suite"}
    assert len(_data_requests(requests_seen)) == 1
    assert _metric_value(
        metrics, f"{LIFECYCLE_METRIC_PREFIX}quarantined_chunks_total", **metric_labels
    ) > 0
    assert _metric_value(
        metrics, f"{LIFECYCLE_METRIC_PREFIX}quarantined_records_total", **metric_labels
    ) == 2
    assert _metric_value(
        metrics, f"{LIFECYCLE_METRIC_PREFIX}quarantined_chunks", **metric_labels
    ) > 0
    assert _metric_value(
        metrics, f"{LIFECYCLE_METRIC_PREFIX}quarantined_bytes", **metric_labels
    ) > 0


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
            first.wait_for_log("buffered whole chunk records=1", timeout=10)
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
        service.wait_for_log("buffered whole chunk records=1", timeout=10)

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


def test_out_azure_logs_ingestion_buffered_oauth_timeout_bounds_shutdown():
    service = Service("out_azure_logs_ingestion_buffering_short_timeout.yaml")
    service.start()
    configure_http_response(status_code=204, body="")
    configure_oauth_token_response(hang_before_response=True)

    stopped = False
    try:
        response = requests.post(
            f"http://127.0.0.1:{service.flb_listener_port}/",
            json={"id": "oauth-timeout", "message": "durably queued"},
            timeout=5,
        )
        assert response.status_code == 201
        service.wait_for_requests(1, timeout=15)
        service.wait_for_log("response timeout reached", timeout=15)

        database = os.path.join(service.buffer_dir, ".azure_logs_ingestion.db")

        def _request_is_retryable():
            with sqlite3.connect(database) as connection:
                state = connection.execute(
                    "SELECT state FROM azli_requests "
                    "WHERE instance_key='suite-buffer'"
                ).fetchone()
            return state == (3,)

        service.service.wait_for_condition(
            _request_is_retryable,
            timeout=5,
            interval=0.25,
            description="durable request to remain retryable after OAuth timeout",
        )
        assert _data_requests(data_storage["requests"]) == []

        started = time.monotonic()
        service.stop()
        stopped = True
        assert time.monotonic() - started < 8
    finally:
        configure_oauth_token_response(hang_before_response=False)
        if not stopped:
            service.stop()


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


def test_out_azure_logs_ingestion_retries_uncompressed_oversized_chunk():
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
        log_contents = service.wait_for_log(
            "exceeds uncompressed request limit", timeout=20, count=2
        )
        source_ids = re.findall(
            r"uncompressed request limit id=([^ ]+)", log_contents
        )
        assert len(source_ids) >= 2
        assert len(set(source_ids)) == 1
        assert _data_requests(data_storage["requests"]) == []
        with sqlite3.connect(
            os.path.join(service.buffer_dir, ".azure_logs_ingestion.db")
        ) as connection:
            assert connection.execute(
                "SELECT COUNT(*) FROM azli_sources WHERE instance_key='suite-buffer'"
            ).fetchone()[0] == 0
            assert connection.execute(
                "SELECT COUNT(*) FROM azli_requests WHERE instance_key='suite-buffer'"
            ).fetchone()[0] == 0
        assert _quarantine_count(service.buffer_dir) == 0
        _assert_empty_artifact_directories(service.buffer_dir, "suite-buffer")
    finally:
        service.stop()


def test_out_azure_logs_ingestion_retries_compressed_oversized_chunk():
    service = Service(
        "out_azure_logs_ingestion_buffering_default_sizes.yaml",
        buffer_key="suite-default-sizes",
    )
    service.start()
    configure_http_response(status_code=204, body="")
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    rng = random.Random(13261)
    try:
        response = requests.post(
            f"http://127.0.0.1:{service.flb_listener_port}/",
            json={
                "id": "large-incompressible",
                "message": base64.b64encode(rng.randbytes(1100000)).decode("ascii"),
            },
            timeout=10,
        )
        assert response.status_code == 201
        log_contents = service.wait_for_log(
            "exceeds compressed request limit", timeout=25, count=2
        )
        source_ids = re.findall(r"compressed request limit id=([^ ]+)", log_contents)
        assert len(source_ids) >= 2
        assert len(set(source_ids)) == 1
        assert _data_requests(data_storage["requests"]) == []
        with sqlite3.connect(
            os.path.join(service.buffer_dir, ".azure_logs_ingestion.db")
        ) as connection:
            assert connection.execute(
                "SELECT COUNT(*) FROM azli_sources WHERE instance_key='suite-default-sizes'"
            ).fetchone()[0] == 0
            assert connection.execute(
                "SELECT COUNT(*) FROM azli_requests WHERE instance_key='suite-default-sizes'"
            ).fetchone()[0] == 0
        assert _quarantine_count(service.buffer_dir, "suite-default-sizes") == 0
        _assert_empty_artifact_directories(
            service.buffer_dir, "suite-default-sizes"
        )
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

    peak_sizes = {"database": 0, "wal": 0}

    def _all_records_received():
        database_path = os.path.join(service.buffer_dir, ".azure_logs_ingestion.db")
        wal_path = f"{database_path}-wal"
        peak_sizes["database"] = max(
            peak_sizes["database"],
            os.path.getsize(database_path) if os.path.exists(database_path) else 0,
        )
        peak_sizes["wal"] = max(
            peak_sizes["wal"],
            os.path.getsize(wal_path) if os.path.exists(wal_path) else 0,
        )
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
        final_database_size = os.path.getsize(database_path)
        wal_path = f"{database_path}-wal"
        final_wal_size = os.path.getsize(wal_path) if os.path.exists(wal_path) else 0
        instance_root = os.path.join(service.buffer_dir, "suite-high-volume")
        instance_artifacts_exist = os.path.exists(instance_root)
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
        for records in re.findall(r"buffered whole chunk records=(\d+)", log_contents)
    ]
    plan_events = [
        (int(chunks), int(records))
        for chunks, records in re.findall(
            r"planned durable request chunks=(\d+) records=(\d+)",
            log_contents,
        )
    ]
    probe_events = [
        (int(probes), int(limit))
        for probes, limit in re.findall(
            r"whole-chunk planner probes=(\d+) limit=(\d+)", log_contents
        )
    ]
    snapshot_events = [
        (int(size), int(limit), int(sources))
        for size, limit, sources in re.findall(
            r"whole-chunk planner snapshot_bytes=(\d+) limit=(\d+) sources=(\d+)",
            log_contents,
        )
    ]
    upload_events = [
        (int(uploads), int(limit))
        for uploads, limit in re.findall(
            r"batch timer uploads=(\d+) limit=(\d+)", log_contents
        )
    ]

    assert len(payloads) == 100000
    assert len(set(ids)) == 100000
    assert receipt_count > 0
    assert integrity == "ok"
    assert not instance_artifacts_exist
    assert allocated_bytes < 128 * 1024 * 1024
    assert all(size <= 1048576 for size in compressed_sizes)
    assert sum(callback_events) == 100000
    assert sum(records for _, records in plan_events) == 100000
    assert all(0 < chunks <= 8 for chunks, _ in plan_events)
    assert len(probe_events) == len(plan_events)
    assert all(0 < probes <= limit == 8 for probes, limit in probe_events)
    assert snapshot_events
    assert all(2 <= size <= limit == 16_000_000
               for size, limit, _ in snapshot_events)
    assert all(0 < sources <= 8 for _, _, sources in snapshot_events)
    assert upload_events
    assert all(0 < uploads <= limit == 4 for uploads, limit in upload_events)
    assert any(uploads > 1 for uploads, _ in upload_events)
    logger.info(
        "SQLite batching benchmark records=%d elapsed=%.3fs records_per_second=%.1f "
        "peak_db=%d peak_wal=%d final_db=%d final_wal=%d",
        len(payloads), elapsed, len(payloads) / elapsed,
        peak_sizes["database"], peak_sizes["wal"],
        final_database_size, final_wal_size,
    )
    assert elapsed < 120
    assert stop_elapsed < 10


def test_out_azure_logs_ingestion_accounts_database_reservations():
    config_path = _config_replacing(
        "      batch_target_size: 3000",
        "      batch_target_size: 1048576",
    )
    config_path_with_timeout = _config_replacing_in_file(
        config_path,
        "      batch_timeout: 5s",
        "      batch_timeout: 60s",
    )
    service = Service(
        config_path_with_timeout,
        buffer_limit="1300000",
        initial_http_status=500,
    )
    service.start()
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )
    rng = random.Random(213259)
    try:
        admitted = 0
        for index in range(15):
            _post_chunk(
                service,
                [{
                    "id": f"account-{index}",
                    "message": base64.b64encode(rng.randbytes(16000)).decode("ascii"),
                }],
            )
            try:
                service.wait_for_log(
                    "buffered whole chunk records=1",
                    timeout=3,
                    count=admitted + 1,
                )
                admitted += 1
            except TimeoutError:
                break
        log_contents = service.wait_for_log("batch buffer full", timeout=10)
        logical_values = re.findall(r"batch buffer full logical=(\d+)", log_contents)
        assert logical_values
        database_path = os.path.join(service.buffer_dir, ".azure_logs_ingestion.db")
        with sqlite3.connect(database_path) as connection:
            sql_logical = connection.execute(
                "SELECT COALESCE((SELECT SUM(bytes) FROM azli_sources),0) + "
                "COALESCE((SELECT SUM(bytes) FROM azli_requests),0) + "
                "COALESCE((SELECT SUM(bytes) FROM azli_receipts),0)"
            ).fetchone()[0]
            source_count = connection.execute(
                "SELECT COUNT(*) FROM azli_sources"
            ).fetchone()[0]
        assert admitted >= 5
        assert source_count == admitted
        assert int(logical_values[-1]) == sql_logical
        assert sql_logical > source_count * (4096 + 256)
    finally:
        service.stop()
        os.unlink(config_path)
        os.unlink(config_path_with_timeout)


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
                "COALESCE((SELECT SUM(bytes) FROM azli_requests),0) + "
                "COALESCE((SELECT SUM(bytes) FROM azli_receipts),0)"
            ).fetchone()[0]
            instances = connection.execute(
                "SELECT COUNT(*) FROM azli_instances WHERE instance_key IN ('quota-a','quota-b')"
            ).fetchone()[0]
            page_size = connection.execute("PRAGMA page_size").fetchone()[0]
            page_count = connection.execute("PRAGMA page_count").fetchone()[0]
        allocated_bytes = 0
        for root, _, files in os.walk(service.buffer_dir):
            for name in files:
                info = os.stat(os.path.join(root, name))
                allocated_bytes += getattr(info, "st_blocks", 0) * 512 or info.st_size
        assert instances == 2
        assert 0 < used <= 1250000
        wal_headroom = max(1250000 // 4, page_size * 16)
        main_limit = 1250000 - wal_headroom - page_size * 16
        assert page_count * page_size <= main_limit
        assert allocated_bytes <= 1250000
    finally:
        service.stop()


def test_out_azure_logs_ingestion_buffer_exhaustion_retries_after_space_frees():
    service = Service(
        "out_azure_logs_ingestion_buffering.yaml",
        # Source/request BLOBs plus SQLite WAL and transition headroom are charged.
        buffer_limit="1200000",
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
                rng.randbytes(40000)
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

        def _rejected_source_delivered_and_spool_clear():
            requests_seen = list(data_storage["requests"])
            delivered = [
                item["id"]
                for request in _data_requests(requests_seen)
                for item in request["json"]
            ]
            if delivered.count("1") == 1 and _spool_is_empty(
                service.buffer_dir, "suite-buffer"
            ):
                return requests_seen
            return None

        service.service.wait_for_condition(
            _rejected_source_delivered_and_spool_clear,
            timeout=30,
            interval=0.5,
            description="engine-retried source delivered after durable quota is freed",
        )
        _post_chunk(
            service,
            [{"id": "after-free", "message": "space is available"}],
        )

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
        metrics = service.metrics(
            f"{LIFECYCLE_METRIC_PREFIX}quota_rejections_total{{"
        )
    finally:
        service.stop()

    metric_labels = {"name": "azure_logs_ingestion.0", "dcr_id": "dcr-suite"}
    assert _metric_value(
        metrics, f"{LIFECYCLE_METRIC_PREFIX}quota_rejections_total", **metric_labels
    ) >= 1
    data_requests = _data_requests(requests_seen)
    delivered_batches = [[item["id"] for item in request["json"]] for request in data_requests]
    flattened = [item for batch in delivered_batches for item in batch]
    assert len(delivered_batches) >= 3
    assert all(batch == ["0"] for batch in delivered_batches[:2])
    assert flattened.count("1") == 1
    assert flattened.count("after-free") == 1
