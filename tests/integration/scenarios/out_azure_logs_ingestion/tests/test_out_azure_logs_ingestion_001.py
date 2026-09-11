import base64
import logging
import os
import platform
import random
import re
import shutil
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

UNCOMPRESSED_PAYLOAD_SIZE_METRIC = (
    "fluentbit_azure_logs_ingestion_uncompressed_payload_size_bytes"
)
HTTP_PAYLOAD_SIZE_METRIC = "fluentbit_azure_logs_ingestion_http_payload_size_bytes"
METRIC_RE = re.compile(r'^(?P<name>[^\{]+)\{(?P<labels>[^}]*)\} (?P<value>.+)$')


def metric_value(metrics, metric_name, **expected_labels):
    for line in metrics.splitlines():
        match = METRIC_RE.match(line)
        if match is None or match.group("name") != metric_name:
            continue
        labels = dict(
            item.split("=", 1) for item in match.group("labels").replace('"', '').split(",")
        )
        if labels == expected_labels:
            return float(match.group("value"))
    raise AssertionError(f"metric not found: {metric_name} {expected_labels}")


class Service:
    def __init__(self, config_file, initial_http_status=200, extra_env=None):
        self.config_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "../config", config_file))
        cert_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../in_splunk/certificate"))
        self.tls_crt_file = os.path.join(cert_dir, "certificate.pem")
        self.tls_key_file = os.path.join(cert_dir, "private_key.pem")
        self.oauth_server_port = None
        self.second_listener_port = None
        self.initial_http_status = initial_http_status
        self.service = FluentBitTestService(
            self.config_file,
            data_storage=data_storage,
            data_keys=["payloads", "requests"],
            extra_env={
                "CERTIFICATE_TEST": self.tls_crt_file,
                "PRIVATE_KEY_TEST": self.tls_key_file,
                **(extra_env or {}),
            },
            pre_start=self._start_receiver,
            post_stop=self._stop_receiver,
        )

    def _start_receiver(self, service):
        self.oauth_server_port = service.allocate_port_env("TEST_SUITE_OAUTH_PORT")
        self.second_listener_port = service.allocate_port_env("SECOND_LISTENER_PORT")
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

    def wait_for_log(self, text, timeout=10):
        return self.wait_for_log_count(text, 1, timeout)

    def wait_for_log_count(self, text, count, timeout=10):
        def contains_text():
            with open(self.flb.log_file, encoding="utf-8", errors="replace") as handle:
                content = handle.read()
            return content if content.count(text) >= count else None

        return self.service.wait_for_condition(
            contains_text,
            timeout=timeout,
            interval=0.25,
            description=f"Fluent Bit log containing {count} occurrences of {text!r}",
        )

    def metrics(self, expected, timeout=10):
        url = (
            f"http://127.0.0.1:{self.flb.http_monitoring_port}"
            "/api/v2/metrics/prometheus"
        )

        def expected_metric():
            response = requests.get(url, timeout=2)
            if response.status_code == 200 and expected in response.text:
                return response.text
            return None

        return self.service.wait_for_condition(
            expected_metric,
            timeout=timeout,
            interval=0.5,
            description=f"Prometheus metric {expected}",
        )


def data_requests(requests_seen):
    return [
        request
        for request in requests_seen
        if request["path"].startswith("/dataCollectionRules/")
    ]


def post_chunk(service, chunk_id, records=2):
    payload = [
        {
            "id": f"{chunk_id}-{record_index}",
            "message": f"deferred chunk {chunk_id} record {record_index}",
        }
        for record_index in range(records)
    ]
    response = requests.post(
        f"http://127.0.0.1:{service.flb_listener_port}/",
        json=payload,
        timeout=5,
    )
    assert response.status_code == 201
    return payload


def test_out_azure_logs_ingestion_batches_three_engine_chunks():
    service = Service("out_azure_logs_ingestion_batching.yaml", initial_http_status=204)
    service.start()
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    chunks = []
    try:
        for chunk_id in range(3):
            chunks.append(post_chunk(service, chunk_id))
            service.wait_for_log(f"deferred batch queued chunks={chunk_id + 1}/3")
            if chunk_id < 2:
                assert data_requests(data_storage["requests"]) == []

        requests_seen = service.wait_for_requests(2, timeout=15)
        metrics = service.metrics(
            f'{HTTP_PAYLOAD_SIZE_METRIC}_count{{name="azure_logs_ingestion.0",'
            f'dcr_id="dcr-suite"}} 1'
        )
    finally:
        service.stop()

    sent = data_requests(requests_seen)
    assert len(sent) == 1
    assert [record["id"] for record in sent[0]["json"]] == [
        record["id"] for chunk in chunks for record in chunk
    ]
    labels = {"name": "azure_logs_ingestion.0", "dcr_id": "dcr-suite"}
    assert metric_value(metrics, f"{HTTP_PAYLOAD_SIZE_METRIC}_count", **labels) == 1


@pytest.mark.parametrize("chunk_count", [1, 2])
def test_out_azure_logs_ingestion_flushes_partial_batch_after_timeout(chunk_count):
    service = Service(
        "out_azure_logs_ingestion_batching_short_timeout.yaml",
        initial_http_status=204,
    )
    service.start()
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    expected = []
    try:
        for chunk_id in range(chunk_count):
            expected.extend(post_chunk(service, f"partial-{chunk_id}"))
            service.wait_for_log(f"deferred batch queued chunks={chunk_id + 1}/3")
        requests_seen = service.wait_for_requests(2, timeout=10)
    finally:
        service.stop()

    sent = data_requests(requests_seen)
    assert len(sent) == 1
    assert [record["id"] for record in sent[0]["json"]] == [
        record["id"] for record in expected
    ]


def test_out_azure_logs_ingestion_retries_every_batched_chunk():
    service = Service("out_azure_logs_ingestion_batching.yaml", initial_http_status=500)
    service.start()
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    chunks = []
    try:
        for chunk_id in range(3):
            chunks.append(post_chunk(service, f"retry-{chunk_id}"))
            service.wait_for_log(f"deferred batch queued chunks={chunk_id + 1}/3")
        service.wait_for_requests(2, timeout=15)
        configure_http_response(status_code=204, body="")
        expected_ids = {
            record["id"] for chunk in chunks for record in chunk
        }

        def all_retried_chunks_delivered():
            requests_seen = list(data_storage["requests"])
            retried_ids = {
                record["id"]
                for request in data_requests(requests_seen)[1:]
                for record in request["json"]
            }
            return requests_seen if retried_ids == expected_ids else None

        requests_seen = service.service.wait_for_condition(
            all_retried_chunks_delivered,
            timeout=30,
            interval=0.5,
            description="all retried deferred chunks delivered",
        )
    finally:
        service.stop()

    sent = data_requests(requests_seen)
    expected_ids = [record["id"] for chunk in chunks for record in chunk]
    assert len(sent) >= 2
    assert [record["id"] for record in sent[0]["json"]] == expected_ids
    retried_ids = [
        record["id"] for request in sent[1:] for record in request["json"]
    ]
    assert sorted(retried_ids) == sorted(expected_ids)


def test_out_azure_logs_ingestion_sends_concurrent_closed_batches():
    service = Service("out_azure_logs_ingestion_batching.yaml", initial_http_status=204)
    service.start()
    configure_http_response(status_code=204, body="", delay_seconds=2)
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    first_batch = []
    second_batch = []
    try:
        for chunk_id in range(3):
            first_batch.extend(post_chunk(service, f"active-a-{chunk_id}"))
            service.wait_for_log_count("deferred batch queued chunks=", chunk_id + 1)
        service.service.wait_for_condition(
            lambda: True if len(data_requests(data_storage["requests"])) == 1 else None,
            timeout=10,
            interval=0.1,
            description="first delayed Azure request to start",
        )

        started = time.monotonic()
        for chunk_id in range(3):
            second_batch.extend(post_chunk(service, f"active-b-{chunk_id}"))
            service.wait_for_log_count("deferred batch queued chunks=", chunk_id + 4)
        requests_seen = service.service.wait_for_condition(
            lambda: list(data_storage["requests"])
            if len(data_requests(data_storage["requests"])) == 2 else None,
            timeout=1.5,
            interval=0.05,
            description="second Azure request while the first response is delayed",
        )
        assert time.monotonic() - started < 2
        service.wait_for_log_count("http_status=204", 2, timeout=10)
    finally:
        service.stop()

    sent = data_requests(requests_seen)
    assert [record["id"] for record in sent[0]["json"]] == [
        record["id"] for record in first_batch
    ]
    assert [record["id"] for record in sent[1]["json"]] == [
        record["id"] for record in second_batch
    ]


def test_out_azure_logs_ingestion_retries_oversized_batch_without_sending():
    service = Service("out_azure_logs_ingestion_batching.yaml", initial_http_status=204)
    service.start()
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    rng = random.Random(13254)
    try:
        for chunk_id in range(3):
            payload = [{
                "id": f"oversized-{chunk_id}",
                "message": base64.b64encode(rng.randbytes(400000)).decode("ascii"),
            }]
            response = requests.post(
                f"http://127.0.0.1:{service.flb_listener_port}/",
                json=payload,
                timeout=10,
            )
            assert response.status_code == 201
            service.wait_for_log(f"deferred batch queued chunks={chunk_id + 1}/3")

        service.wait_for_log("deferred batch exceeds Azure request limit", timeout=15)
        assert data_requests(data_storage["requests"]) == []
    finally:
        service.stop()


@pytest.mark.skipif(platform.system() == "Darwin", reason="macOS cancels the engine thread on stop")
def test_out_azure_logs_ingestion_shutdown_drains_partial_batch():
    service = Service(
        "out_azure_logs_ingestion_batching_short_timeout.yaml",
        initial_http_status=204,
    )
    service.start()
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    expected = post_chunk(service, "shutdown")
    service.wait_for_log("deferred batch queued chunks=1/3")
    started = time.monotonic()
    service.stop()

    assert time.monotonic() - started < 10
    sent = data_requests(data_storage["requests"])
    assert len(sent) == 1
    assert [record["id"] for record in sent[0]["json"]] == [
        record["id"] for record in expected
    ]
    with open(service.flb.log_file, encoding="utf-8", errors="replace") as handle:
        log = handle.read()
    assert "draining deferred batches" in log
    assert "destroying output with pending deferred batch" not in log


def test_out_azure_logs_ingestion_keeps_output_batches_isolated():
    service = Service(
        "out_azure_logs_ingestion_batching_two_outputs.yaml",
        initial_http_status=204,
    )
    service.start()
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    try:
        expected_a = []
        for chunk_id in range(2):
            expected_a.extend(post_chunk(service, f"a-{chunk_id}"))
            response = requests.post(
                f"http://127.0.0.1:{service.second_listener_port}/",
                json=[
                    {
                        "id": f"b-{chunk_id}-{record_index}",
                        "message": f"output b chunk {chunk_id} record {record_index}",
                    }
                    for record_index in range(2)
                ],
                timeout=5,
            )
            assert response.status_code == 201
            time.sleep(0.4)

        requests_seen = service.service.wait_for_condition(
            lambda: list(data_storage["requests"])
            if len(data_requests(data_storage["requests"])) >= 2 else None,
            timeout=15,
            interval=0.5,
            description="two isolated Azure batches",
        )
    finally:
        service.stop()

    by_dcr = {
        request["path"].split("/")[2]: request["json"]
        for request in data_requests(requests_seen)
    }
    assert set(by_dcr) == {"dcr-a", "dcr-b"}
    assert [record["id"] for record in by_dcr["dcr-a"]] == [
        f"a-{chunk}-{record}" for chunk in range(2) for record in range(2)
    ]
    assert [record["id"] for record in by_dcr["dcr-b"]] == [
        f"b-{chunk}-{record}" for chunk in range(2) for record in range(2)
    ]


@pytest.mark.skipif(platform.system() == "Darwin", reason="macOS cancels the engine thread on stop")
def test_out_azure_logs_ingestion_shutdown_waits_for_active_batch():
    service = Service("out_azure_logs_ingestion_batching.yaml", initial_http_status=204)
    service.start()
    configure_http_response(status_code=204, body="", delay_seconds=2)
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    expected = []
    for chunk_id in range(3):
        expected.extend(post_chunk(service, f"active-stop-{chunk_id}"))
        service.wait_for_log(f"deferred batch queued chunks={chunk_id + 1}/3")
    service.service.wait_for_condition(
        lambda: list(data_storage["requests"])
        if len(data_requests(data_storage["requests"])) == 1 else None,
        timeout=10,
        interval=0.1,
        description="active Azure batch request",
    )

    started = time.monotonic()
    service.stop()
    elapsed = time.monotonic() - started

    assert 1 <= elapsed < 10
    sent = data_requests(data_storage["requests"])
    assert [record["id"] for record in sent[0]["json"]] == [
        record["id"] for record in expected
    ]
    with open(service.flb.log_file, encoding="utf-8", errors="replace") as handle:
        log = handle.read()
    assert "http_status=204" in log
    assert "cancelling pending flushes" not in log


@pytest.mark.skipif(platform.system() == "Darwin", reason="macOS cancels the engine thread on stop")
def test_out_azure_logs_ingestion_network_timeout_bounds_active_batch():
    storage_path = tempfile.mkdtemp(prefix="flb-azure-batch-cancel-")
    service = Service(
        "out_azure_logs_ingestion_batching_filesystem.yaml",
        initial_http_status=204,
        extra_env={"FLUENT_BIT_TEST_STORAGE_PATH": storage_path},
    )
    service.start()
    stopped = False
    configure_http_response(status_code=204, body="", delay_seconds=5)
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    try:
        for chunk_id in range(3):
            post_chunk(service, f"cancel-stop-{chunk_id}")
            service.wait_for_log(f"deferred batch queued chunks={chunk_id + 1}/3")
        service.service.wait_for_condition(
            lambda: True if len(data_requests(data_storage["requests"])) == 1 else None,
            timeout=10,
            interval=0.1,
            description="active request before grace expiry",
        )
        started = time.monotonic()
        service.stop()
        stopped = True
        elapsed = time.monotonic() - started
    finally:
        if not stopped:
            service.stop()
        shutil.rmtree(storage_path, ignore_errors=True)

    assert 4 <= elapsed < 8
    with open(service.flb.log_file, encoding="utf-8", errors="replace") as handle:
        log = handle.read()
    assert "response timeout reached" in log
    assert "destroying output with pending deferred batch" not in log


@pytest.mark.skipif(platform.system() == "Darwin", reason="macOS cancels the engine thread on reload")
def test_out_azure_logs_ingestion_hot_reload_drains_old_batch():
    service = Service(
        "out_azure_logs_ingestion_batching_hot_reload.yaml",
        initial_http_status=204,
    )
    service.start()
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    before_reload = post_chunk(service, "before-reload")
    service.wait_for_log("deferred batch queued chunks=1/3")
    service.flb.send_sighup()

    try:
        service.flb.wait_for_hot_reload_count(1, timeout=15)
        after_reload = post_chunk(service, "after-reload")
        requests_seen = service.service.wait_for_condition(
            lambda: list(data_storage["requests"])
            if len(data_requests(data_storage["requests"])) == 2 else None,
            timeout=10,
            interval=0.25,
            description="old and new configuration Azure requests",
        )
    finally:
        service.stop()

    sent = data_requests(requests_seen)
    assert [record["id"] for record in sent[0]["json"]] == [
        record["id"] for record in before_reload
    ]
    assert [record["id"] for record in sent[1]["json"]] == [
        record["id"] for record in after_reload
    ]
    with open(service.flb.log_file, encoding="utf-8", errors="replace") as handle:
        log = handle.read()
    assert log.index("draining deferred batches") < log.index("[reload] start everything")
    assert "destroying output with pending deferred batch" not in log


@pytest.mark.skipif(platform.system() == "Darwin", reason="macOS cancels the engine thread on reload")
def test_out_azure_logs_ingestion_hot_reload_retries_old_batch():
    service = Service(
        "out_azure_logs_ingestion_batching_hot_reload.yaml",
        initial_http_status=500,
    )
    service.start()
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    expected = post_chunk(service, "reload-retry")
    service.wait_for_log("deferred batch queued chunks=1/3")
    service.flb.send_sighup()

    try:
        service.service.wait_for_condition(
            lambda: True if len(data_requests(data_storage["requests"])) >= 1 else None,
            timeout=10,
            interval=0.1,
            description="failed old-configuration Azure request",
        )
        configure_http_response(status_code=204, body="")
        service.flb.wait_for_hot_reload_count(1, timeout=20)
    finally:
        service.stop()

    delivered_ids = [
        record["id"]
        for request in data_requests(data_storage["requests"])[1:]
        for record in request["json"]
    ]
    assert delivered_ids == [record["id"] for record in expected]


@pytest.mark.skipif(platform.system() == "Darwin", reason="macOS cancels the engine thread on reload")
def test_out_azure_logs_ingestion_hot_reload_waits_for_active_batch():
    service = Service(
        "out_azure_logs_ingestion_batching_hot_reload.yaml",
        initial_http_status=204,
    )
    service.start()
    configure_http_response(status_code=204, body="", delay_seconds=2)
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    try:
        for chunk_id in range(3):
            post_chunk(service, f"active-reload-{chunk_id}")
            service.wait_for_log(f"deferred batch queued chunks={chunk_id + 1}/3")
        service.service.wait_for_condition(
            lambda: True if len(data_requests(data_storage["requests"])) == 1 else None,
            timeout=10,
            interval=0.1,
            description="active Azure request before reload",
        )
        service.flb.send_sighup()
        time.sleep(0.5)
        with open(service.flb.log_file, encoding="utf-8", errors="replace") as handle:
            assert "[reload] start everything" not in handle.read()
        service.flb.wait_for_hot_reload_count(1, timeout=10)
    finally:
        service.stop()

    with open(service.flb.log_file, encoding="utf-8", errors="replace") as handle:
        log = handle.read()
    assert log.index("http_status=204") < log.index("[reload] start everything")
    assert "cancelling pending flushes" not in log
    assert "destroying output with pending deferred batch" not in log


def test_out_azure_logs_ingestion_filesystem_chunks_survive_restart():
    storage_path = tempfile.mkdtemp(prefix="flb-azure-batch-storage-")
    env = {"FLUENT_BIT_TEST_STORAGE_PATH": storage_path}
    expected = None
    first_stopped = False

    first = Service(
        "out_azure_logs_ingestion_batching_filesystem.yaml",
        initial_http_status=500,
        extra_env=env,
    )
    try:
        first.start()
        configure_oauth_token_response(
            status_code=200,
            body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
        )
        expected = post_chunk(first, "filesystem-restart")
        first.wait_for_log("deferred batch queued chunks=1/3")
        first.stop()
        first_stopped = True

        second = Service(
            "out_azure_logs_ingestion_batching_filesystem.yaml",
            initial_http_status=204,
            extra_env=env,
        )
        second.start()
        configure_oauth_token_response(
            status_code=200,
            body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
        )
        try:
            requests_seen = second.service.wait_for_condition(
                lambda: list(data_storage["requests"])
                if len(data_requests(data_storage["requests"])) >= 1 else None,
                timeout=15,
                interval=0.25,
                description="filesystem-backed chunk after restart",
            )
        finally:
            second.stop()
    finally:
        if not first_stopped:
            first.stop()
        shutil.rmtree(storage_path, ignore_errors=True)

    delivered = data_requests(requests_seen)
    assert [record["id"] for record in delivered[0]["json"]] == [
        record["id"] for record in expected
    ]


def test_out_azure_logs_ingestion_rejects_batching_workers():
    service = Service("out_azure_logs_ingestion_batching_workers.yaml")
    with pytest.raises(FluentBitStartupError):
        service.start()
    service.stop()


def test_out_azure_logs_ingestion_legacy_oauth2_and_payload_format():
    service = Service("out_azure_logs_ingestion_oauth2.yaml", initial_http_status=500)
    service.start()
    configure_oauth_token_response(
        status_code=200,
        body={"access_token": "oauth-access-token", "token_type": "Bearer", "expires_in": 300},
    )

    service.wait_for_requests(2, timeout=15)
    service.wait_for_log("http_status=500", timeout=15)
    configure_http_response(status_code=200, body={"status": "received"})
    requests_seen = service.wait_for_requests(3, timeout=15)
    labels = {"name": "azure_logs_ingestion.0", "dcr_id": "dcr-suite"}
    metrics = service.metrics(
        f'{HTTP_PAYLOAD_SIZE_METRIC}_count{{name="azure_logs_ingestion.0",'
        f'dcr_id="dcr-suite"}} 2'
    )
    service.stop()

    token_request = next(request for request in requests_seen if request["path"] == "/oauth/token")
    data_requests = [
        request
        for request in requests_seen
        if request["path"] == "/dataCollectionRules/dcr-suite/streams/Custom-suite_CL"
    ]
    data_request = data_requests[-1]

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

    uncompressed_size = sum(
        len(request["decoded_data"].encode("utf-8")) for request in data_requests
    )
    http_size = sum(
        int(request["headers"]["Content-Length"]) for request in data_requests
    )
    uncompressed_sum = metric_value(
        metrics, f"{UNCOMPRESSED_PAYLOAD_SIZE_METRIC}_sum", **labels
    )
    http_sum = metric_value(metrics, f"{HTTP_PAYLOAD_SIZE_METRIC}_sum", **labels)

    assert metric_value(metrics, f"{HTTP_PAYLOAD_SIZE_METRIC}_count", **labels) == 2
    assert uncompressed_sum == uncompressed_size
    assert http_sum == http_size
    assert http_sum / uncompressed_sum == http_size / uncompressed_size
    assert metric_value(
        metrics,
        f"{HTTP_PAYLOAD_SIZE_METRIC}_bucket",
        **labels,
        le="204800.0",
    ) == 2
