import base64
import gzip
import hashlib
import hmac
import json
import os
import glob
import re
import sqlite3
import time
import shutil
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import requests
import pytest
import yaml
from google.protobuf import json_format
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceRequest
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

from server.s3_server import TaggedUploadBarrier, data_storage, s3_server_run, s3_server_stop
from utils.data_utils import read_json_file
from utils.fluent_bit_manager import FluentBitStartupError
from utils.test_service import FluentBitTestService


class Service:
    def __init__(self, config_file, *, put_status=200, put_delay=0,
                 upload_barrier=None, shutdown_timeout=None, credential_mode=None,
                 response_override=None):
        self.put_status = put_status
        self.put_delay = put_delay
        self.upload_barrier = upload_barrier
        self.credential_mode = credential_mode
        self.response_override = response_override
        self.config_file = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../config", config_file)
        )
        self.service = FluentBitTestService(
            self.config_file,
            data_storage=data_storage,
            data_keys=["requests"],
            extra_env={
                "AWS_ACCESS_KEY_ID": "" if credential_mode else "test-access-key",
                "AWS_SECRET_ACCESS_KEY": "" if credential_mode else "test-secret-key",
                "AWS_EC2_METADATA_DISABLED": "true",
            },
            pre_start=self._start_receiver,
            post_stop=self._stop_receiver,
            shutdown_timeout=shutdown_timeout,
        )

    def _start_receiver(self, service):
        self.s3_port = service.allocate_port_env("TEST_SUITE_HTTP_PORT")
        s3_server_run(self.s3_port)
        data_storage["put_status"] = self.put_status
        data_storage["put_delay"] = self.put_delay
        data_storage["upload_barrier"] = self.upload_barrier
        data_storage["credential_mode"] = self.credential_mode
        data_storage["response_override"] = self.response_override
        if self.credential_mode:
            service._set_env("AWS_CONTAINER_CREDENTIALS_FULL_URI", f"http://127.0.0.1:{self.s3_port}/credentials")
            service._set_env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "")
            service._set_env("AWS_CONFIG_FILE", os.devnull)
            service._set_env("AWS_SHARED_CREDENTIALS_FILE", os.devnull)
            service._set_env("AWS_WEB_IDENTITY_TOKEN_FILE", "")

    def _stop_receiver(self, service):
        s3_server_stop()

    def start(self):
        self.service.start()
        self.flb_listener_port = self.service.flb_listener_port

    def stop(self):
        self.service.stop()

    def wait_for_request(self, index=0):
        return self.service.wait_for_condition(
            lambda: data_storage["requests"][index] if len(data_storage["requests"]) > index else None,
            timeout=15,
            interval=0.5,
            description=f"S3 upload request {index}",
        )

    def _resolve_json_fixture(self, json_file):
        return os.path.abspath(
            os.path.join(
                os.path.dirname(__file__),
                "../../in_opentelemetry/tests/data_files",
                json_file,
            )
        )

    def _build_signal_payload(self, json_file, signal_type):
        messages = {
            "logs": ExportLogsServiceRequest(),
            "metrics": ExportMetricsServiceRequest(),
            "traces": ExportTraceServiceRequest(),
        }
        return json_format.Parse(
            json.dumps(read_json_file(self._resolve_json_fixture(json_file))),
            messages[signal_type],
        )

    def send_logs_payload(self, json_file):
        payload = self._build_signal_payload(json_file, "logs")
        response = requests.post(
            f"http://127.0.0.1:{self.flb_listener_port}/v1/logs",
            data=payload.SerializeToString(),
            headers={"Content-Type": "application/x-protobuf"},
            timeout=5,
        )
        response.raise_for_status()

    def send_metrics_payload(self, json_file):
        payload = self._build_signal_payload(json_file, "metrics")
        response = requests.post(
            f"http://127.0.0.1:{self.flb_listener_port}/v1/metrics",
            data=payload.SerializeToString(),
            headers={"Content-Type": "application/x-protobuf"},
            timeout=5,
        )
        response.raise_for_status()

    def send_traces_payload(self, json_file):
        payload = self._build_signal_payload(json_file, "traces")
        response = requests.post(
            f"http://127.0.0.1:{self.flb_listener_port}/v1/traces",
            data=payload.SerializeToString(),
            headers={"Content-Type": "application/x-protobuf"},
            timeout=5,
        )
        response.raise_for_status()


def _parse_json_lines(body):
    lines = [line for line in body.decode("utf-8").splitlines() if line.strip()]
    return [json.loads(line) for line in lines]


def _s3_throttle_config(tmp_path, *, multipart=False, workers=2, io_timeout=None):
    output = {
        "name": "s3",
        "match": "routed*",
        "workers": workers,
        "bucket": "throttled",
        "region": "us-east-1",
        "endpoint": "http://127.0.0.1:${TEST_SUITE_HTTP_PORT}",
        "use_put_object": not multipart,
        "total_file_size": "10485760" if multipart else "1048576",
        "upload_chunk_size": "5242880" if multipart else "524288",
        "upload_timeout": "120s" if multipart else "1s",
        "s3_key_format": "/$TAG/$UUID",
        "store_dir": str(tmp_path / "store"),
        "retry_limit": 1,
        "throttle": True,
        "throttle.base": 1,
        "throttle.cap": 8,
    }
    if io_timeout is not None:
        output["net.io_timeout"] = io_timeout
    config = {
        "service": {
            "flush": 0.1,
            "grace": 1,
            "http_server": "on",
            "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}",
        },
        "pipeline": {
            "inputs": [{
                "name": "http",
                "listen": "127.0.0.1",
                "port": "${FLUENT_BIT_TEST_LISTENER_PORT}",
                "buffer_max_size": "10M",
            }],
            "outputs": [output],
        },
    }
    if not multipart:
        config["pipeline"]["outputs"].append(
            dict(output, match="independent", bucket="independent")
        )
    path = tmp_path / "s3_throttle.yaml"
    path.write_text(yaml.safe_dump(config))
    return path


def _s3_push(service, tag, message):
    response = requests.post(f"http://127.0.0.1:{service.flb_listener_port}/{tag}",
                             json={"message": message}, timeout=10)
    response.raise_for_status()


def _s3_retry_rows(tmp_path, kind):
    path = tmp_path / "store" / "throttled" / "uploader.db"
    with sqlite3.connect(path) as db:
        return db.execute("SELECT failures, deadline, uri FROM retry WHERE kind = ?",
                          (kind,)).fetchall()


def _s3_slow_down(status=503, delay=8):
    return status, b"<Error><Code>SlowDown</Code></Error>", [("Retry-After", str(delay))]


def _s3_completed_requests(service, predicate, count):
    def received():
        matching = [req for req in data_storage["requests"] if predicate(req)]
        if len(matching) >= count and all("status" in req for req in matching[:count]):
            return matching
        return None

    return service.service.wait_for_condition(
        received, timeout=25, interval=0.1, description=f"{count} matching S3 requests"
    )


@pytest.mark.parametrize("fail_after_restart", [False, True])
def test_out_s3_uploader_cooldown_persists_through_shutdown(tmp_path, fail_after_restart):
    config = _s3_throttle_config(tmp_path, workers=0 if fail_after_restart else 2)

    def throttled(request):
        return request["path"].startswith("/throttled/")

    def first_response(request):
        if throttled(request):
            if fail_after_restart and len(data_storage["requests"]) == 1:
                return 503, b"<Error><Code>ServiceUnavailable</Code></Error>", []
            return _s3_slow_down(delay=10**30)
        return None

    first = Service(str(config), response_override=first_response)
    try:
        first.start()
        _s3_push(first, "routed", "retry this object")
        initial = _s3_completed_requests(first, throttled, 1)[0]
        assert initial["status"] == 503
        first.service.wait_for_condition(
            lambda: _s3_retry_rows(tmp_path, "gate"),
            description="durable uploader cooldown",
        )
        failures = int(fail_after_restart)
        rows = _s3_retry_rows(tmp_path, "chunk")
        assert [(n, uri) for n, _, uri in rows] == [(failures, initial["path"])]
        [(rounds, deadline, _)] = _s3_retry_rows(tmp_path, "gate")
        assert rounds == 1
        assert 0 < deadline / 1000 - time.time() <= 8.1
        not_before = time.monotonic() + deadline / 1000 - time.time()

        _s3_push(first, "routed", "staged during cooldown")
        _s3_push(first, "independent", "healthy destination")
        healthy = _s3_completed_requests(first, lambda req: not throttled(req), 1)[0]
        assert healthy["status"] == 200
        process = first.service.flb.process
    finally:
        first.stop()
    assert process.returncode == 0
    assert sum(throttled(req) for req in data_storage["requests"]) == 1 + failures

    def retry_response(request):
        attempts = sum(req["path"] == initial["path"] for req in data_storage["requests"])
        if fail_after_restart and request["path"] == initial["path"]:
            if attempts == 1:
                return 503, b"", [("Retry-After", "1")]
            if attempts == 2:
                return 503, b"<Error><Code>SlowDownWrite</Code></Error>", []
        return None

    second = Service(str(config), response_override=retry_response)
    try:
        second.start()
        # The input is idle throughout restart. Both files came from the S3 spool.
        count = 4 if fail_after_restart else 2
        requests_seen = _s3_completed_requests(second, throttled, count)
        assert requests_seen[0]["started"] >= not_before - 0.1
        for retry in requests_seen[:-1]:
            assert retry["path"] == initial["path"]
            assert retry["body"] == initial["body"]
        expected = [503, 503, 200, 200] if fail_after_restart else [200, 200]
        assert [req["status"] for req in requests_seen] == expected
        assert _parse_json_lines(requests_seen[-1]["body"])[0]["message"] == "staged during cooldown"
    finally:
        second.stop()


@pytest.mark.parametrize("empty_etag", [False, True])
def test_out_s3_uploader_reserved_small_part_closes_upload(tmp_path, empty_etag):
    config = _s3_throttle_config(tmp_path, multipart=True)
    settings = yaml.safe_load(config.read_text())
    output = settings["pipeline"]["outputs"][0]
    output.update(compression="gzip", total_file_size="50M")
    del output["upload_chunk_size"]
    config.write_text(yaml.safe_dump(settings))

    def slow_second(request):
        if "partNumber=2" in request["path"] and sum(
            "partNumber=2" in req["path"] for req in data_storage["requests"]
        ) == 1:
            if empty_etag:
                return 200, b"", [("ETag", '""'), ("X-Next-Header", "not-an-etag")]
            return _s3_slow_down(delay=1)
        return None

    service = Service(str(config), response_override=slow_second)
    try:
        service.start()
        # Two ordinary flushes must cross the default threshold together.
        records = [base64.b64encode(os.urandom(3 * 1024 * 1024)).decode() for _ in range(2)]
        _s3_push(service, "routed", records[0])
        spool = tmp_path / "store" / "throttled"
        service.service.wait_for_condition(
            lambda: any(path.stat().st_size >= len(records[0]) for path in spool.glob("*T*/*")),
            description="first flush persisted below the multipart threshold",
        )
        _s3_push(service, "routed", records[1])
        first = _s3_completed_requests(service, lambda r: "partNumber=1" in r["path"], 1)[0]
        assert [row["message"] for row in _parse_json_lines(gzip.decompress(first["body"]))] == records
        last_message = "x" * (6 * 1024 * 1024)
        _s3_push(service, "routed", last_message)
        attempts = _s3_completed_requests(service, lambda r: "partNumber=2" in r["path"], 2)
        assert [req["status"] for req in attempts] == [200 if empty_etag else 503, 200]
        assert attempts[0]["path"] == attempts[1]["path"]
        assert len(attempts[1]["body"]) < 5242880
        assert _parse_json_lines(gzip.decompress(attempts[1]["body"]))[0]["message"] == last_message
        done = _s3_completed_requests(
            service, lambda r: r["method"] == "POST" and "uploadId=" in r["path"], 1
        )[0]
        assert parse_qs(urlsplit(done["path"]).query)["uploadId"] == parse_qs(
            urlsplit(first["path"]).query)["uploadId"]
        assert done["status"] == 200
    finally:
        service.stop()


def test_out_s3_uploader_keeps_reservation_while_journal_is_locked(tmp_path):
    config = _s3_throttle_config(tmp_path, multipart=True)
    settings = yaml.safe_load(config.read_text())
    settings["pipeline"]["outputs"][0]["upload_timeout"] = "2s"
    config.write_text(yaml.safe_dump(settings))
    database = tmp_path / "store" / "throttled" / "uploader.db"
    locks = []

    def lock_reservation(req):
        if "upload_id" in req:
            db = sqlite3.connect(database, check_same_thread=False)
            db.execute("BEGIN IMMEDIATE")
            locks.append(db)

    service = Service(str(config), response_override=lock_reservation)
    try:
        service.start()
        _s3_push(service, "routed", "x" * (6 * 1024 * 1024))
        created = _s3_completed_requests(service, lambda req: "upload_id" in req, 1)[0]
        service.service.wait_for_condition(
            lambda: _s3_metric(service, "s3_uploader_storage_blocked") == 1,
            description="multipart reservation is waiting for its journal",
        )
        time.sleep(2.1)
        assert len(data_storage["requests"]) == 1
        locks[0].rollback()
        sent = _s3_completed_requests(service, lambda req: "partNumber=" in req["path"], 1)[0]
        assert parse_qs(urlsplit(sent["path"]).query)["uploadId"] == [created["upload_id"]]
        done = _s3_completed_requests(service, lambda req: "uploadId=" in req["path"] and
                                      req["method"] == "POST", 1)[0]
        assert done["status"] == 200
        assert all(req["method"] != "DELETE" for req in data_storage["requests"])
    finally:
        for db in locks:
            db.close()
        service.stop()


@pytest.mark.parametrize("outcome", ["success", "legacy_exhausted", "missing", "embedded_missing", "invalid_manifest"])
def test_out_s3_uploader_resumes_multipart_and_retries_embedded_slowdown(tmp_path, outcome):
    config = _s3_throttle_config(tmp_path, multipart=True)

    def is_part(request):
        return request["method"] == "PUT" and "partNumber=" in request["path"]

    def is_completion(request):
        return request["method"] == "POST" and "uploadId=" in request["path"]

    first = Service(str(config), response_override=lambda req: _s3_slow_down() if is_part(req) else None)
    try:
        first.start()
        _s3_push(first, "routed", "x" * (6 * 1024 * 1024))
        part = _s3_completed_requests(first, is_part, 1)[0]
        assert part["status"] == 503
        first.service.wait_for_condition(
            lambda: _s3_retry_rows(tmp_path, "gate"),
            description="persisted multipart cooldown",
        )
        process = first.service.flb.process
    finally:
        first.stop()
    assert process.returncode == 0
    assert sum(is_part(req) for req in data_storage["requests"]) == 1
    assert not any(is_completion(req) for req in data_storage["requests"])

    second = Service(str(config),
                     response_override=lambda req: _s3_slow_down(status=200, delay=5)
                     if is_completion(req) else None)
    try:
        second.start()
        part_after_restart = _s3_completed_requests(second, is_part, 1)[0]
        assert part_after_restart["path"] == part["path"]
        assert part_after_restart["body"] == part["body"]
        assert part_after_restart["status"] == 200
        completion = _s3_completed_requests(second, is_completion, 1)[0]
        second.service.wait_for_condition(
            lambda: _s3_retry_rows(tmp_path, "gate"),
            description="persisted completion cooldown",
        )
        assert not any("uploads=" in req["path"] for req in data_storage["requests"])
        process = second.service.flb.process
    finally:
        second.stop()
    assert process.returncode == 0
    assert sum(is_completion(req) for req in data_storage["requests"]) == 1

    if outcome in ("legacy_exhausted", "missing"):
        # Older uploader versions left exhausted completions in the journal.
        upload_id = parse_qs(urlsplit(completion["path"]).query)["uploadId"][0]
        path = tmp_path / "store" / "throttled" / "uploader.db"
        with sqlite3.connect(path) as db:
            db.execute("INSERT OR REPLACE INTO retry VALUES ('complete', ?, 2, 0, NULL)",
                       (upload_id,))

    def finish(request):
        if is_completion(request):
            if sum(is_completion(req) for req in data_storage["requests"]) <= 2:
                return _s3_slow_down(status=200, delay=1)
            if outcome == "invalid_manifest":
                return 400, b"<Error><Code>InvalidPart</Code></Error>", []
            if outcome in ("missing", "embedded_missing"):
                status = 404 if outcome == "missing" else 200
                return status, b"<Error><Code>NoSuchUpload</Code></Error>", []
            return 200, b"<CompleteMultipartUploadResult/>", []
        return None

    third = Service(str(config), response_override=finish)
    try:
        third.start()
        retries = _s3_completed_requests(third, is_completion, 3)
        retried = retries[0]
        assert retried["started"] - completion["finished"] >= 4.9
        assert retried["path"] == completion["path"]
        assert retried["body"] == completion["body"]
        assert all(req["body"] == completion["body"] for req in retries)
        assert retries[-1]["status"] == {"missing": 404, "invalid_manifest": 400}.get(outcome, 200)
        metadata = tmp_path / "store" / "throttled" / "multipart_upload_metadata"
        if outcome == "invalid_manifest":
            third.service.wait_for_condition(
                lambda: (0, 0, "InvalidPart") in _s3_retry_rows(tmp_path, "complete"),
                description="rejected manifest retained for inspection",
            )
            assert list(metadata.iterdir())
            third.service.wait_for_condition(
                lambda: _s3_metric(third, "s3_uploader_rejected_uploads") == 1,
                description="rejected multipart upload visible in metrics",
            )
        else:
            third.service.wait_for_condition(
                lambda: not list(metadata.iterdir()) and not _s3_retry_rows(tmp_path, "complete"),
                description="terminal multipart manifest and journal row removed",
            )
    finally:
        third.stop()

    if outcome == "invalid_manifest":
        # Switching to delete drains quarantined uploads after a restart.
        settings = yaml.safe_load(config.read_text())
        settings["pipeline"]["outputs"][0]["retry_exhausted_action"] = "delete"
        config.write_text(yaml.safe_dump(settings))
    if outcome in ("missing", "embedded_missing", "invalid_manifest"):
        def deny_first_abort(request):
            if request["method"] == "DELETE" and not any(
                req.get("status") == 403 for req in data_storage["requests"]
            ):
                return 403, b"<Error><Code>AccessDenied</Code></Error>", []
            return None

        fourth = Service(str(config), response_override=deny_first_abort)
        try:
            fourth.start()
            _s3_push(fourth, "routed", "y" * (6 * 1024 * 1024))
            _s3_completed_requests(fourth, is_part, 1)
            if outcome == "invalid_manifest":
                aborts = _s3_completed_requests(fourth, lambda r: r["method"] == "DELETE", 2)
                assert all(req["path"] == completion["path"] for req in aborts)
                assert [req["status"] for req in aborts] == [403, 204]
                fourth.service.wait_for_condition(lambda: not _s3_retry_rows(tmp_path, "complete"),
                                                  description="aborted manifest cleared")
                fourth.service.wait_for_condition(
                    lambda: _s3_metric(fourth, "s3_uploader_rejected_uploads") == 0,
                    description="rejected upload gauge reflects completed cleanup",
                )
            assert not any(is_completion(req) and req["path"] == completion["path"]
                           for req in data_storage["requests"])
        finally:
            fourth.stop()


@pytest.mark.parametrize("already_gone", [False, True])
def test_out_s3_uploader_aborts_unreferenced_empty_upload(tmp_path, already_gone):
    config = _s3_throttle_config(tmp_path, multipart=True)
    first = Service(str(config), response_override=lambda req: _s3_slow_down()
                    if req["method"] == "PUT" else None)
    try:
        first.start()
        _s3_push(first, "routed", "x" * (6 * 1024 * 1024))
        original = _s3_completed_requests(first, lambda req: req["method"] == "PUT", 1)[0]
        first.service.wait_for_condition(lambda: _s3_retry_rows(tmp_path, "gate"),
                                         description="durable cooldown")
    finally:
        first.stop()

    # Recreate the durable state between CreateMultipartUpload and the part assignment.
    with sqlite3.connect(tmp_path / "store" / "throttled" / "uploader.db") as db:
        assert db.execute("DELETE FROM retry WHERE kind='part'").rowcount == 1

    def abort_response(req):
        if already_gone and req["method"] == "DELETE":
            return 404, b"<Error><Code>NoSuchUpload</Code></Error>", []
        return None

    second = Service(str(config), response_override=abort_response)
    try:
        second.start()
        aborted = _s3_completed_requests(second, lambda req: req["method"] == "DELETE", 1)[0]
        replacement = _s3_completed_requests(second, lambda req: req["method"] == "PUT", 1)[0]
        old_id = parse_qs(urlsplit(original["path"]).query)["uploadId"]
        assert parse_qs(urlsplit(aborted["path"]).query)["uploadId"] == old_id
        assert parse_qs(urlsplit(replacement["path"]).query)["uploadId"] != old_id
        assert replacement["body"] == original["body"]
        assert replacement["status"] == 200
    finally:
        second.stop()


def test_out_s3_uploader_retries_initial_manifest(tmp_path):
    config = _s3_throttle_config(tmp_path, multipart=True)
    service = Service(str(config))
    manifests = tmp_path / "store" / "throttled" / "multipart_upload_metadata"
    try:
        service.start()
        parked = manifests.with_suffix(".parked")
        manifests.rename(parked)
        try:
            manifests.touch()
            _s3_push(service, "routed", "x" * (6 * 1024 * 1024))
            create = _s3_completed_requests(service, lambda r: "upload_id" in r, 1)[0]
            service.service.wait_for_condition(
                lambda: _s3_metric(service, "s3_uploader_storage_blocked") == 1,
                description="initial manifest write blocked",
            )
            assert not any(req["method"] == "PUT" for req in data_storage["requests"])
        finally:
            manifests.unlink(missing_ok=True)
            parked.rename(manifests)
        part = _s3_completed_requests(service, lambda r: r["method"] == "PUT", 1)[0]
        assert parse_qs(urlsplit(part["path"]).query)["uploadId"] == [create["upload_id"]]
        assert sum("upload_id" in req for req in data_storage["requests"]) == 1
    finally:
        service.stop()


def test_out_s3_uploader_replays_part_after_missing_upload(tmp_path):
    config = _s3_throttle_config(tmp_path, multipart=True)
    settings = yaml.safe_load(config.read_text())
    settings["pipeline"]["outputs"][0]["retry_limit"] = 0
    config.write_text(yaml.safe_dump(settings))

    def missing_first_upload(req):
        if req["method"] == "PUT" and not any(
            previous.get("status") == 404 for previous in data_storage["requests"]
        ):
            return 404, b"<Error><Code>NoSuchUpload</Code></Error>", []
        return None

    service = Service(str(config), response_override=missing_first_upload)
    try:
        service.start()
        _s3_push(service, "routed", "x" * (6 * 1024 * 1024))
        parts = _s3_completed_requests(service, lambda req: req["method"] == "PUT", 2)
        assert [part["status"] for part in parts] == [404, 200]
        assert parts[0]["body"] == parts[1]["body"]
        assert parse_qs(urlsplit(parts[0]["path"]).query)["uploadId"] != parse_qs(
            urlsplit(parts[1]["path"]).query)["uploadId"]
    finally:
        service.stop()


def test_out_s3_uploader_ordinary_503_leaves_other_uploads_eligible(tmp_path):
    config = _s3_throttle_config(tmp_path)

    settings = yaml.safe_load(config.read_text())
    settings["pipeline"]["outputs"][0]["retry_limit"] = 3
    config.write_text(yaml.safe_dump(settings))
    pending_at_delivery = []

    def response(request):
        if "/routed.more/" in request["path"]:
            pending_at_delivery.extend(_s3_retry_rows(tmp_path, "chunk"))
        elif "/routed/" in request["path"]:
            attempts = [req for req in data_storage["requests"] if "/routed/" in req["path"]]
            if len(attempts) <= 2:
                return (503, b"<Error><Code>ServiceUnavailable</Code></Error>",
                        [("Retry-After", "20")])
        return None

    service = Service(str(config), response_override=response)
    try:
        service.start()
        _s3_push(service, "routed", "ordinary retry")
        initial, retry = _s3_completed_requests(service, lambda req: "/routed/" in req["path"], 2)[:2]
        assert initial["status"] == retry["status"] == 503
        assert retry["started"] - initial["finished"] >= 1.9
        assert retry["path"] == initial["path"]
        assert not _s3_retry_rows(tmp_path, "gate")
        _s3_push(service, "routed.more", "different upload")
        fresh = _s3_completed_requests(service, lambda req: "/routed.more/" in req["path"], 1)[0]
        assert fresh["status"] == 200
        assert any(failures == 2 and uri == initial["path"] for failures, _, uri in pending_at_delivery)
        success = _s3_completed_requests(service, lambda req: "/routed/" in req["path"], 3)[2]
        assert fresh["finished"] < success["started"]
        assert success["status"] == 200
    finally:
        service.stop()


def _s3_metric(service, metric):
    url = f"http://127.0.0.1:{service.service.flb.http_monitoring_port}/api/v2/metrics/prometheus"
    response = requests.get(url, timeout=2)
    if response.status_code == 404:
        # The first metrics snapshot may still be pending after startup.
        return None
    response.raise_for_status()
    prefix = f'fluentbit_output_{metric}{{name="s3.0"}} '
    return next((float(line.split()[1]) for line in response.text.splitlines()
                 if line.startswith(prefix)), None)


def test_out_s3_uploader_full_spool_defers_engine_route(tmp_path):
    config = _s3_throttle_config(tmp_path)
    settings = yaml.safe_load(config.read_text())
    settings["pipeline"]["outputs"][0].update(store_dir_limit_size="1K", retry_limit=0)
    config.write_text(yaml.safe_dump(settings))

    def throttle_once(request):
        if len(data_storage["requests"]) == 1:
            return 429, b"", [("Retry-After", "6")]
        return None

    service = Service(str(config), response_override=throttle_once)
    try:
        service.start()
        _s3_push(service, "routed", "a" * 650)
        assert _s3_completed_requests(service, lambda req: True, 1)[0]["status"] == 429
        _s3_push(service, "routed.more", "b" * 650)
        service.service.wait_for_condition(
            lambda: (_s3_metric(service, "throttle_deferred_routes") or 0) > 0,
            description="engine retained the second chunk",
        )
        assert _s3_metric(service, "s3_uploader_cooldown_until_seconds") > time.time()
        assert _s3_metric(service, "s3_uploader_spool_full") == 1
        delivered = _s3_completed_requests(service, lambda req: req.get("status") == 200, 2)
        assert [_parse_json_lines(req["body"])[0]["message"] for req in delivered] == [
            "a" * 650, "b" * 650
        ]
        service.service.wait_for_condition(lambda: _s3_metric(service, "s3_uploader_spool_full") == 0,
                                           description="spool admits data again")
    finally:
        service.stop()


@pytest.mark.parametrize("throttle", [False, True])
def test_out_s3_sequence_directory_after_shutdown(tmp_path, throttle):
    config = _s3_throttle_config(tmp_path)
    settings = yaml.safe_load(config.read_text())
    settings["pipeline"]["outputs"] = [settings["pipeline"]["outputs"][0]]
    settings["pipeline"]["outputs"][0].update(throttle=throttle, s3_key_format="/$TAG/$INDEX")
    config.write_text(yaml.safe_dump(settings))
    sequence = tmp_path / "store" / "throttled" / "sequence" / "index_metadata" / "seq_index_0"
    service = Service(str(config))
    try:
        service.start()
        _s3_push(service, "routed", "sequence test")
        assert _s3_completed_requests(service, lambda r: r["method"] == "PUT", 1)[0]["status"] == 200
        assert int(sequence.read_text()) == 1
    finally:
        service.stop()
    assert sequence.exists() == throttle


@pytest.mark.parametrize("key_format", ["/$TAG/$INDEX", "/$TAG/fixed", "/" + "d" * 999 + "/fixed"])
def test_out_s3_uploader_recovers_corrupt_journal(tmp_path, key_format):
    config = _s3_throttle_config(tmp_path)
    settings = yaml.safe_load(config.read_text())
    settings["pipeline"]["outputs"][0].update(s3_key_format=key_format, static_file_path=True)
    config.write_text(yaml.safe_dump(settings))
    spool = tmp_path / "store" / "throttled"
    first = Service(str(config), response_override=lambda req: _s3_slow_down())
    try:
        first.start()
        _s3_push(first, "routed", "acknowledged before corruption")
        original = _s3_completed_requests(first, lambda req: True, 1)[0]
    finally:
        first.stop()

    damaged = b"corrupt SQLite journal" * 32
    (spool / "uploader.db").write_bytes(damaged)
    second = Service(str(config), response_override=lambda req: _s3_slow_down())
    try:
        second.start()
        replay = _s3_completed_requests(second, lambda req: True, 1)[0]
        assert replay["body"] == original["body"]
        directory = original["path"].rsplit("/", 1)[0]
        replay_dir, basename = replay["path"].rsplit("/", 1)
        assert replay_dir == directory[:len("/throttled") + 992]
        assert re.search(r"[0-9a-fA-F]{32}$", basename)
        assert len(replay["path"].removeprefix("/throttled/").encode()) <= 1024
        assert replay["path"] != original["path"]
        assert (spool / "uploader.db").read_bytes() == damaged
    finally:
        second.stop()

    # Rows left after unlinking a payload must not attach to a later file.
    with sqlite3.connect(spool / "uploader.db.1") as db:
        for kind in ("chunk", "part"):
            db.execute("INSERT INTO retry VALUES (?, 'orphan', 1, 0, 'old-key')", (kind,))

    third = Service(str(config))
    try:
        third.start()
        final = _s3_completed_requests(third, lambda req: True, 1)[0]
        assert final["status"] == 200
        assert final["path"] == replay["path"]
        assert final["body"] == original["body"]
        _s3_push(third, "routed", "after recovery")
        fresh = _s3_completed_requests(third, lambda req: True, 2)[1]
        assert fresh["path"] != replay["path"]
        if "$INDEX" in key_format:
            assert fresh["path"] != original["path"]
        assert fresh["path"].startswith(original["path"].rsplit("/", 1)[0] + "/")
        assert _s3_metric(third, "s3_uploader_journal_generation") == 1
        with sqlite3.connect(spool / "uploader.db.1") as db:
            assert not db.execute("SELECT 1 FROM retry WHERE id='orphan'").fetchall()
    finally:
        third.stop()


@pytest.mark.parametrize("stop_while_locked", [False, True])
def test_out_s3_uploader_recovers_from_locked_journal(tmp_path, stop_while_locked):
    config = _s3_throttle_config(tmp_path)
    service = Service(str(config))
    try:
        service.start()
        path = tmp_path / "store" / "throttled" / "uploader.db"
        with sqlite3.connect(path) as db:
            db.execute("BEGIN IMMEDIATE")
            _s3_push(service, "routed", "locked checkpoint")
            service.service.wait_for_condition(
                lambda: _s3_metric(service, "s3_uploader_storage_blocked") == 1,
                description="journal write blocked",
            )
            assert not data_storage["requests"]
            if stop_while_locked:
                process = service.service.flb.process
                service.stop()
                assert process.returncode == 1
                return
            db.rollback()
        request = _s3_completed_requests(service, lambda req: True, 1)[0]
        assert request["status"] == 200
        assert _parse_json_lines(request["body"])[0]["message"] == "locked checkpoint"
        service.service.wait_for_condition(
            lambda: _s3_metric(service, "s3_uploader_storage_blocked") == 0,
            description="storage recovery visible in the next metrics snapshot",
        )
    finally:
        service.stop()


def test_out_s3_uploader_reload_preserves_shutdown_failure(tmp_path):
    config = _s3_throttle_config(tmp_path)
    settings = yaml.safe_load(config.read_text())
    settings["service"]["hot_reload"] = True
    config.write_text(yaml.safe_dump(settings))
    service = Service(str(config))
    try:
        service.start()
        manager = service.service.flb
        process = manager.process
        with sqlite3.connect(tmp_path / "store" / "throttled" / "uploader.db") as db:
            db.execute("BEGIN IMMEDIATE")
            _s3_push(service, "routed", "locked during reload")
            service.service.wait_for_condition(
                lambda: _s3_metric(service, "s3_uploader_storage_blocked") == 1,
                description="old pipeline has a pending checkpoint",
            )
            settings["pipeline"]["outputs"] = [{"name": "null", "match": "*"}]
            config.write_text(yaml.safe_dump(settings))
            assert manager.trigger_http_reload()["reload"] == "done"
            manager.wait_for_hot_reload_count(1, timeout=30)
        service.stop()
        assert process.returncode == 1
    finally:
        service.stop()


def test_out_s3_uploader_restart_only_retires_delivered_file(tmp_path):
    if os.name != "nt" and os.geteuid() == 0:
        pytest.skip("unlink failure requires an unprivileged process")
    config = _s3_throttle_config(tmp_path)
    spool = tmp_path / "store" / "throttled"
    protected = []

    def prevent_removal(req):
        [file] = spool.glob("*T*/*")
        path = file if os.name == "nt" else file.parent
        protected.append((path, path.stat().st_mode))
        path.chmod(0o444 if os.name == "nt" else 0o555)

    first = Service(str(config), response_override=prevent_removal)
    try:
        first.start()
        _s3_push(first, "routed", "already delivered")
        _s3_completed_requests(first, lambda r: r.get("status") == 200, 1)
        first.service.wait_for_condition(
            lambda: any(row[0] == -1 for row in _s3_retry_rows(tmp_path, "chunk")),
            description="delivery checkpoint retained while unlink fails",
        )
        first.stop()
        assert list(spool.glob("*T*/*"))
    finally:
        for path, mode in protected:
            path.chmod(mode)
        first.stop()

    second = Service(str(config))
    try:
        second.start()
        second.service.wait_for_condition(
            lambda: not list(spool.glob("*T*/*")) and not _s3_retry_rows(tmp_path, "chunk"),
            description="restart finishes local removal",
        )
        assert not data_storage["requests"]
        _s3_push(second, "routed", "after restart")
        [sent] = _s3_completed_requests(second, lambda r: r.get("status") == 200, 1)
        assert _parse_json_lines(sent["body"])[0]["message"] == "after restart"
    finally:
        second.stop()


def test_out_s3_uploader_shutdown_preserves_inflight_file(tmp_path):
    config = _s3_throttle_config(tmp_path, io_timeout="1s")
    first = Service(str(config), put_delay=5)
    try:
        first.start()
        _s3_push(first, "routed", "in-flight during shutdown")
        request = first.wait_for_request()
        process = first.service.flb.process
        stopped_at = time.monotonic()
        first.service.flb.stop()
        elapsed = time.monotonic() - stopped_at
    finally:
        first.stop()
    assert process.returncode == 0
    assert elapsed < 5
    assert len(data_storage["requests"]) == 1

    second = Service(str(config))
    try:
        second.start()
        recovered = _s3_completed_requests(second, lambda req: req["method"] == "PUT", 1)[0]
        assert recovered["path"] == request["path"]
        assert recovered["body"] == request["body"]
        assert recovered["status"] == 200
    finally:
        second.stop()


def _parse_single_json_payload(body):
    return json.loads(body.decode("utf-8").strip())


def _send_otlp_signal(service, signal_type, json_file):
    if signal_type == "logs":
        service.send_logs_payload(json_file)
    elif signal_type == "metrics":
        service.send_metrics_payload(json_file)
    else:
        service.send_traces_payload(json_file)


def _start_or_skip_unsupported_s3_format(service, format_name):
    try:
        service.start()
    except FluentBitStartupError:
        log_contents = ""
        if service.service.flb and service.service.flb.log_file:
            with open(service.service.flb.log_file, "r", encoding="utf-8", errors="replace") as file:
                log_contents = file.read()
        if f"unknown configuration property '{format_name}'" in log_contents:
            pytest.skip(f"s3.{format_name} is not supported by this Fluent Bit binary")
        raise


def _start_or_skip_unsupported_columnar_format(service, requires_marker):
    """Start the service, skipping if the columnar format support
    (arrow-glib/parquet-glib) was not compiled into the Fluent Bit binary."""
    try:
        service.start()
    except FluentBitStartupError:
        log_contents = ""
        if service.service.flb and service.service.flb.log_file:
            with open(service.service.flb.log_file, "r", encoding="utf-8", errors="replace") as file:
                log_contents = file.read()
        if requires_marker in log_contents or \
                "unknown configuration property 'format'" in log_contents:
            pytest.skip("columnar format support is not compiled into this Fluent Bit binary")
        raise


def test_out_s3_put_object_uploads_json_lines_payload():
    service = Service("out_s3_basic.yaml")
    service.start()
    request = service.wait_for_request()
    service.stop()

    assert request["method"] == "PUT"
    assert request["path"].startswith("/test-bucket/payloads/out_s3/")
    assert request["headers"]["Content-Type"] == "application/x-ndjson"

    payload = _parse_json_lines(request["body"])
    assert len(payload) == 1
    assert payload[0]["message"] == "hello from out_s3"
    assert payload[0]["source"] == "dummy"
    assert "date" in payload[0]


def test_out_s3_format_json_uploads_logs_only_as_json_lines():
    service = Service("out_s3_format_json.yaml")
    _start_or_skip_unsupported_s3_format(service, "format")
    request = service.wait_for_request()
    service.stop()

    assert request["method"] == "PUT"
    assert request["path"].startswith("/test-bucket/payloads/out_s3/")
    assert request["headers"]["Content-Type"] == "application/x-ndjson"

    payload = _parse_json_lines(request["body"])
    assert len(payload) == 1
    assert payload[0]["message"] == "hello from out_s3 format json"
    assert payload[0]["source"] == "dummy"
    assert "date" in payload[0]


def test_out_s3_put_object_gzip_upload_sets_encoding_and_compresses_payload():
    service = Service("out_s3_gzip.yaml")
    service.start()
    request = service.wait_for_request()
    service.stop()

    assert request["method"] == "PUT"
    assert request["path"].startswith("/test-bucket/payloads/out_s3/")
    assert request["headers"]["Content-Type"] == "application/x-ndjson"
    assert request["headers"]["Content-Encoding"] == "gzip"

    payload = _parse_json_lines(gzip.decompress(request["body"]))
    assert len(payload) == 1
    assert payload[0]["message"] == "hello gzip s3"
    assert payload[0]["source"] == "dummy"
    assert "date" in payload[0]


@pytest.mark.parametrize(
    ("signal_type", "json_file", "root_key", "expected_value"),
    [
        ("logs", "test_logs_001.in.json", "resourceLogs", "This is an example log message."),
        ("metrics", "test_metrics_001.in.json", "resourceMetrics", "requests_total"),
        ("traces", "test_traces_001.in.json", "resourceSpans", "checkout-span"),
    ],
)
def test_out_s3_otlp_json_uploads_signal_payloads(signal_type, json_file, root_key, expected_value):
    service = Service("out_s3_otlp_json.yaml")
    _start_or_skip_unsupported_s3_format(service, "format")
    _send_otlp_signal(service, signal_type, json_file)
    try:
        request = service.wait_for_request()
    except TimeoutError:
        if signal_type == "metrics" or signal_type == "traces":
            pytest.skip("otlp_json metrics or traces payload uploads are not emitted by this Fluent Bit binary")
        raise
    service.stop()

    assert request["method"] == "PUT"
    assert request["path"].startswith("/test-bucket/payloads/")
    assert request["headers"]["Content-Type"] == "application/json"

    payload = _parse_single_json_payload(request["body"])
    assert root_key in payload

    rendered = json.dumps(payload)
    assert expected_value in rendered


def test_out_s3_default_retry_exhausted_action_quarantines_file():
    store_dir = "/tmp/fluent-bit-test-suite-s3-retry-exhausted"
    if os.path.exists(store_dir):
        shutil.rmtree(store_dir)
    os.makedirs(store_dir, exist_ok=True)

    service = Service("out_s3_retry_exhausted_default_quarantine.yaml")
    service.start()
    timeout = time.time() + 10
    files = []
    while time.time() < timeout:
        files = [p for p in glob.glob(f"{store_dir}/**", recursive=True) if os.path.isfile(p)]
        if len(files) > 0:
            break
        time.sleep(0.2)
    service.stop()

    assert len(files) > 0


@pytest.mark.parametrize("action", ["quarantine", "delete", "quarantine_full"])
@pytest.mark.parametrize("preserve_ordering", [True, False])
def test_out_s3_multiworker_retry_exhaustion_survives_and_recovers(tmp_path, action, preserve_ordering):
    config = {
        "service": {
            "flush": 0.1,
            "grace": 1,
            "log_level": "info",
            "http_server": "on",
            "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}",
            "storage.path": str(tmp_path / "engine"),
        },
        "pipeline": {
            "inputs": [
                {"name": "dummy", "tag": tag, "rate": 20,
                 "storage.type": "filesystem",
                 "dummy": json.dumps({"message": "retry exhaustion", "source": tag})}
                for tag in ["journal", "app"]
            ],
            "outputs": [
                {
                    "name": "s3",
                    "match": "*",
                    "workers": 4,
                    "bucket": bucket,
                    "region": "us-east-1",
                    "endpoint": "http://127.0.0.1:${TEST_SUITE_HTTP_PORT}",
                    "use_put_object": True,
                    "preserve_data_ordering": preserve_ordering,
                    "retry_limit": 1,
                    "retry_exhausted_action": "delete" if action == "delete" else "quarantine",
                    "quarantine_dir_limit_size": "1" if action == "quarantine_full" else "0",
                    "total_file_size": "1M",
                    "upload_timeout": "1s",
                    "compression": "gzip",
                    "s3_key_format": "/$TAG/$UUID.gz",
                    "store_dir": str(tmp_path / bucket),
                    "store_dir_limit_size": "20M",
                }
                for bucket in ["first-bucket", "second-bucket"]
            ],
        },
    }
    config_file = tmp_path / "retry_exhaustion.yaml"

    if not preserve_ordering:
        # Leave active buffers behind to exercise put_all_chunks during restart.
        for input_config in config["pipeline"]["inputs"]:
            input_config["samples"] = 1
        for output_config in config["pipeline"]["outputs"]:
            output_config["upload_timeout"] = "60s"
        config_file.write_text(yaml.safe_dump(config))
        service = Service(str(config_file), put_status=403)
        service.start()
        service.service.wait_for_condition(
            lambda: all(len(list((tmp_path / bucket).glob("**/20*/*"))) >= 2
                        for bucket in ["first-bucket", "second-bucket"]),
            timeout=30, description="buffers for restart",
        )
        process = service.service.flb.process
        service.stop()
        assert process.returncode == 0
        for input_config in config["pipeline"]["inputs"]:
            del input_config["samples"]
        for output_config in config["pipeline"]["outputs"]:
            output_config["upload_timeout"] = "1s"

    config_file.write_text(yaml.safe_dump(config))
    service = Service(str(config_file), put_status=403, put_delay=0.1)
    service.start()

    def cleanup_completed():
        assert service.service.flb.process.poll() is None, "Fluent Bit crashed during retry exhaustion"
        logs = Path(service.service.flb.log_file).read_text()
        if action == "quarantine":
            return all(len(list((tmp_path / bucket).glob("**/quarantine/*"))) >= 2
                       for bucket in ["first-bucket", "second-bucket"])
        if action == "quarantine_full":
            marker = "quarantine limit reached, deleting retry-exhausted chunk"
        else:
            marker = "will not retry"
        return all(sum(f"[output:s3:s3.{index}]" in line and marker in line
                       for line in logs.splitlines()) >= 2 for index in [0, 1])

    service.service.wait_for_condition(
        cleanup_completed, timeout=60, interval=0.1, description="retry-exhausted chunks in both outputs"
    )
    # A successful upload after exhaustion proves workers can still use the store.
    data_storage["put_status"] = 200
    request_count = len(data_storage["requests"])

    def recovered():
        assert service.service.flb.process.poll() is None, "Fluent Bit crashed after retry exhaustion"
        return all(any(request["path"].startswith(f"/{bucket}/") and request.get("status") == 200
                       for request in data_storage["requests"][request_count:])
                   for bucket in ["first-bucket", "second-bucket"])

    service.service.wait_for_condition(
        recovered,
        timeout=30, description="uploads after permissions recover",
    )
    process = service.service.flb.process
    service.stop()
    assert process.returncode == 0
    # Read only after shutdown so no quarantine file is still being written.
    quarantined = {path: path.read_bytes() for path in tmp_path.glob("**/quarantine/*") if path.is_file()}

    # Restart using the same buffers, including quarantined files.
    service = Service(str(config_file))
    service.start()
    service.wait_for_request()
    process = service.service.flb.process
    service.stop()
    assert process.returncode == 0
    assert all(path.read_bytes() == content for path, content in quarantined.items())


@pytest.mark.parametrize("mode", ["put_unordered", "put_ordered", "put_index", "multipart",
                                  "put_refresh", "put_expiring"])
def test_out_s3_workers_upload_independent_tags_concurrently(tmp_path, mode):
    multipart = mode == "multipart"
    tags = ["first", "second"]
    config = {
        "service": {
            "flush": 0.1,
            "grace": 5,
            "log_level": "info",
            "http_server": "on",
            "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}",
        },
        "pipeline": {
            "inputs": [
                {"name": "dummy", "tag": tag, "rate": 10,
                 "samples": 2 if multipart else 0,
                 "dummy": json.dumps({"source": tag, "message": "x" * (3000000 if multipart else 100)})}
                for tag in tags
            ],
            "outputs": [{
                "name": "s3",
                "match": "*",
                "workers": 4,
                "bucket": "concurrent-bucket",
                "region": "us-east-1",
                "endpoint": "http://127.0.0.1:${TEST_SUITE_HTTP_PORT}",
                "use_put_object": not multipart,
                "preserve_data_ordering": mode != "put_unordered",
                # Use exact bytes: S3's multipart minimum is 5 MiB, not 5 MB.
                "total_file_size": "10485760" if multipart else "1048576",
                "upload_chunk_size": "5242880" if multipart else "524288",
                "upload_timeout": "120s" if multipart else "1s",
                "compression": "none" if multipart else "gzip",
                "s3_key_format": "/$TAG/$INDEX-$UUID" if mode == "put_index" else "/$TAG/$UUID",
                "store_dir": str(tmp_path / "store"),
            }],
        },
    }
    config_file = tmp_path / "concurrent_uploads.yaml"
    config_file.write_text(yaml.safe_dump(config))
    barrier = None if mode == "put_index" else TaggedUploadBarrier(tags)
    credential_mode = {"put_refresh": "refresh", "put_expiring": "expiring"}.get(mode)
    service = Service(str(config_file), put_delay=0.4, upload_barrier=barrier,
                      shutdown_timeout=30, credential_mode=credential_mode)
    service.start()

    def uploads_complete():
        assert service.service.flb.process.poll() is None
        uploads = [request for request in data_storage["requests"]
                   if request["method"] == "PUT" and request.get("status") == 200]
        expected = 1 if multipart else 2
        if all(sum(f"/{tag}/" in request["path"] for request in uploads) >= expected for tag in tags):
            return uploads
        return None

    uploads = service.service.wait_for_condition(
        uploads_complete, timeout=60, interval=0.1, description="uploads from both tags",
    )
    process = service.service.flb.process
    service.stop()
    assert process.returncode == 0

    overlaps = [(first, second) for index, first in enumerate(uploads)
                for second in uploads[index + 1:]
                if max(first["started"], second["started"]) < min(first["finished"], second["finished"])]
    if mode == "put_index":
        assert not overlaps, "$INDEX uploads must preserve global ordering"
    else:
        paired = [request for request in uploads if request.get("barrier_passed") is not None]
        assert len(paired) == len(tags)
        assert all(request["barrier_passed"] for request in paired), "Tagged uploads did not meet at barrier"
        assert overlaps, "Independent tags were serialized despite four output workers"
        for first, second in overlaps:
            assert first["path"].split("/")[2] != second["path"].split("/")[2]
    if multipart:
        initiations = [request for request in data_storage["requests"] if "upload_id" in request]
        assert len(initiations) == len(tags)
        upload_ids = {urlsplit(request["path"]).path: request["upload_id"] for request in initiations}
        assert len(set(upload_ids.values())) == len(tags)
        completions = []
        for request in data_storage["requests"]:
            parsed = urlsplit(request["path"])
            query = parse_qs(parsed.query)
            if request["method"] == "PUT" or "uploadId" in query:
                assert request["status"] == 200
                assert query["uploadId"] == [upload_ids[parsed.path]]
                if request["method"] == "PUT":
                    assert "partNumber" in query
                    tag = parsed.path.split("/")[2]
                    assert all(json.loads(line)["source"] == tag for line in request["body"].splitlines())
                else:
                    completions.append(parsed.path)
        assert sorted(completions) == sorted(upload_ids)
    if credential_mode:
        assert data_storage["credential_requests"] > 1
        for request in data_storage["requests"]:
            _assert_rotating_credentials_signature(request)
        if credential_mode == "refresh":
            assert data_storage["auth_failures"] == set(tags)
            assert sum(request["status"] == 403 for request in data_storage["requests"]) == len(tags)


def _assert_rotating_credentials_signature(request):
    headers = {key.lower(): value for key, value in request["headers"].items()}
    algorithm, fields = headers["authorization"].split(" ", 1)
    fields = dict(field.strip().split("=", 1) for field in fields.split(","))
    access_key, scope = fields["Credential"].split("/", 1)
    generation = access_key.removeprefix("test-access-")
    assert headers["x-amz-security-token"] == f"test-token-{generation}"
    signed_headers = fields["SignedHeaders"]
    canonical_headers = "".join(f"{key}:{' '.join(headers[key].split())}\n"
                                for key in signed_headers.split(";"))
    parsed = urlsplit(request["path"])
    assert not parsed.query
    payload_hash = hashlib.sha256(request["body"]).hexdigest()
    canonical = "\n".join([request["method"], parsed.path, "", canonical_headers,
                            signed_headers, payload_hash])
    string_to_sign = "\n".join([algorithm, headers["x-amz-date"], scope,
                                 hashlib.sha256(canonical.encode()).hexdigest()])
    key = f"AWS4test-secret-{generation}".encode()
    for component in scope.split("/"):
        key = hmac.new(key, component.encode(), hashlib.sha256).digest()
    assert fields["Signature"] == hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()


@pytest.mark.parametrize("throttle", [False, True])
def test_out_s3_blob_and_log_uploads_keep_separate_ownership(tmp_path, throttle):
    small_blob = tmp_path / "small.bin"
    large_blob = tmp_path / "large.bin"
    small_blob.write_bytes(b"small blob")
    large_blob.write_bytes(b"b" * 6000000)
    config = {
        "service": {
            "flush": 0.1, "grace": 5, "log_level": "info",
            "http_server": "on", "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}",
        },
        "pipeline": {
            "inputs": [
                {"name": "dummy", "tag": "logs", "rate": 10,
                 "dummy": '{"message":"concurrent log"}'},
                {"name": "blob", "tag": "blobs", "path": str(tmp_path / "*.bin"),
                 "database_file": str(tmp_path / "input.db"), "scan_refresh_interval": "1s"},
            ],
            "outputs": [{
                "name": "s3", "match": "*", "workers": 4,
                "bucket": "mixed-bucket", "region": "us-east-1",
                "endpoint": "http://127.0.0.1:${TEST_SUITE_HTTP_PORT}",
                "use_put_object": True, "total_file_size": "1048576",
                "throttle": throttle,
                "upload_timeout": "1s", "s3_key_format": "/$TAG/$UUID",
                "store_dir": str(tmp_path / "store"),
                "blob_database_file": str(tmp_path / "output.db"),
                "part_size": "5242880", "upload_parts_timeout": "1s",
                "part_delivery_attempt_limit": 1,
            }],
        },
    }
    config_file = tmp_path / "mixed_uploads.yaml"
    config_file.write_text(yaml.safe_dump(config))

    def slow_first_part(request):
        if request["method"] == "DELETE" and "denied-abort" in request["path"]:
            return 403, b"<Error><Code>AccessDenied</Code></Error>", []
        if "partNumber=1" in request["path"] and not any(
            req.get("status") == 503 for req in data_storage["requests"]
        ):
            return _s3_slow_down(delay=2)
        return None

    service = Service(str(config_file), put_delay=0.2, shutdown_timeout=30,
                      response_override=slow_first_part if throttle else None)
    service.start()

    if throttle:
        # Model an exhausted multipart blob recovered from the output database.
        with sqlite3.connect(tmp_path / "output.db") as db:
            file_id = db.execute(
                "INSERT INTO blob_files(tag,source,destination,path,remote_id,size,created,"
                "delivery_attempts,aborted) VALUES(?,?,?,?,?,?,?,99,1)",
                ("blobs", "blob.1", "", str(tmp_path / "expired"), "denied-abort", 2, 1),
            ).lastrowid
            db.executemany("INSERT INTO blob_parts(file_id,part_id,offset_start,offset_end) "
                           "VALUES(?,?,?,?)", [(file_id, 0, 0, 1), (file_id, 1, 1, 2)])
        abort = _s3_completed_requests(service, lambda r: r["method"] == "DELETE", 1)[0]
        assert abort["status"] == 403
        (tmp_path / "after.bin").write_bytes(b"after denied abort")
        _s3_completed_requests(service, lambda r: r["body"] == b"after denied abort"
                               and r.get("status") == 200, 1)

    def uploads_complete():
        assert service.service.flb.process.poll() is None
        requests_seen = data_storage["requests"]
        return (any(request["method"] == "POST" and "uploadId=" in request["path"]
                    and request.get("status") == 200 for request in requests_seen)
                and any(request["method"] == "PUT" and request["body"] == b"small blob"
                        and request.get("status") == 200 for request in requests_seen)
                and any("/logs/" in request["path"] and request.get("status") == 200
                        for request in requests_seen))

    service.service.wait_for_condition(uploads_complete, timeout=60,
                                       description="blob multipart completion alongside log uploads")
    process = service.service.flb.process
    service.stop()
    assert process.returncode == 0
    initiations = [request for request in data_storage["requests"] if "upload_id" in request]
    assert len(initiations) == 1
    upload_id = initiations[0]["upload_id"]
    parts = [request for request in data_storage["requests"]
             if "partNumber=" in request["path"] and request.get("status") == 200]
    assert len(parts) == 2
    failed = None
    if throttle:
        [failed] = [req for req in data_storage["requests"] if req.get("status") == 503]
        [retried] = [req for req in parts if req["path"] == failed["path"]]
        assert retried["started"] - failed["finished"] >= 1.9
        assert retried["body"] == failed["body"]
    part_bodies = {}
    for request in parts:
        part_number = int(parse_qs(urlsplit(request["path"]).query)["partNumber"][0])
        assert part_number not in part_bodies
        part_bodies[part_number] = request["body"]
    assert sorted(part_bodies) == [1, 2]
    assert b"".join(part_bodies[number] for number in sorted(part_bodies)) == large_blob.read_bytes()
    completions = [request for request in data_storage["requests"]
                   if request["method"] == "POST" and "uploadId=" in request["path"]]
    assert len(completions) == 1
    for request in data_storage["requests"]:
        query = parse_qs(urlsplit(request["path"]).query)
        if "uploadId" in query and request["method"] != "DELETE":
            assert query["uploadId"] == [upload_id]
            assert request["status"] == (503 if request is failed else 200)


def test_out_s3_blob_refund_survives_blocked_shutdown(tmp_path):
    config = _s3_throttle_config(tmp_path)
    settings = yaml.safe_load(config.read_text())
    database = tmp_path / "blobs.db"
    payload = tmp_path / "refund.bin"
    body = b"refund after restart"
    payload.write_bytes(body)
    # The seeded row already owns refund.bin. Keep its notification recipient
    # active without letting the scanner enqueue the same payload a second time.
    settings["pipeline"]["inputs"] = [{
        "name": "blob", "tag": "routed", "path": str(tmp_path / "*.pending"),
        "database_file": str(tmp_path / "input.db"), "upload_success_action": "delete",
    }]
    settings["pipeline"]["outputs"][0].update(blob_database_file=str(database), upload_parts_timeout="1s")
    config.write_text(yaml.safe_dump(settings))

    first = Service(str(config), response_override=lambda req: _s3_slow_down(delay=1))
    try:
        first.start()
        with sqlite3.connect(database) as db:
            db.execute("CREATE TRIGGER block_refund BEFORE UPDATE OF in_progress ON blob_parts "
                       "WHEN OLD.in_progress=1 AND NEW.in_progress=0 "
                       "BEGIN SELECT RAISE(ABORT, 'refund blocked'); END")
            file_id = db.execute(
                "INSERT INTO blob_files(tag,source,destination,path,size,created,delivery_attempts) "
                "VALUES(?,?,?,?,?,1,2)", ("routed", "blob.0", "127.0.0.1", str(payload), payload.stat().st_size),
            ).lastrowid
            db.execute("INSERT INTO blob_parts(file_id,part_id,offset_start,offset_end,delivery_attempts) "
                       "VALUES(?,0,0,?,3)", (file_id, payload.stat().st_size))
        _s3_completed_requests(first, lambda r: r.get("status") == 503, 1)
        process = first.service.flb.process
        first.stop()
        assert process.returncode == 1
        with sqlite3.connect(database) as db:
            assert db.execute("SELECT part_attempts,file_attempts FROM s3_blob_claims").fetchall() == [(3, 2)]
            assert db.execute("SELECT in_progress,delivery_attempts FROM blob_parts").fetchall() == [(1, 4)]
            db.execute("DROP TRIGGER block_refund")
    finally:
        first.stop()

    attempts = []

    def inspect_retry(req):
        with sqlite3.connect(database) as db:
            attempts.extend(db.execute("SELECT part_attempts,file_attempts FROM s3_blob_claims"))

    second = Service(str(config), response_override=inspect_retry)
    try:
        second.start()
        sent = _s3_completed_requests(second, lambda req: req["method"] == "PUT", 1)[0]
        assert sent["body"] == body
        assert attempts == [(3, 2)]
        second.service.wait_for_condition(lambda: not payload.exists(),
                                          description="blob input received the delivery notification")
        process = second.service.flb.process
    finally:
        second.stop()
    assert process.returncode == 0


def test_out_s3_format_arrow_uploads_feather_with_zstd():
    service = Service("out_s3_arrow.yaml")
    _start_or_skip_unsupported_columnar_format(service, "requires arrow-glib")
    request = service.wait_for_request()
    service.stop()

    assert request["method"] == "PUT"
    assert request["path"].startswith("/test-bucket/payloads/out_s3/")
    body = request["body"]
    # Arrow/Feather V2 files begin with the "ARROW1" magic. The object is the
    # columnar file itself, so it must not carry a byte-level Content-Encoding.
    assert body[:6] == b"ARROW1"
    assert "Content-Encoding" not in request["headers"]


def test_out_s3_format_parquet_uploads_parquet_with_zstd():
    service = Service("out_s3_parquet.yaml")
    _start_or_skip_unsupported_columnar_format(service, "requires parquet-glib")
    request = service.wait_for_request()
    service.stop()

    assert request["method"] == "PUT"
    assert request["path"].startswith("/test-bucket/payloads/out_s3/")
    body = request["body"]
    # Parquet files start and end with the "PAR1" magic. Page-level zstd is
    # applied inside the file, so no byte-level Content-Encoding is expected.
    assert body[:4] == b"PAR1"
    assert body[-4:] == b"PAR1"
    assert "Content-Encoding" not in request["headers"]


def test_out_s3_format_parquet_compression_none_is_accepted():
    # 'compression none' must be explicitly accepted (not rejected as an
    # unknown codec) and produce an uncompressed Parquet object with no
    # byte-level Content-Encoding header.
    service = Service("out_s3_parquet_none.yaml")
    _start_or_skip_unsupported_columnar_format(service, "requires parquet-glib")
    request = service.wait_for_request()
    service.stop()

    assert request["method"] == "PUT"
    body = request["body"]
    assert body[:4] == b"PAR1"
    assert body[-4:] == b"PAR1"
    assert "Content-Encoding" not in request["headers"]


def test_out_s3_format_arrow_compression_none_is_accepted():
    # 'compression none' must be explicitly accepted (not rejected as an
    # unknown codec) and produce an uncompressed Arrow/Feather object with no
    # byte-level Content-Encoding header.
    service = Service("out_s3_arrow_none.yaml")
    _start_or_skip_unsupported_columnar_format(service, "requires arrow-glib")
    request = service.wait_for_request()
    service.stop()

    assert request["method"] == "PUT"
    body = request["body"]
    assert body[:6] == b"ARROW1"
    assert "Content-Encoding" not in request["headers"]


def test_out_s3_format_arrow_compression_gzip_is_rejected():
    # format=arrow with compression=gzip is an invalid combination;
    # validate_format_compression() must reject it at plugin init.
    service = Service("out_s3_arrow_gzip_invalid.yaml")
    with pytest.raises(FluentBitStartupError):
        service.start()
    service.stop()
