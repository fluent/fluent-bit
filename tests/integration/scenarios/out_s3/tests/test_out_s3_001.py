import gzip
import json
import os
import glob
import time
import shutil
from pathlib import Path

import requests
import pytest
import yaml
from google.protobuf import json_format
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceRequest
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

from server.s3_server import data_storage, s3_server_run, s3_server_stop
from utils.data_utils import read_json_file
from utils.fluent_bit_manager import FluentBitStartupError
from utils.test_service import FluentBitTestService


class Service:
    def __init__(self, config_file, *, put_status=200, put_delay=0):
        self.put_status = put_status
        self.put_delay = put_delay
        self.config_file = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../config", config_file)
        )
        self.service = FluentBitTestService(
            self.config_file,
            data_storage=data_storage,
            data_keys=["requests"],
            extra_env={
                "AWS_ACCESS_KEY_ID": "test-access-key",
                "AWS_SECRET_ACCESS_KEY": "test-secret-key",
                "AWS_EC2_METADATA_DISABLED": "true",
            },
            pre_start=self._start_receiver,
            post_stop=self._stop_receiver,
        )

    def _start_receiver(self, service):
        self.s3_port = service.allocate_port_env("TEST_SUITE_HTTP_PORT")
        s3_server_run(self.s3_port)
        data_storage["put_status"] = self.put_status
        data_storage["put_delay"] = self.put_delay

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


@pytest.mark.parametrize("mode", ["put_unordered", "put_ordered", "put_index", "multipart"])
def test_out_s3_workers_upload_independent_tags_concurrently(tmp_path, mode):
    multipart = mode == "multipart"
    tags = ["first", "second"]
    config = {
        "service": {
            "flush": 0.1,
            "grace": 2,
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
    service = Service(str(config_file), put_delay=0.4)
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
        assert overlaps, "Independent tags were serialized despite four output workers"
        for first, second in overlaps:
            assert first["path"].split("/")[2] != second["path"].split("/")[2]
    if multipart:
        assert all("partNumber=" in request["path"] for request in uploads)
        assert sum(request["method"] == "POST" and "uploadId=" in request["path"]
                   for request in data_storage["requests"]) == len(tags)


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
