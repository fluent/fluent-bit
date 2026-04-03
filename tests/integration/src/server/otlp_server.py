#  Fluent Bit
#  ==========
#  Copyright (C) 2015-2026 The Fluent Bit Authors
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import gzip
import logging
import subprocess
import threading
import time
from concurrent import futures

import grpc
from flask import Flask, Response, jsonify, request
from google.protobuf.message import DecodeError
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import (
    ExportLogsServiceRequest,
    ExportLogsServiceResponse,
)
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import (
    ExportMetricsServiceRequest,
    ExportMetricsServiceResponse,
)
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
    ExportTraceServiceRequest,
    ExportTraceServiceResponse,
)
from werkzeug.serving import make_server

app = Flask(__name__)
data_storage = {"traces": [], "metrics": [], "logs": [], "requests": []}
response_config = {
    "status_code": 200,
    "body": {"status": "received"},
    "content_type": "application/json",
    "delay_seconds": 0,
}
grpc_method_paths = {
    "logs": "/opentelemetry.proto.collector.logs.v1.LogsService/Export",
    "metrics": "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export",
    "traces": "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
}
logger = logging.getLogger(__name__)

server_thread = None
http_server_instance = None
grpc_server_instance = None
shutdown_flag = threading.Event()


def reset_otlp_server_state():
    for key in data_storage:
        data_storage[key] = []
    response_config.update(
        {
            "status_code": 200,
            "body": {"status": "received"},
            "content_type": "application/json",
            "delay_seconds": 0,
        }
    )
    grpc_method_paths.update(
        {
            "logs": "/opentelemetry.proto.collector.logs.v1.LogsService/Export",
            "metrics": "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export",
            "traces": "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
        }
    )
    shutdown_flag.clear()


def configure_otlp_response(*, status_code=None, body=None, content_type=None, delay_seconds=None):
    if status_code is not None:
        response_config["status_code"] = status_code
    if body is not None:
        response_config["body"] = body
    if content_type is not None:
        response_config["content_type"] = content_type
    if delay_seconds is not None:
        response_config["delay_seconds"] = delay_seconds


def configure_otlp_grpc_methods(*, logs=None, metrics=None, traces=None):
    if logs is not None:
        grpc_method_paths["logs"] = logs
    if metrics is not None:
        grpc_method_paths["metrics"] = metrics
    if traces is not None:
        grpc_method_paths["traces"] = traces


def _build_response():
    if response_config["delay_seconds"]:
        time.sleep(response_config["delay_seconds"])

    body = response_config["body"]
    if isinstance(body, (dict, list)):
        return jsonify(body), response_config["status_code"]

    return Response(
        body,
        status=response_config["status_code"],
        content_type=response_config["content_type"],
    )


def _record_request(*, path, headers, raw_payload, transport):
    data_storage["requests"].append(
        {
            "path": path,
            "headers": dict(headers),
            "raw_size": len(raw_payload),
            "raw_payload": raw_payload,
            "transport": transport,
        }
    )


def _decode_payload(raw_payload, headers):
    if headers.get("Content-Encoding", "").lower() == "gzip":
        return gzip.decompress(raw_payload)
    if headers.get("Content-Encoding", "").lower() == "zstd":
        result = subprocess.run(
            ["zstd", "-d", "-c"],
            input=raw_payload,
            capture_output=True,
            check=True,
        )
        return result.stdout
    return raw_payload


def _parse_http_signal(signal_name, message_type):
    try:
        decoded_payload = _decode_payload(request.data, request.headers)
        otlp_request = message_type()
        otlp_request.ParseFromString(decoded_payload)
        data_storage[signal_name].append(otlp_request)
        _record_request(
            path=request.path,
            headers=request.headers,
            raw_payload=request.data,
            transport="http",
        )
        return _build_response()
    except DecodeError:
        return jsonify({"status": "invalid protobuf"}), 400


def _guess_http_signal(path):
    lowered_path = path.lower()

    if "metrics" in lowered_path:
        return "metrics", ExportMetricsServiceRequest
    if "traces" in lowered_path:
        return "traces", ExportTraceServiceRequest

    return "logs", ExportLogsServiceRequest


@app.route("/shutdown", methods=["POST"])
def shutdown():
    shutdown_flag.set()
    logger.info("OTLP Server is shutting down...")

    if http_server_instance is not None:
        threading.Thread(target=http_server_instance.shutdown, daemon=True).start()

    return jsonify({"status": "shutting down"}), 200


@app.route("/v1/traces", methods=["POST"])
def traces():
    return _parse_http_signal("traces", ExportTraceServiceRequest)


@app.route("/v1/metrics", methods=["POST"])
def metrics():
    return _parse_http_signal("metrics", ExportMetricsServiceRequest)


@app.route("/v1/logs", methods=["POST"])
def logs():
    return _parse_http_signal("logs", ExportLogsServiceRequest)


@app.route("/", defaults={"dynamic_path": ""}, methods=["POST"])
@app.route("/<path:dynamic_path>", methods=["POST"])
def dynamic_signal(dynamic_path):
    signal_name, message_type = _guess_http_signal(f"/{dynamic_path}")
    return _parse_http_signal(signal_name, message_type)


@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({"status": "pong"}), 200


def run_server(port=4317, *, use_tls=False, tls_crt_file=None, tls_key_file=None):
    global http_server_instance

    ssl_context = None
    if use_tls:
        ssl_context = (tls_crt_file, tls_key_file)

    http_server_instance = make_server("0.0.0.0", port, app, ssl_context=ssl_context)
    http_server_instance.serve_forever()


def _build_grpc_handler(signal_name, message_type, response_type):
    def _handler(request_message, context):
        data_storage[signal_name].append(request_message)
        _record_request(
            path=context._rpc_event.call_details.method.decode(),
            headers=context.invocation_metadata(),
            raw_payload=request_message.SerializeToString(),
            transport="grpc",
        )
        return response_type()

    return grpc.unary_unary_rpc_method_handler(
        _handler,
        request_deserializer=message_type.FromString,
        response_serializer=response_type.SerializeToString,
    )


class DynamicOtlpGrpcHandler(grpc.GenericRpcHandler):
    def service(self, handler_call_details):
        method = handler_call_details.method

        if method == grpc_method_paths["logs"]:
            return _build_grpc_handler("logs", ExportLogsServiceRequest, ExportLogsServiceResponse)
        if method == grpc_method_paths["metrics"]:
            return _build_grpc_handler("metrics", ExportMetricsServiceRequest, ExportMetricsServiceResponse)
        if method == grpc_method_paths["traces"]:
            return _build_grpc_handler("traces", ExportTraceServiceRequest, ExportTraceServiceResponse)
        if "logs" in method.lower():
            return _build_grpc_handler("logs", ExportLogsServiceRequest, ExportLogsServiceResponse)
        if "metrics" in method.lower():
            return _build_grpc_handler("metrics", ExportMetricsServiceRequest, ExportMetricsServiceResponse)
        if "traces" in method.lower():
            return _build_grpc_handler("traces", ExportTraceServiceRequest, ExportTraceServiceResponse)

        return None


def run_grpc_server(port=4317, *, use_tls=False, tls_crt_file=None, tls_key_file=None):
    global grpc_server_instance

    grpc_server_instance = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    grpc_server_instance.add_generic_rpc_handlers((DynamicOtlpGrpcHandler(),))

    bind_address = f"0.0.0.0:{port}"
    if use_tls:
        with open(tls_key_file, "rb") as key_file:
            private_key = key_file.read()
        with open(tls_crt_file, "rb") as cert_file:
            certificate_chain = cert_file.read()
        credentials = grpc.ssl_server_credentials(((private_key, certificate_chain),))
        grpc_server_instance.add_secure_port(bind_address, credentials)
    else:
        grpc_server_instance.add_insecure_port(bind_address)

    grpc_server_instance.start()
    grpc_server_instance.wait_for_termination()


def stop_otlp_server():
    global grpc_server_instance
    global http_server_instance

    shutdown_flag.set()

    if http_server_instance is not None:
        http_server_instance.shutdown()
        http_server_instance = None

    if grpc_server_instance is not None:
        grpc_server_instance.stop(grace=0)
        grpc_server_instance = None


def otlp_server_run(port, *, use_tls=False, tls_crt_file=None, tls_key_file=None, use_grpc=False):
    global server_thread

    reset_otlp_server_state()
    logger.info("Starting OTLP server on port %s", port)
    server_thread = threading.Thread(
        target=run_grpc_server if use_grpc else run_server,
        kwargs={
            "port": port,
            "use_tls": use_tls,
            "tls_crt_file": tls_crt_file,
            "tls_key_file": tls_key_file,
        },
        daemon=True,
    )
    server_thread.start()
    return server_thread
