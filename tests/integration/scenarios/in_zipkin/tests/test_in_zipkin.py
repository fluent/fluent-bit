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

import json
import os
import time

import pytest
import requests

from utils.input_pause_resume import (
    assert_pause_resume_cycles,
    assert_shutdown_while_paused,
    open_stalled_tcp_connection,
)
from utils.test_service import FluentBitTestService


TRACE_ID = "463ac35c9f6413ad48485a3953bb6124"
SPAN_ID = "a2fb4a1d1a96d312"
PARENT_ID = "0020000000000001"


class Service:
    def __init__(self, config_name="zipkin.yaml"):
        config_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../config", config_name)
        )
        self.service = FluentBitTestService(config_path)

    def start(self):
        self.service.start()
        self.flb = self.service.flb
        self.port = self.service.flb_listener_port
        self.wait_for_log_message("listening for Zipkin v2 spans")

    def stop(self):
        self.service.stop()

    def wait_for_log_message(self, pattern, timeout=15, interval=0.25):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.flb.log_file and os.path.exists(self.flb.log_file):
                with open(self.flb.log_file, "r", encoding="utf-8", errors="replace") as log_file:
                    if pattern in log_file.read():
                        return
            time.sleep(interval)
        raise TimeoutError(f"Timed out waiting for log pattern: {pattern}")


def span_payload(name="checkout", extra_tags=None):
    tags = {
        "http.method": "GET",
        "attempt": "42",
        "cached": "true",
        "ratio": "1.5",
        "otel.scope.name": "zipkin-client",
        "otel.scope.version": "2.24.3",
        "otel.status_code": "ERROR",
        "otel.status_description": "upstream failed",
    }
    if extra_tags:
        tags.update(extra_tags)

    return [
        {
            "traceId": TRACE_ID,
            "id": SPAN_ID,
            "parentId": PARENT_ID,
            "name": name,
            "kind": "CLIENT",
            "timestamp": 1700000000000000,
            "duration": 2500,
            "debug": True,
            "shared": False,
            "localEndpoint": {
                "serviceName": "checkout-service",
                "ipv4": "127.0.0.1",
                "port": 8080,
            },
            "remoteEndpoint": {
                "serviceName": "payments",
                "ipv6": "2001:db8::1",
                "port": 443,
            },
            "tags": tags,
            "annotations": [
                {
                    "timestamp": 1700000000001000,
                    "value": "request sent",
                }
            ],
        }
    ]


def read_stdout_otlp_json(service, timeout=15, interval=0.25):
    deadline = time.time() + timeout
    decoder = json.JSONDecoder()

    while time.time() < deadline:
        if service.flb.log_file and os.path.exists(service.flb.log_file):
            with open(service.flb.log_file, "r", encoding="utf-8", errors="replace") as log_file:
                content = log_file.read()

            for offset, character in enumerate(content):
                if character != "{":
                    continue
                try:
                    value, _ = decoder.raw_decode(content[offset:])
                except json.JSONDecodeError:
                    continue
                if isinstance(value, dict) and "resourceSpans" in value:
                    return value

        time.sleep(interval)

    raise TimeoutError("Timed out waiting for Zipkin trace output")


def first_span(output):
    resource_span = output["resourceSpans"][0]
    scope_span = resource_span["scopeSpans"][0]
    span = scope_span["spans"][0]
    resource_attributes = {
        item["key"]: next(iter(item["value"].values()))
        for item in resource_span["resource"].get("attributes", [])
    }
    span_attributes = {
        item["key"]: next(iter(item["value"].values()))
        for item in span.get("attributes", [])
    }
    return resource_attributes, scope_span.get("scope", {}), span_attributes, span


@pytest.mark.parametrize(
    "config_name",
    ["zipkin_single.yaml", "zipkin.yaml"],
    ids=["single-listener", "workers-4"],
)
def test_in_zipkin_translates_v2_json_to_native_traces(config_name):
    service = Service(config_name)
    try:
        service.start()
        response = requests.post(
            f"http://127.0.0.1:{service.port}/api/v2/spans",
            json=span_payload(),
            timeout=10,
        )
        assert response.status_code == 202
        assert response.content == b""

        output = read_stdout_otlp_json(service)
        resource, scope, attributes, span = first_span(output)

        assert resource["service.name"] == "checkout-service"
        assert scope["name"] == "zipkin-client"
        assert scope["version"] == "2.24.3"
        assert span["traceId"] == TRACE_ID
        assert span["spanId"] == SPAN_ID
        assert span["parentSpanId"] == PARENT_ID
        assert span["name"] == "checkout"
        assert span["kind"] == 3
        assert span["startTimeUnixNano"] == "1700000000000000000"
        assert span["endTimeUnixNano"] == "1700000000002500000"
        assert span["status"] == {
            "message": "upstream failed",
            "code": "ERROR",
        }
        assert span["events"][0]["name"] == "request sent"
        assert span["events"][0]["timeUnixNano"] == "1700000000001000000"
        assert attributes["http.method"] == "GET"
        assert attributes["attempt"] == "42"
        assert attributes["cached"] is True
        assert attributes["ratio"] == 1.5
        assert attributes["service.peer.name"] == "payments"
        assert attributes["network.local.address"] == "127.0.0.1"
        assert attributes["network.local.port"] == "8080"
        assert attributes["network.peer.address"] == "2001:db8::1"
        assert attributes["network.peer.port"] == "443"
        assert attributes["zipkin.debug"] is True
        assert attributes["zipkin.shared"] is False
    finally:
        service.stop()


@pytest.mark.parametrize(
    "method,path,content_type,payload,status",
    [
        ("GET", "/api/v2/spans", "application/json", "[]", 405),
        ("POST", "/api/v1/spans", "application/json", "[]", 404),
        ("POST", "/api/v2/spans", "application/octet-stream", "[]", 415),
        ("POST", "/api/v2/spans", "application/json", "not-json", 400),
        ("POST", "/api/v2/spans", "application/json", "{}", 400),
        ("POST", "/api/v2/spans", "application/json", "[]", 202),
    ],
)
def test_in_zipkin_protocol_errors(method, path, content_type, payload, status):
    service = Service()
    try:
        service.start()
        response = requests.request(
            method,
            f"http://127.0.0.1:{service.port}{path}",
            data=payload,
            headers={"Content-Type": content_type},
            timeout=10,
        )
        assert response.status_code == status
        if status == 405:
            assert response.headers["Allow"] == "POST"
    finally:
        service.stop()


@pytest.mark.parametrize(
    "mutation",
    [
        {"traceId": "0" * 32},
        {"id": "not-a-span-id!!"},
        {"kind": "UNKNOWN"},
        {"timestamp": -1},
        {"localEndpoint": {"port": 70000}},
        {"tags": {"not": 42}},
        {"annotations": [{"timestamp": 1}]},
    ],
)
def test_in_zipkin_rejects_invalid_spans_atomically(mutation):
    service = Service()
    payload = span_payload()
    payload[0].update(mutation)
    try:
        service.start()
        response = requests.post(
            f"http://127.0.0.1:{service.port}/api/v2/spans",
            json=payload,
            timeout=10,
        )
        assert response.status_code == 400
    finally:
        service.stop()


def test_in_zipkin_pause_resume_and_shutdown():
    service = Service("zipkin_pause_resume.yaml")
    payload = json.dumps(span_payload(extra_tags={"padding": "x" * 8192}))
    resume_payload = json.dumps(span_payload(name="resumed"))
    try:
        service.start()

        def open_active_connections():
            return [
                open_stalled_tcp_connection("127.0.0.1", service.port)
                for _ in range(8)
            ]

        assert_pause_resume_cycles(
            service.flb,
            f"http://127.0.0.1:{service.port}/api/v2/spans",
            payload,
            ["Content-Type: application/json"],
            input_name="zipkin.0",
            success_status=202,
            cycles=1,
            pause_trigger_requests=32,
            resume_payload=resume_payload,
            resume_requests=1,
            active_connection_factory=open_active_connections,
        )

        assert_shutdown_while_paused(
            service.flb,
            service.stop,
            "127.0.0.1",
            service.port,
            f"http://127.0.0.1:{service.port}/api/v2/spans",
            payload,
            ["Content-Type: application/json"],
            input_name="zipkin.0",
            success_status=202,
            connection_factory=open_stalled_tcp_connection,
            pause_trigger_requests=32,
        )
    finally:
        service.stop()
