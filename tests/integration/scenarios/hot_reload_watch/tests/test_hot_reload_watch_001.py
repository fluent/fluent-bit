#  Fluent Bit
#  ==========
#  Copyright (C) 2015-2024 The Fluent Bit Authors
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
import logging
import os
import shutil
import tempfile
import time

import pytest
import requests
from google.protobuf import json_format

from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
from src.server.otlp_server import data_storage, otlp_server_run
from src.utils.fluent_bit_manager import FluentBitManager
from src.utils.network import find_available_port

logger = logging.getLogger(__name__)


class Service:
    def __init__(self, before_name, after_name):
        self.test_path = os.path.dirname(os.path.abspath(__file__))
        self.config_dir = os.path.abspath(os.path.join(self.test_path, "../config"))
        self.before_config = os.path.join(self.config_dir, before_name)
        self.after_config = os.path.join(self.config_dir, after_name)
        self.runtime_dir = tempfile.mkdtemp(prefix="flb-hot-reload-watch-")
        self.runtime_config = os.path.join(self.runtime_dir, "fluent-bit.yaml")
        data_storage["logs"] = []

    def start(self):
        shutil.copyfile(self.before_config, self.runtime_config)

        self.flb = FluentBitManager(self.runtime_config)
        self.test_suite_http_port = find_available_port(starting_port=50000)
        os.environ["TEST_SUITE_HTTP_PORT"] = str(self.test_suite_http_port)
        logger.info(f"test suite http port: {self.test_suite_http_port}")

        otlp_server_run(self.test_suite_http_port)

        url = f"http://127.0.0.1:{self.test_suite_http_port}/ping"
        start_time = time.time()
        while time.time() - start_time < 10:
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    break
            except requests.exceptions.ConnectionError:
                pass
            time.sleep(0.5)

        self.flb.start()

    def stop(self):
        if getattr(self, "flb", None) is not None and self.flb.process is not None:
            self.flb.stop()
        requests.post(f"http://127.0.0.1:{self.test_suite_http_port}/shutdown")
        shutil.rmtree(self.runtime_dir, ignore_errors=True)

    def wait_for_log_count(self, expected_count, timeout=15):
        start_time = time.time()

        while time.time() - start_time < timeout:
            if len(data_storage["logs"]) >= expected_count:
                return
            time.sleep(0.5)

        raise TimeoutError(f"Timed out waiting for {expected_count} log payloads")

    def read_message(self, index):
        request = data_storage["logs"][index]
        json_str = json_format.MessageToJson(request)
        payload = json.loads(json_str)
        return payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["body"]["stringValue"]

    def replace_config(self):
        pending_path = os.path.join(self.runtime_dir, "fluent-bit.yaml.tmp")
        shutil.copyfile(self.after_config, pending_path)
        os.replace(pending_path, self.runtime_config)


def assert_reload_result(service):
    service.wait_for_log_count(2)
    assert service.read_message(1) == "after"


def test_hot_reload_watch_yaml_config_change():
    service = Service("fluent-bit-before.yaml", "fluent-bit-after.yaml")

    try:
        service.start()
        service.wait_for_log_count(1)
        assert service.read_message(0) == "before"

        service.replace_config()
        service.flb.wait_for_hot_reload_count(1)
        assert_reload_result(service)
    finally:
        service.stop()


def test_hot_reload_sighup_yaml_config_change():
    service = Service("fluent-bit-manual-before.yaml", "fluent-bit-manual-after.yaml")

    try:
        service.start()
        service.wait_for_log_count(1)
        assert service.read_message(0) == "before"

        service.replace_config()

        with pytest.raises(TimeoutError):
            service.flb.wait_for_hot_reload_count(1, timeout=2)

        service.flb.send_sighup()
        service.flb.wait_for_hot_reload_count(1)
        assert_reload_result(service)
    finally:
        service.stop()


def test_hot_reload_http_yaml_config_change():
    service = Service("fluent-bit-manual-before.yaml", "fluent-bit-manual-after.yaml")

    try:
        service.start()
        service.wait_for_log_count(1)
        assert service.read_message(0) == "before"

        service.replace_config()

        with pytest.raises(TimeoutError):
            service.flb.wait_for_hot_reload_count(1, timeout=2)

        payload = service.flb.trigger_http_reload()
        assert payload["reload"] == "done"
        service.flb.wait_for_hot_reload_count(1)
        assert_reload_result(service)
    finally:
        service.stop()
