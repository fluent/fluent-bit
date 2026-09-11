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

from utils import fluent_bit_manager as manager_module
from utils import test_service as service_module
from utils.fluent_bit_manager import ENV_FLB_HTTP_MONITORING_PORT
from utils.fluent_bit_manager import FluentBitManager
from utils.test_service import FluentBitTestService


def test_service_reserves_distinct_monitoring_port(monkeypatch):
    allocated_ports = iter([31001, 31002, 31001, 31003])

    monkeypatch.delenv(ENV_FLB_HTTP_MONITORING_PORT, raising=False)
    monkeypatch.setattr(
        service_module,
        "find_available_port",
        lambda starting_port=0: next(allocated_ports),
    )
    monkeypatch.setattr(manager_module, "find_available_port", lambda starting_port=0: 31001)
    monkeypatch.setattr(
        FluentBitManager,
        "start",
        lambda manager: manager.set_http_monitoring_port(ENV_FLB_HTTP_MONITORING_PORT),
    )

    service = FluentBitTestService("/tmp/fluent-bit.yaml")

    try:
        service.start()

        assert service.flb_listener_port == 31001
        assert service.test_suite_http_port == 31002
        assert int(service.flb.http_monitoring_port) not in {
            service.flb_listener_port,
            service.test_suite_http_port,
        }
    finally:
        service.stop()
