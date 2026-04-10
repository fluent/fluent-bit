import os
import time

import requests

from utils.fluent_bit_manager import FluentBitManager
from utils.network import find_available_port


class FluentBitTestService:
    def __init__(
        self,
        config_path,
        *,
        data_storage=None,
        data_keys=None,
        extra_env=None,
        pre_start=None,
        post_stop=None,
    ):
        self.config_path = config_path
        self.data_storage = data_storage
        self.data_keys = data_keys or []
        self.extra_env = extra_env or {}
        self.pre_start = pre_start
        self.post_stop = post_stop
        self.flb = None
        self._previous_env = {}

    def _reset_storage(self):
        if not self.data_storage:
            return
        for key in self.data_keys:
            self.data_storage[key] = []

    def _set_env(self, key, value):
        self._previous_env.setdefault(key, os.environ.get(key))
        os.environ[key] = value

    def allocate_port_env(self, key, *, starting_port=0):
        port = find_available_port(starting_port)
        self._set_env(key, str(port))
        return port

    def _restore_env(self):
        for key, value in self._previous_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self._previous_env.clear()

    def start(self):
        self._reset_storage()
        self.flb = FluentBitManager(self.config_path)
        self.flb_listener_port = find_available_port()
        self.test_suite_http_port = find_available_port()
        self._set_env("FLUENT_BIT_TEST_LISTENER_PORT", str(self.flb_listener_port))
        self._set_env("TEST_SUITE_HTTP_PORT", str(self.test_suite_http_port))

        for key, value in self.extra_env.items():
            self._set_env(key, str(value))

        if self.pre_start:
            self.pre_start(self)

        self.flb.start()

    def stop(self):
        try:
            if self.flb:
                self.flb.stop()
        finally:
            if self.post_stop:
                self.post_stop(self)
            self._restore_env()

    def wait_for_http_endpoint(self, url, *, timeout=10, interval=0.5):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                response = requests.get(url, timeout=interval)
                if response.status_code == 200:
                    return
            except requests.RequestException:
                pass
            time.sleep(interval)
        raise TimeoutError(f"Timed out waiting for endpoint {url}")

    def wait_for_condition(self, predicate, *, timeout=10, interval=0.5, description="condition"):
        deadline = time.time() + timeout
        while time.time() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(interval)
        raise TimeoutError(f"Timed out waiting for {description}")
