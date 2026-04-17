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

import datetime
import logging
import os
from pathlib import Path
import shutil
import subprocess
import time

import requests

from utils.network import find_available_port, wait_for_port_to_be_free
from utils.valgrind import assert_valgrind_clean

ENV_FLB_HTTP_MONITORING_PORT = "FLUENT_BIT_HTTP_MONITORING_PORT"

logger = logging.getLogger(__name__)

class FluentBitStartupError(RuntimeError):
    pass


def _default_binary_path():
    repo_root = Path(__file__).resolve().parents[4]
    local_binary = repo_root / "build" / "bin" / "fluent-bit"
    if local_binary.is_file():
        return str(local_binary)

    binary_from_path = shutil.which("fluent-bit")
    if binary_from_path:
        return binary_from_path

    return str(local_binary)


class FluentBitManager:
    def __init__(self, config_path=None, binary_path=None):
        logger.info(f"config path {config_path}")
        self.config_path = config_path
        self.binary_path = binary_path or os.environ.get("FLUENT_BIT_BINARY") or _default_binary_path()
        self.binary_absolute_path = os.path.abspath(self.binary_path)
        self.process = None
        self.http_monitoring_port = None
        self.results_dir = None
        self.log_file = None
        self.valgrind_log_file = None
        self.output_handle = None

    def set_http_monitoring_port(self, env_var_name, starting_port=0):
        port = find_available_port(starting_port)
        os.environ[env_var_name] = str(port)
        self.http_monitoring_port = str(port)

    def start(self):
        if not self.config_path or not os.path.exists(self.config_path):
            raise FileNotFoundError(f"Config file {self.config_path} does not exist")
        if not os.path.isfile(self.binary_absolute_path):
            raise FileNotFoundError(
                f"Fluent Bit binary {self.binary_absolute_path} does not exist. "
                "Set FLUENT_BIT_BINARY or build build/bin/fluent-bit."
            )
        if not os.access(self.binary_absolute_path, os.X_OK):
            raise PermissionError(f"Fluent Bit binary {self.binary_absolute_path} is not executable")

        # create temporary directory for logs
        out_dir = self.create_results_directory()
        self.results_dir = out_dir
        self.log_file = os.path.join(out_dir, "fluent_bit.log")
        self.valgrind_log_file = os.path.join(out_dir, "valgrind.log")
        self.set_http_monitoring_port(ENV_FLB_HTTP_MONITORING_PORT)

        version, commit = self.get_version_info()
        logger.info(f'Fluent Bit info')
        logger.info(f' version    : {version}')
        logger.info(f' path       : {self.binary_absolute_path}')
        logger.info(f" config file: {self.config_path}")
        logger.info(f" logfile    : {self.log_file}")
        logger.info(f" http port  : {self.http_monitoring_port}")
        logger.info(f" commit     : {commit}")
        if self.valgrind_log_file:
            logger.info(f" valgrind   : {self.valgrind_log_file}")

        command = [
            self.binary_absolute_path,
            "-c", self.config_path,
            "-l", self.log_file
        ]

        valgrind = os.environ.get('VALGRIND', False)
        if valgrind:
            command = [
                "valgrind",
                f"--log-file={self.valgrind_log_file}",
                "--leak-check=full",
                "--show-leak-kinds=all"
            ] + command


        logger.info(f"Running command {command}")

        self.output_handle = open(self.log_file, "a", encoding="utf-8")
        self.process = subprocess.Popen(
            command,
            stdout=self.output_handle,
            stderr=subprocess.STDOUT,
            text=True,
        )
        logger.info(f"Fluent Bit started (pid: {self.process.pid})")

        # wait for Fluent Bit to start
        self.wait_for_fluent_bit()

    def stop(self):
        if not self.process:
            return

        pid = self.process.pid
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.process = None

        if self.output_handle:
            self.output_handle.close()
            self.output_handle = None

        if self.http_monitoring_port:
            wait_for_port_to_be_free(int(self.http_monitoring_port), timeout=10 if os.environ.get("VALGRIND") else 5)

        if os.environ.get("VALGRIND") and os.environ.get("VALGRIND_STRICT"):
            assert_valgrind_clean(self.valgrind_log_file)

        logger.info(f"Fluent Bit stopped (pid: {pid})")

    def get_version_info(self):
        try:
            result = subprocess.run(
                [self.binary_absolute_path, '--version'],
                capture_output=True,
                text=True,
                check=True,
            )
            output = result.stdout.strip().split('\n')
            version = output[0].replace('Fluent Bit ', '').strip()
            commit = output[1].strip().replace('Git commit: ', '') if len(output) > 1 else "unknown"
            return version, commit
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.error("Error running Fluent Bit: %s", e)
            raise FluentBitStartupError(f"Unable to execute Fluent Bit binary {self.binary_absolute_path}") from e

    def create_results_directory(self, base_dir=None):
        if base_dir is None:
            suite_root = Path(__file__).resolve().parents[2]
            base_dir = suite_root / "results"
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        results_dir = os.path.join(base_dir, f"fluent_bit_results_{timestamp}")
        os.makedirs(results_dir, exist_ok=True)
        return results_dir

    # Check if Fluent Bit is running by trying to reach the uptime endpoint, it waits until
    # the value of `uptime_sec` is greater than 1
    def wait_for_fluent_bit(self, timeout=None):
        if timeout is None:
            timeout = 30 if os.environ.get("VALGRIND") else 10
        url = f"http://127.0.0.1:{self.http_monitoring_port}/api/v1/uptime"
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.process and self.process.poll() is not None:
                raise FluentBitStartupError(
                    f"Fluent Bit exited early with code {self.process.returncode}. "
                    f"See log file {self.log_file}"
                )
            try:
                response = requests.get(url, timeout=0.5)
                logger.info(f"Fluent Bit health check: {response.status_code}")

                if response.status_code == 200:
                    uptime = response.json().get('uptime_sec', 0)
                    if uptime > 1:
                        logger.info("Fluent Bit is running, health check OK")
                        return True
            except requests.ConnectionError:
                # it's ok to fail, we are testing
                pass

            time.sleep(1)

        raise FluentBitStartupError(
            f"Fluent Bit did not start within {timeout} seconds. See log file {self.log_file}"
        )
