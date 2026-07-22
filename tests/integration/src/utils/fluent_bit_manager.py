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
import platform
from pathlib import Path
import signal
import shutil
import subprocess
import tempfile
import time

import requests

from utils.network import find_available_port, wait_for_port_to_be_free
from utils.leaks import assert_leaks_clean
from utils.memory_check import leaks_enabled, memory_check_enabled, valgrind_enabled
from utils.valgrind import assert_valgrind_clean

ENV_FLB_HTTP_MONITORING_PORT = "FLUENT_BIT_HTTP_MONITORING_PORT"
ENV_FLB_BINARY_PATH = "FLUENT_BIT_BINARY"
LEAKS_TARGET_PID_TIMEOUT = 10
LEAKS_EXIT_TIMEOUT = 120

LEAKS_EXEC_SCRIPT = (
    'printf "%s\\n" "$$" > "$1"; output_file="$2"; shift 2; '
    'exec "$@" >> "$output_file" 2>&1'
)

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


def _resolve_binary_path(binary_path=None):
    selected_path = binary_path or os.environ.get(ENV_FLB_BINARY_PATH) or _default_binary_path()
    return shutil.which(selected_path) or os.path.abspath(selected_path)


def fluent_bit_binary_supports_config_property(property_name, binary_path=None):
    resolved_path = _resolve_binary_path(binary_path)
    property_marker = property_name.lower()

    try:
        result = subprocess.run(
            [resolved_path, "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        help_output = f"{result.stdout}\n{result.stderr}".lower()
        if property_marker in help_output:
            return True
    except OSError:
        pass

    try:
        binary_contents = Path(resolved_path).read_bytes().lower()
    except OSError:
        return False

    return property_marker.encode("utf-8") in binary_contents


def fluent_bit_input_supports_config_property(plugin_name, property_name, binary_path=None):
    resolved_path = _resolve_binary_path(binary_path)
    property_marker = property_name.lower()

    try:
        result = subprocess.run(
            [resolved_path, "-i", plugin_name, "-h"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return False

    help_output = f"{result.stdout}\n{result.stderr}".lower()
    return property_marker in help_output


class FluentBitManager:
    def __init__(self, config_path=None, binary_path=None):
        logger.info(f"config path {config_path}")
        self.config_path = config_path
        self.binary_path = binary_path or os.environ.get(ENV_FLB_BINARY_PATH) or _default_binary_path()
        self.binary_absolute_path = _resolve_binary_path(self.binary_path)
        self.process = None
        self.http_monitoring_port = None
        self.results_dir = None
        self.log_file = None
        self.valgrind_log_file = None
        self.leaks_log_file = None
        self.leaks_target_pid_file = None
        self.target_pid = None
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
        self.leaks_log_file = os.path.join(out_dir, "leaks.log")
        self.leaks_target_pid_file = os.path.join(out_dir, "leaks_target.pid")
        self.set_http_monitoring_port(ENV_FLB_HTTP_MONITORING_PORT)

        if valgrind_enabled() and leaks_enabled():
            raise FluentBitStartupError("VALGRIND and LEAKS cannot be enabled together")

        version, commit = self.get_version_info()
        logger.info(f'Fluent Bit info')
        logger.info(f' version    : {version}')
        logger.info(f' path       : {self.binary_absolute_path}')
        logger.info(f" config file: {self.config_path}")
        logger.info(f" logfile    : {self.log_file}")
        logger.info(f" http port  : {self.http_monitoring_port}")
        logger.info(f" commit     : {commit}")
        if valgrind_enabled():
            logger.info(f" valgrind   : {self.valgrind_log_file}")
        if leaks_enabled():
            logger.info(f" leaks      : {self.leaks_log_file}")

        command = [
            self.binary_absolute_path,
            "-c", self.config_path,
            "-l", self.log_file
        ]

        if valgrind_enabled():
            command = [
                "valgrind",
                f"--log-file={self.valgrind_log_file}",
                "--leak-check=full",
                "--show-leak-kinds=all"
            ] + command

        if leaks_enabled():
            command = self._build_leaks_command(command)

        logger.info(f"Running command {command}")

        output_path = self.leaks_log_file if leaks_enabled() else self.log_file
        self.output_handle = open(output_path, "a", encoding="utf-8")
        self.process = subprocess.Popen(
            command,
            stdout=self.output_handle,
            stderr=subprocess.STDOUT,
        )

        if leaks_enabled():
            self.target_pid = self._wait_for_leaks_target_pid()
        else:
            self.target_pid = self.process.pid

        logger.info(
            f"Fluent Bit started (pid: {self.target_pid}, supervisor pid: {self.process.pid})"
        )

        # wait for Fluent Bit to start
        self.wait_for_fluent_bit()

    def stop(self):
        if not self.process:
            return

        pid = self.target_pid or self.process.pid
        return_code = self.process.poll()
        supervisor_running = self.process.poll() is None
        if supervisor_running or (leaks_enabled() and self.target_pid):
            self.send_signal(signal.SIGTERM)

        if supervisor_running:
            try:
                timeout = LEAKS_EXIT_TIMEOUT if leaks_enabled() else 10
                return_code = self.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self._force_stop()
                return_code = self.process.returncode
        self.process = None
        self.target_pid = None

        if self.output_handle:
            self.output_handle.close()
            self.output_handle = None

        if self.http_monitoring_port:
            timeout = 10 if memory_check_enabled() else 5
            wait_for_port_to_be_free(int(self.http_monitoring_port), timeout=timeout)

        if valgrind_enabled() and os.environ.get("VALGRIND_STRICT"):
            assert_valgrind_clean(self.valgrind_log_file)

        if leaks_enabled() and os.environ.get("LEAKS_STRICT"):
            assert_leaks_clean(return_code, self.leaks_log_file)

        logger.info(f"Fluent Bit stopped (pid: {pid})")

    def send_signal(self, signal_number):
        if not self.process:
            raise RuntimeError("Fluent Bit is not running")

        if leaks_enabled():
            if not self.target_pid:
                raise RuntimeError("Fluent Bit target PID is unavailable")
            try:
                os.kill(self.target_pid, signal_number)
            except ProcessLookupError:
                pass
        else:
            self.process.send_signal(signal_number)

    def send_sighup(self):
        self.send_signal(signal.SIGHUP)

    def get_reload_status(self):
        url = f"http://127.0.0.1:{self.http_monitoring_port}/api/v2/reload"
        response = requests.get(url, timeout=0.5)
        response.raise_for_status()
        return response.json()

    def trigger_http_reload(self):
        url = f"http://127.0.0.1:{self.http_monitoring_port}/api/v2/reload"
        response = requests.post(url)
        response.raise_for_status()
        return response.json()

    def wait_for_hot_reload_count(self, expected_count, timeout=10):
        deadline = time.time() + timeout

        while time.time() < deadline:
            try:
                payload = self.get_reload_status()
                if payload.get("hot_reload_count", 0) >= expected_count:
                    return payload
            except requests.RequestException:
                pass
            time.sleep(0.1)

        raise TimeoutError(f"Timed out waiting for hot reload count {expected_count}")

    def _build_leaks_command(self, command):
        if platform.system() != "Darwin":
            raise FluentBitStartupError("LEAKS is only supported on macOS")

        leaks_binary = shutil.which("leaks")
        if not leaks_binary:
            raise FluentBitStartupError("The macOS leaks command was not found")

        return [
            leaks_binary,
            "--quiet",
            "--fullStacks",
            "--atExit",
            "--",
            "/bin/sh",
            "-c",
            LEAKS_EXEC_SCRIPT,
            "fluent-bit-leaks-target",
            self.leaks_target_pid_file,
            self.log_file,
        ] + command

    def _wait_for_leaks_target_pid(self):
        deadline = time.time() + LEAKS_TARGET_PID_TIMEOUT

        while time.time() < deadline:
            try:
                pid_text = Path(self.leaks_target_pid_file).read_text(encoding="utf-8").strip()
                target_pid = int(pid_text)
                if target_pid > 0:
                    return target_pid
            except (FileNotFoundError, ValueError):
                pass

            if self.process.poll() is not None:
                raise FluentBitStartupError(
                    f"leaks exited before Fluent Bit started with code {self.process.returncode}. "
                    f"See log file {self.leaks_log_file}"
                )
            time.sleep(0.05)

        raise FluentBitStartupError(
            f"Timed out waiting for the Fluent Bit PID from leaks. See {self.leaks_log_file}"
        )

    def _force_stop(self):
        if leaks_enabled() and self.target_pid:
            try:
                os.kill(self.target_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=10)
                return
            except subprocess.TimeoutExpired:
                pass

        self.process.kill()
        self.process.wait(timeout=5)

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
        os.makedirs(base_dir, exist_ok=True)
        return tempfile.mkdtemp(prefix=f"fluent_bit_results_{timestamp}_", dir=base_dir)

    # Check if Fluent Bit is running by trying to reach the uptime endpoint, it waits until
    # the value of `uptime_sec` is greater than 1
    def wait_for_fluent_bit(self, timeout=None):
        if timeout is None:
            timeout = 30 if memory_check_enabled() else 10
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
