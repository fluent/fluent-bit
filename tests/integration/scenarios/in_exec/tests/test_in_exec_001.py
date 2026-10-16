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

import os
from pathlib import Path
import signal
import sys
import tempfile
import time

import pytest

from utils.fluent_bit_manager import FluentBitManager


def wait_for_child_pid(pid_file, previous_pid=None, timeout=10):
    deadline = time.time() + timeout

    while time.time() < deadline:
        try:
            child_pid = int(pid_file.read_text(encoding="utf-8").strip())
            if child_pid > 0 and child_pid != previous_pid:
                return child_pid
        except (FileNotFoundError, ValueError):
            pass

        time.sleep(0.1)

    raise TimeoutError("Timed out waiting for the exec child PID")


def process_exists(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False

    return True


def wait_for_process_exit(pid, timeout=10):
    deadline = time.time() + timeout

    while time.time() < deadline:
        if not process_exists(pid):
            return True
        time.sleep(0.1)

    return False


@pytest.mark.skipif(sys.platform == "win32", reason="requires POSIX signals and tail")
def test_threaded_exec_hot_reload_stops_blocking_child():
    test_path = Path(__file__).resolve().parent
    config_path = test_path.parent / "config" / "threaded_hot_reload.yaml"
    child_pids = []
    new_child_pid = None
    shutdown_child_exited = False

    with tempfile.TemporaryDirectory(prefix="flb-in-exec-") as runtime_dir:
        pid_file = Path(runtime_dir) / "child.pid"
        previous_pid_file = os.environ.get("EXEC_CHILD_PID_FILE")
        os.environ["EXEC_CHILD_PID_FILE"] = str(pid_file)
        manager = FluentBitManager(str(config_path))

        try:
            manager.start()
            old_child_pid = wait_for_child_pid(pid_file)
            child_pids.append(old_child_pid)

            manager.send_sighup()
            manager.wait_for_hot_reload_count(1, timeout=30)

            new_child_pid = wait_for_child_pid(pid_file, old_child_pid)
            child_pids.append(new_child_pid)
            assert wait_for_process_exit(old_child_pid)
        finally:
            try:
                manager.stop()
                if new_child_pid is not None:
                    shutdown_child_exited = wait_for_process_exit(new_child_pid)
            finally:
                if previous_pid_file is None:
                    os.environ.pop("EXEC_CHILD_PID_FILE", None)
                else:
                    os.environ["EXEC_CHILD_PID_FILE"] = previous_pid_file

                for child_pid in child_pids:
                    if process_exists(child_pid):
                        os.kill(child_pid, signal.SIGKILL)

        assert shutdown_child_exited
