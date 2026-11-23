"""A Windows byte-range lock must not corrupt tail state or lose records."""

import ctypes
from ctypes import wintypes
import json
import os
import sys
import time

import pytest

from utils.test_service import FluentBitTestService


def process_cpu_seconds(pid):
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = kernel32.OpenProcess(0x1000, False, pid)
    assert handle, ctypes.get_last_error()
    times = [wintypes.FILETIME() for _ in range(4)]
    try:
        assert kernel32.GetProcessTimes(handle, *(ctypes.byref(t) for t in times))
        return sum((t.dwHighDateTime << 32) | t.dwLowDateTime for t in times[2:]) / 10_000_000
    finally:
        kernel32.CloseHandle(handle)


@pytest.mark.skipif(sys.platform != "win32", reason="requires Windows byte-range locks")
@pytest.mark.parametrize("partial,startup", [(False, False), (True, False), (False, True)],
                         ids=["empty-buffer", "partial-line", "static-file"])
def test_tail_recovers_after_read_lock(tmp_path, partial, startup):
    import msvcrt

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    for name in ("LockFile", "UnlockFile"):
        function = getattr(kernel32, name)
        function.argtypes = [wintypes.HANDLE] + [wintypes.DWORD] * 4
        function.restype = wintypes.BOOL

    target = tmp_path / "input.log"
    target.write_bytes(b"before\n")
    healthy = tmp_path / "input-healthy.log"
    healthy.touch()
    output = tmp_path / "output.json"
    config = tmp_path / "tail.yaml"
    config.write_text(f"""
service:
  flush: 0.2
  grace: 1
  log_level: debug
  http_server: on
  http_port: ${{FLUENT_BIT_HTTP_MONITORING_PORT}}
pipeline:
  inputs:
    - name: tail
      path: {target.as_posix()},{healthy.as_posix()}
      read_from_head: true
      refresh_interval: 60
      watcher_interval: 1
      progress_check_interval: 1
      buffer_max_size: 128k
  outputs:
    - name: file
      match: '*'
      path: {tmp_path.as_posix()}
      file: {output.name}
      format: plain
""")

    def records():
        if not output.exists():
            return []
        return [json.loads(line)["log"]
                for line in output.read_text().splitlines(keepends=True)
                if line.endswith("\n")]

    service = FluentBitTestService(str(config))
    try:
        if not startup:
            service.start()
            service.wait_for_condition(lambda: records() == ["before"])
        with target.open("r+b", buffering=0) as writer:
            if not startup:
                writer.seek(0, os.SEEK_END)
            if partial:
                writer.write(b"par")
                # Allow the stat watcher to buffer the unfinished line.
                time.sleep(3)
            position = writer.tell()
            handle = msvcrt.get_osfhandle(writer.fileno())
            assert kernel32.LockFile(handle, position, 0, 4096, 0), ctypes.get_last_error()
            try:
                if startup:
                    service.start()
                else:
                    writer.write(b"tial\n" if partial else b"after\n")
                # Verify that a different handle really encounters EACCES.
                with target.open("rb", buffering=0) as reader:
                    reader.seek(position)
                    with pytest.raises(PermissionError):
                        reader.read(1)
                healthy.write_bytes(b"healthy\n")
                locked_records = ["healthy"] if startup else ["before", "healthy"]
                service.wait_for_condition(lambda: records() == locked_records)
                cpu_before = process_cpu_seconds(service.flb.process.pid)
                time.sleep(5)
                assert service.flb.process.poll() is None, "tail crashed on a locked read"
                cpu_used = process_cpu_seconds(service.flb.process.pid) - cpu_before
                assert cpu_used < 1.0, f"locked tail consumed {cpu_used:.2f} CPU seconds in 5s"
                assert records() == locked_records
            finally:
                assert kernel32.UnlockFile(handle, position, 0, 4096, 0), ctypes.get_last_error()
            expected = (["healthy", "before"] if startup else
                        ["before", "healthy", "partial" if partial else "after"])
            service.wait_for_condition(lambda: records() == expected, timeout=15)
            writer.seek(0, os.SEEK_END)
            writer.write(b"final\n")
            service.wait_for_condition(lambda: records() == expected + ["final"], timeout=15)
    finally:
        service.stop()
