"""Issue #12617: pending collection must not hide copytruncate from watchers."""

import os
from contextlib import closing
import sqlite3
import sys
import time
from pathlib import Path

import pytest

from utils.test_service import FluentBitTestService


def read_positions(pid, log_dir):
    positions = {}
    for entry in Path(f"/proc/{pid}/fd").iterdir():
        try:
            target = Path(os.readlink(entry))
            if target.parent != log_dir:
                continue
            info = Path(f"/proc/{pid}/fdinfo/{entry.name}").read_text()
            positions[target] = int(info.split("pos:", 1)[1].split()[0])
        except (FileNotFoundError, OSError):
            continue
    return positions


def wait_for_positions(pid, log_dir, targets, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        positions = read_positions(pid, log_dir)
        stale = {path.name: (positions.get(path), path.stat().st_size)
                 for path in targets
                 if positions.get(path) != path.stat().st_size}
        if not stale:
            return
        time.sleep(0.05)
    pytest.fail(f"tail failed to read content (offset, size): {stale}")


def wait_for_db_offsets(db_path, targets, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with closing(sqlite3.connect(db_path, timeout=1)) as db:
            offsets = dict(db.execute("SELECT name, offset FROM in_tail_files"))
        stale = {path.name: (offsets.get(str(path)), path.stat().st_size)
                 for path in targets
                 if offsets.get(str(path)) != path.stat().st_size}
        if not stale:
            return
        time.sleep(0.05)
    pytest.fail(f"tail failed to persist offsets (offset, size): {stale}")


@pytest.mark.skipif(sys.platform != "linux", reason="uses Linux /proc fd positions")
@pytest.mark.parametrize("inotify", [False, True], ids=["stat", "inotify"])
@pytest.mark.parametrize("replacement", [b"", b"after-truncate\n"], ids=["empty", "short"])
@pytest.mark.parametrize("initial_mode", ["complete", "partial", "buffered"])
def test_copytruncate_with_pending_collector(tmp_path, inotify, replacement, initial_mode):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    targets = [log_dir / f"target-{i}.log" for i in range(32)]
    initial = ("before " + "x" * 120 + "\n") * 512
    retained_prefix = b""
    if initial_mode == "partial":
        # No complete line means there is no persisted offset marker.
        initial = "x" * 512
    elif initial_mode == "buffered":
        # Preserve the resumable marker while truncating buffered bytes beyond it.
        retained_prefix = initial.encode()
        initial += "x" * 512
    for target in targets:
        target.write_text(initial)
    busy = log_dir / "busy.log"
    busy.touch()
    config = tmp_path / "tail.yaml"
    config.write_text(f"""
service:
  flush: 1
  grace: 1
  log_level: debug
  http_server: on
  http_port: ${{FLUENT_BIT_HTTP_MONITORING_PORT}}
pipeline:
  inputs:
    - name: tail
      path: {log_dir}/*.log
      read_from_head: true
      refresh_interval: 1
      watcher_interval: 1
      progress_check_interval: 1
      inotify_watcher: {str(inotify).lower()}
      buffer_chunk_size: 1k
      buffer_max_size: 2k
      db: {tmp_path}/tail.db
  outputs:
    - name: null
      match: '*'
""")
    service = FluentBitTestService(str(config))
    try:
        service.start()
        pid = service.flb.process.pid
        wait_for_positions(pid, log_dir, targets, timeout=30)

        # Force pending collection to walk caught-up files while another file
        # has a backlog. The small buffers keep that backlog observable.
        busy.write_bytes((("busy " + "x" * 1000 + "\n") * 8192).encode())
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            offset = read_positions(pid, log_dir).get(busy, 0)
            # Stat events alone read at most 1 KiB every 250 ms. More than
            # 16 KiB here means the pending collector has started draining.
            if 16384 < offset < busy.stat().st_size:
                break
            time.sleep(0.001)
        else:
            pytest.fail("did not observe busy-file backlog")
        for target in targets:
            with target.open("wb") as handle:
                handle.write(retained_prefix + replacement)
        wait_for_positions(pid, log_dir, targets)

        # Recovery must also reset the persisted stream offset and continue
        # consuming ordinary appends after an empty or nonempty truncation.
        for target in targets:
            with target.open("ab") as handle:
                handle.write(b"next-line\n")
        wait_for_positions(pid, log_dir, targets)
        wait_for_db_offsets(tmp_path / "tail.db", targets)
    finally:
        service.stop()
