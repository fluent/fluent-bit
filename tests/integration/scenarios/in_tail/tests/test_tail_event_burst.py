"""Bursts of appends across many monitored files must be delivered exactly once.

The files are written while they are in event mode, which exercises how the
file system notifications are batched and how the pending data is scheduled:
no file can be starved and no record can be lost or duplicated, also when some
of the files are rotated in the middle of the burst.
"""

from collections import Counter
import json

import pytest

from utils.test_service import FluentBitTestService

FILES = 200
ROUNDS = 6
LINES_PER_WRITE = 5


def read_records(output):
    if not output.exists():
        return Counter()
    # A flush can still be writing the final JSON line while we poll.
    lines = [line for line in output.read_text().splitlines(keepends=True)
             if line.endswith("\n")]
    return Counter(json.loads(line)["log"] for line in lines)


@pytest.mark.parametrize("inotify", [True, False], ids=["inotify", "stat"])
@pytest.mark.parametrize("database", [False, True], ids=["no-db", "db"])
def test_event_burst_across_many_files(tmp_path, inotify, database):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    targets = [log_dir / f"app-{i:03d}.log" for i in range(FILES)]
    for target in targets:
        target.touch()
    output = tmp_path / "output.json"
    config = tmp_path / "tail.yaml"
    db_config = f"      db: {tmp_path}/tail.db\n" if database else ""
    config.write_text(f"""
service:
  flush: 0.2
  grace: 2
  log_level: info
  http_server: on
  http_port: ${{FLUENT_BIT_HTTP_MONITORING_PORT}}
pipeline:
  inputs:
    - name: tail
      path: {log_dir}/*.log
      read_from_head: true
      refresh_interval: 1
      rotate_wait: 5
      inotify_watcher: {str(inotify).lower()}
      buffer_chunk_size: 1k
      buffer_max_size: 4k
{db_config}  outputs:
    - name: file
      match: '*'
      path: {tmp_path}
      file: {output.name}
      format: plain
""")
    service = FluentBitTestService(str(config))
    expected = Counter()
    handles = [target.open("ab", buffering=0) for target in targets]

    def write_round(round_id):
        for index, handle in enumerate(handles):
            payload = ""
            for line in range(LINES_PER_WRITE):
                record = f"file={index:03d} round={round_id} line={line} " + "x" * 300
                expected[record] += 1
                payload += record + "\n"
            # One write per file: more data than what fits in the read buffer.
            handle.write(payload.encode())

    try:
        service.start()
        # Let the (empty) files be promoted to event mode.
        service.wait_for_condition(
            lambda: service.flb.process.poll() is None, timeout=5, interval=0.5,
            description="service running",
        )
        write_round(0)
        service.wait_for_condition(
            lambda: read_records(output) == expected, timeout=60, interval=0.1,
            description="records of the first round",
        )

        for round_id in range(1, ROUNDS):
            write_round(round_id)
            if round_id == ROUNDS // 2:
                # Rotate one of every four files: the writer keeps appending
                # to the old descriptor for one more round.
                rotated = []
                for index in range(0, FILES, 4):
                    targets[index].rename(f"{targets[index]}.1")
                    rotated.append(index)
                write_round(f"{round_id}-after-rotation")
                for index in rotated:
                    handles[index].close()
                    handles[index] = targets[index].open("ab", buffering=0)

        service.wait_for_condition(
            lambda: read_records(output) == expected, timeout=90, interval=0.1,
            description="every record delivered exactly once",
        )
    finally:
        for handle in handles:
            handle.close()
        service.stop()
    assert read_records(output) == expected
