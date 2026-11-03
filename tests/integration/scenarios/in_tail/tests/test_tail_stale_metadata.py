"""A stale size must not replay content whose saved offset marker still matches."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

import pytest

from utils.test_service import FluentBitTestService


@pytest.fixture(scope="module")
def stale_fstat_library(tmp_path_factory):
    if sys.platform != "linux":
        pytest.skip("stale metadata injection requires Linux LD_PRELOAD")
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("stale metadata injection requires a C compiler")
    library = tmp_path_factory.mktemp("tail-stale-fstat") / "stale_fstat.so"
    subprocess.run(
        [compiler, "-shared", "-fPIC", "-Wall", "-Wextra", "-o", str(library),
         str(Path(__file__).with_name("stale_fstat.c")), "-ldl"],
        check=True,
    )
    return library


@pytest.mark.parametrize("database", [False, True], ids=["no-db", "db"])
def test_stale_size_does_not_replay_records(tmp_path, stale_fstat_library, database):
    target = tmp_path / "input.log"
    target.write_text("before\n")
    armed = tmp_path / "armed"
    output = tmp_path / "output.json"
    config = tmp_path / "tail.yaml"
    db_config = f"      db: {tmp_path}/tail.db\n" if database else ""
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
      path: {target}
      read_from_head: true
      inotify_watcher: false
{db_config}  outputs:
    - name: file
      match: '*'
      path: {tmp_path}
      file: {output.name}
      format: plain
""")
    preload = str(stale_fstat_library)
    if os.environ.get("LD_PRELOAD"):
        preload += ":" + os.environ["LD_PRELOAD"]
    service = FluentBitTestService(str(config), extra_env={
        "LD_PRELOAD": preload,
        "TAIL_TEST_STALE_TARGET": target,
        "TAIL_TEST_STALE_ARMED": armed,
        "TAIL_TEST_STALE_SIZE": target.stat().st_size,
    })

    def logs():
        if not output.exists():
            return []
        return [json.loads(line)["log"] for line in output.read_text().splitlines()]

    try:
        service.start()
        service.wait_for_condition(
            lambda: logs() == ["before"], timeout=10, interval=0.05,
            description="initial record delivery",
        )
        # Reads see the append, but fstat keeps reporting the previous size.
        # Keep this state through both the read callback and the 2.5 s stat check.
        armed.touch()
        with target.open("a") as writer:
            writer.write("after\n")
        time.sleep(3)
        armed.unlink()
        with target.open("a") as writer:
            writer.write("final\n")
        service.wait_for_condition(
            lambda: "final" in logs(), timeout=10, interval=0.05,
            description="delivery after metadata catches up",
        )
    finally:
        service.stop()
    assert "tail test: stale size injected" in Path(service.flb.log_file).read_text()
    assert logs() == ["before", "after", "final"]
