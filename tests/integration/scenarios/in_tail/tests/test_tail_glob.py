import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from test_in_tail_001 import Service, assert_log_set


@pytest.mark.parametrize("mode", ["native", "tilde", "windows-utf8"])
def test_in_tail_glob_nested_paths(tmp_path, mode):
    if mode == "tilde" and sys.platform == "win32":
        pytest.skip("tilde expansion is a POSIX glob feature")
    if mode == "windows-utf8" and sys.platform != "win32":
        pytest.skip("Windows-only path API mode")

    first = tmp_path / ("run-\U0001f600" if mode == "windows-utf8" else "run-a")
    second = tmp_path / "run-b"
    outside = tmp_path / "outside"
    for directory in (first, second, outside):
        directory.mkdir()

    (first / "events-1.log").write_bytes(b"first\n")
    (second / "events-2.log").write_bytes(b"second\n")
    (second / "done.txt").write_bytes(b"literal-suffix\n")
    (outside / "events-3.log").write_bytes(b"outside-pattern\n")

    base = Path("~") if mode == "tilde" else tmp_path
    patterns = [str(base / "run-*" / name) for name in ("events-*.log", "done.txt")]
    output_config = tmp_path / "tail_glob.yaml"
    encoding = "      windows.path_encoding: utf-8\n" if mode == "windows-utf8" else ""
    output_config.write_text(
        f"""service:
  flush: 1
  grace: 1
  http_server: on
  http_port: ${{FLUENT_BIT_HTTP_MONITORING_PORT}}
pipeline:
  inputs:
    - name: tail
      path: ${{TAIL_TEST_PATH}}
      read_from_head: true
{encoding}  outputs:
    - name: http
      match: '*'
      host: 127.0.0.1
      port: ${{TEST_SUITE_HTTP_PORT}}
      uri: /data
      format: json
      json_date_key: false
""",
        encoding="utf-8",
    )

    service = Service(output_config, tail_path=",".join(patterns), db_path=tmp_path / "unused.db")
    if mode == "tilde":
        service.service.extra_env["HOME"] = str(tmp_path)

    try:
        service.start()
        assert_log_set(service.wait_for_records(3), ["first", "second", "literal-suffix"])
        service.assert_no_new_records_for(3)
    finally:
        service.stop()


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux LD_PRELOAD")
def test_in_tail_glob_matches_age_at_end_of_scan(tmp_path):
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("slow glob injection requires a C compiler")

    library = tmp_path / "slow_glob.so"
    subprocess.run(
        [compiler, "-shared", "-fPIC", "-Wall", "-Wextra", "-o", str(library),
         str(Path(__file__).with_name("slow_glob.c")), "-ldl"],
        check=True,
    )

    target = tmp_path / "ages-during-glob.log"
    target.write_bytes(b"too old by the end of globbing\n")
    service = Service("tail_ignore_older.yaml", tail_path=target, db_path=tmp_path / "tail.db")
    preload = os.pathsep.join(filter(None, (str(library), os.getenv("LD_PRELOAD"))))
    service.service.extra_env.update({
        "LD_PRELOAD": preload,
        "TAIL_TEST_SLOW_GLOB_PATH": target,
    })

    try:
        service.start()
        service.assert_no_new_records_for(0)
        log = Path(service.flb.log_file).read_text(encoding="utf-8")
        assert f"excluded={target} (ignore_older)" in log
    finally:
        service.stop()
