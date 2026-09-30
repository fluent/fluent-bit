import os

import pytest

from utils.data_utils import read_file
from utils.fluent_bit_manager import FluentBitStartupError
from utils.test_service import FluentBitTestService


INPUT = """pipeline:
  inputs:
    - name: dummy
      tag: include.test
      dummy: '{"message":"include-selected"}'
      samples: 1
"""

MASTER = """service:
  flush: 1
  grace: 1
  http_server: on
  http_port: ${FLUENT_BIT_HTTP_MONITORING_PORT}
pipeline:
  outputs:
    - name: stdout
      match: '*'
      format: json_lines
"""


def write_master(path, include):
    # Single quotes preserve Windows backslashes in YAML scalars.
    path.write_text(
        "includes:\n  - '" + include.replace("'", "''") + "'\n" + MASTER,
        encoding="utf-8",
    )


@pytest.mark.parametrize("location", [
    "parent", "cwd", "parent_precedence", "nested_cwd",
    "absolute_forward", "absolute_backslash", "rooted_backslash",
])
def test_yaml_include_resolution(tmp_path, monkeypatch, location):
    if location in ("absolute_backslash", "rooted_backslash") and os.name != "nt":
        pytest.skip("Windows path syntax")

    config_dir = tmp_path / "config"
    working_dir = tmp_path / "working"
    config_dir.mkdir()
    working_dir.mkdir()
    master = config_dir / "master.yaml"
    include = "extra.yaml"

    if location in ("parent", "parent_precedence"):
        (config_dir / include).write_text(INPUT, encoding="utf-8")
        if location == "parent_precedence":
            (working_dir / include).write_text("invalid: [", encoding="utf-8")
    elif location == "nested_cwd":
        nested = working_dir / "nested"
        nested.mkdir()
        include = "nested/extra.yaml"
        (nested / "extra.yaml").write_text("includes:\n  - child.yaml\n", encoding="utf-8")
        (nested / "child.yaml").write_text(INPUT, encoding="utf-8")
    else:
        included_file = working_dir / include
        if location != "cwd":
            absolute_dir = tmp_path / "absolute"
            absolute_dir.mkdir()
            included_file = absolute_dir / include
            included_file.write_text("includes:\n  - child.yaml\n", encoding="utf-8")
            (absolute_dir / "child.yaml").write_text(INPUT, encoding="utf-8")
        else:
            included_file.write_text(INPUT, encoding="utf-8")
        if location == "absolute_forward":
            include = included_file.as_posix()
        elif location == "absolute_backslash":
            include = str(included_file)
        elif location == "rooted_backslash":
            include = str(included_file)[len(included_file.drive):]

    write_master(master, include)
    monkeypatch.chdir(working_dir)
    service = FluentBitTestService(str(master))
    try:
        service.start()
        service.wait_for_condition(
            lambda: "include-selected" in read_file(service.flb.log_file),
            timeout=15,
            description="record from the included input",
        )
    finally:
        service.stop()


@pytest.mark.parametrize("invalid_parent", [False, True])
def test_yaml_include_failure(tmp_path, monkeypatch, invalid_parent):
    config_dir = tmp_path / "config"
    working_dir = tmp_path / "working"
    config_dir.mkdir()
    working_dir.mkdir()
    master = config_dir / "master.yaml"
    write_master(master, "extra.yaml")
    if invalid_parent:
        # An existing but malformed parent-relative file must not be bypassed.
        (config_dir / "extra.yaml").write_text("invalid: [", encoding="utf-8")
        (working_dir / "extra.yaml").write_text(INPUT, encoding="utf-8")

    monkeypatch.chdir(working_dir)
    service = FluentBitTestService(str(master))
    try:
        with pytest.raises(FluentBitStartupError):
            service.start()
        assert "extra.yaml" in read_file(service.flb.log_file)
    finally:
        service.stop()
