"""Legacy defaults follow links; explicit hardening rejects them."""

import json
import os
from pathlib import Path
import sys
import time

import pytest

from utils.filesystem import make_link
from utils.test_service import FluentBitTestService


def yaml_path(path):
    return "'" + str(path).replace("'", "''") + "'"


def run_config(tmp_path, inputs, outputs, ready, *, settle=2):
    config = tmp_path / "test.yaml"
    config.write_text(f"""
service:
  flush: 0.2
  grace: 1
  log_level: debug
  http_server: on
  http_port: ${{FLUENT_BIT_HTTP_MONITORING_PORT}}
pipeline:
  inputs:
{inputs}
  outputs:
{outputs}
""")
    service = FluentBitTestService(str(config))
    try:
        service.start()
        service.wait_for_condition(ready, timeout=30, interval=0.1)
        if settle:
            time.sleep(settle)
    finally:
        service.stop()
    return Path(service.flb.log_file).read_text()


@pytest.mark.parametrize("plugin", ["tail", "blob"])
@pytest.mark.parametrize("follow_symlinks", [None, True, False], ids=["default", "follow", "harden"])
@pytest.mark.parametrize("ancestor", [False, True], ids=["leaf", "directory"])
def test_input_symlink_policy(tmp_path, plugin, follow_symlinks, ancestor):
    source = tmp_path / "source"
    source.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (source / "regular.log").write_text("allowed\n")
    (outside / "secret.log").write_text("secret\n")
    if ancestor:
        make_link(source / "linked", outside, directory=True)
        linked = source / "linked" / "secret.log"
        patterns = [source / "*.log", source / "linked" / "*.log"]
    else:
        linked = source / "link.log"
        make_link(linked, outside / "secret.log")
        patterns = [source / "*.log"]
    output = tmp_path / "output"
    options = "      read_from_head: true\n" if plugin == "tail" else ""
    if follow_symlinks is not None:
        options += f"      follow_symlinks: {str(follow_symlinks).lower()}\n"
    # A second instance exercises a symlink ancestor, including glob expansion.
    inputs = "".join(f"""    - name: {plugin}
      path: {yaml_path(pattern)}
      tag: {plugin}.test
{options}""" for pattern in patterns)
    if plugin == "tail":
        outputs = f"""    - name: file
      match: '*'
      path: {yaml_path(tmp_path)}
      file: output
      format: plain"""
        run_config(tmp_path, inputs, outputs, lambda: output.exists())
        expected = ["allowed"] if follow_symlinks is False else ["allowed", "secret"]
        assert sorted(json.loads(line)["log"] for line in output.read_text().splitlines()) == expected
    else:
        # Blob registration is visible in the debug log without a cloud backend.
        log = run_config(tmp_path, inputs, "    - name: null\n      match: '*'", lambda: True)
        assert f"blob scan add: {source / 'regular.log'}," in log
        assert (f"blob scan add: {linked}," in log) == (follow_symlinks is not False)


@pytest.mark.parametrize("ancestor", [False, True], ids=["leaf", "directory"])
@pytest.mark.parametrize("dynamic", [False, True], ids=["static", "dynamic"])
@pytest.mark.parametrize("follow_symlinks", [None, True, False], ids=["default", "follow", "harden"])
def test_output_symlink_policy(tmp_path, ancestor, dynamic, follow_symlinks):
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "victim"
    victim.write_text("untouched\n")
    destination = tmp_path / "destination"
    destination.mkdir()
    if ancestor:
        make_link(destination / "link", outside, directory=True)
        filename = "link/victim"
    else:
        make_link(destination / "victim", victim)
        filename = "victim"
    configured_path = str(destination)
    if dynamic and ancestor:
        configured_path += "/$dirname"
        filename = "victim"
    configured_file = '$filename' if dynamic else filename
    policy = "" if follow_symlinks is None else f"      follow_symlinks: {str(follow_symlinks).lower()}\n"
    marker = tmp_path / "success"
    run_config(tmp_path, f"""    - name: dummy
      dummy: '{{"filename":"{filename}","dirname":"link","message":"data"}}'
      samples: 1""", f"""    - name: file
      match: '*'
      path: {yaml_path(configured_path)}
      file: '{configured_file}'
{policy}      mkdir: true
      fallback_file: fallback
      format: plain
    - name: file
      match: '*'
      path: {yaml_path(tmp_path)}
      file: success
      format: plain""", lambda: marker.exists())
    if follow_symlinks is False:
        assert victim.read_text() == "untouched\n"
    else:
        assert "data" in victim.read_text()
    assert "data" in marker.read_text()


@pytest.mark.parametrize(
    ("follow_symlinks", "seed"),
    [(None, False), (True, False), (False, False), (False, True)],
    ids=["default", "follow", "harden-append", "harden-rotate"],
)
def test_rotation_symlink_policy(tmp_path, follow_symlinks, seed):
    outside = tmp_path / "outside"
    outside.mkdir()
    destination = tmp_path / "destination"
    make_link(destination, outside, directory=True)
    active = outside / "output"
    original = b"oversized file\n"
    if seed:
        active.write_bytes(original)
    policy = "" if follow_symlinks is None else f"      follow_symlinks: {str(follow_symlinks).lower()}\n"
    marker = tmp_path / "success"
    def ready():
        if follow_symlinks is False:
            return marker.exists() and marker.read_bytes().count(b"\n") >= 8
        return active.exists() and any(outside.glob("output.*.gz"))

    log = run_config(tmp_path, """    - name: dummy
      samples: 8
      rate: 4""", f"""    - name: file
      match: '*'
      path: {yaml_path(destination)}
      file: output
{policy}      rotate: true
      rotate_max_size: 1
      rotate_max_files: 2
      rotate_gzip: true
    - name: file
      match: '*'
      path: {yaml_path(tmp_path)}
      file: success
      format: plain""", ready, settle=0)
    if follow_symlinks is False:
        assert list(outside.iterdir()) == ([active] if seed else [])
        if seed:
            assert "could not rotate " in log
            assert active.read_bytes() == original
    else:
        assert (outside / "output").exists()
        assert list(outside.glob("output.*.gz"))


@pytest.mark.parametrize("separator", ["", "/", "//"], ids=["plain", "slash", "double-slash"])
def test_rotation_trailing_separator(tmp_path, separator):
    destination = tmp_path / "destination"
    destination.mkdir()
    run_config(tmp_path, """    - name: dummy
      samples: 8
      rate: 4""", f"""    - name: file
      match: '*'
      path: {yaml_path(str(destination) + separator)}
      file: output
      follow_symlinks: false
      rotate: true
      rotate_max_size: 1
      rotate_max_files: 2""", lambda: bool(list(destination.glob("output.*"))))
    assert list(destination.glob("output.*"))


@pytest.mark.skipif(sys.platform != "linux", reason="Linux directory search permission")
def test_output_search_only_ancestor(tmp_path):
    ancestor = tmp_path / "search-only"
    writable = ancestor / "writable"
    writable.mkdir(parents=True)
    existing = writable / "existing.log"
    existing.write_text("original\n")
    created = writable / "nested" / "created.log"
    ancestor.chmod(0o111)
    try:
        try:
            fd = os.open(ancestor, os.O_RDONLY | os.O_DIRECTORY)
        except PermissionError:
            pass
        else:
            os.close(fd)
            pytest.skip("test process can bypass directory read permissions")

        run_config(tmp_path, """    - name: dummy
      samples: 1
      dummy: '{"message":"search-only"}'""", f"""    - name: file
      match: '*'
      path: {yaml_path(writable)}
      file: existing.log
      format: plain
      follow_symlinks: false
    - name: file
      match: '*'
      path: {yaml_path(created.parent)}
      file: created.log
      format: plain
      mkdir: true
      follow_symlinks: false""", lambda: created.is_file())
        assert existing.read_text().startswith("original\n")
        assert json.loads(existing.read_text().splitlines()[1])["message"] == "search-only"
        assert json.loads(created.read_text())["message"] == "search-only"
    finally:
        ancestor.chmod(0o700)
