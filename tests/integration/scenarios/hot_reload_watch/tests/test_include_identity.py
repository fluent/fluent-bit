"""Configuration includes must reject cycles and aliases before adding plugins."""

import os
import shutil
import sys
import subprocess

import pytest

from utils.fluent_bit_manager import FluentBitManager
from utils.memory_check import valgrind_enabled
from utils.valgrind import assert_valgrind_clean


def run_config(config, cwd, relative, mounts=None):
    binary = FluentBitManager(str(config)).binary_absolute_path
    argument = os.path.relpath(config, cwd) if relative else str(config)
    command = [binary, "--dry-run", "-c", argument]
    memory_log = cwd / "include-valgrind.log"
    if valgrind_enabled():
        command = ["valgrind", f"--log-file={memory_log}", "--leak-check=full",
                   "--show-leak-kinds=all", "--error-exitcode=99"] + command
    if mounts is not None:
        command = ["unshare", "--user", "--map-root-user", "--mount", "--", "sh", "-ec",
                   'mount --bind "$1" "$2"; mount --bind "$1" "$3"; shift 3; exec "$@"',
                   "sh", *(str(path) for path in mounts), *command]
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=30)
    if mounts is not None and result.returncode != 0:
        error = result.stderr.lower()
        if "unshare:" in error or ("mount:" in error and
                ("permission denied" in error or "operation not permitted" in error)):
            pytest.skip(f"bind-mount namespace unavailable: {result.stderr.splitlines()[0]}")
    if valgrind_enabled() and os.environ.get("VALGRIND_STRICT"):
        assert_valgrind_clean(memory_log)
    return result


def include_text(config_format, paths):
    if config_format == "conf":
        return "".join(f"@INCLUDE {path}\n" for path in paths)
    return "includes:\n" + "".join(f"  - '{path}'\n" for path in paths)


@pytest.mark.parametrize("config_format", ["conf", "yaml"])
@pytest.mark.parametrize("relative", [False, True])
@pytest.mark.parametrize("indirect", [False, True])
def test_include_cycle_is_rejected(tmp_path, config_format, relative, indirect):
    directory = tmp_path / "config"
    directory.mkdir()
    main = directory / f"main.{config_format}"
    if indirect:
        main.write_text(include_text(config_format, [f"other.{config_format}"]), encoding="utf-8")
        (directory / f"other.{config_format}").write_text(
            include_text(config_format, [f"./main.{config_format}"]), encoding="utf-8"
        )
    else:
        main.write_text(include_text(config_format, [f"*.{config_format}"]), encoding="utf-8")

    result = run_config(main, tmp_path, relative)
    assert result.returncode != 0
    assert "already included" in result.stderr or "Read twice" in result.stderr, result.stderr


@pytest.mark.parametrize("config_format", ["conf", "yaml"])
@pytest.mark.parametrize("relative", [False, True])
@pytest.mark.parametrize("duplicate", [False, True])
def test_direct_and_wildcard_include_identity(tmp_path, config_format, relative, duplicate):
    directory = tmp_path / "config"
    partials = directory / "partials"
    partials.mkdir(parents=True)
    main = directory / f"main.{config_format}"
    child = partials / f"input.{config_format}"
    child.write_text(
        "[INPUT]\n    Name dummy\n" if config_format == "conf"
        else "pipeline:\n  inputs:\n    - name: dummy\n", encoding="utf-8"
    )
    paths = [f"partials/input.{config_format}"]
    if duplicate:
        paths.append(f"partials/*.{config_format}")
    main.write_text(include_text(config_format, paths), encoding="utf-8")

    result = run_config(main, tmp_path, relative)
    if duplicate:
        assert result.returncode != 0
        assert "already included" in result.stderr or "Read twice" in result.stderr, result.stderr
    else:
        assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("alias_kind", ["symlink", "hardlink"])
def test_yaml_include_cycle_through_file_alias(tmp_path, alias_kind):
    """Reject an include cycle even when its path names a link to an active file."""
    main = tmp_path / "main.yaml"
    child = tmp_path / "child.yaml"
    alias = tmp_path / "alias.yaml"
    main.write_text(include_text("yaml", ["child.yaml"]), encoding="utf-8")
    child.write_text(include_text("yaml", ["alias.yaml"]), encoding="utf-8")
    try:
        if alias_kind == "symlink":
            alias.symlink_to(main)
        else:
            os.link(main, alias)
    except OSError as exc:
        pytest.skip(f"{alias_kind} is unavailable: {exc}")
    result = run_config(main, tmp_path, False)
    assert result.returncode != 0
    assert "already included" in result.stderr, result.stderr


@pytest.mark.parametrize("alias_kind", ["symlink", "hardlink"])
def test_yaml_linked_templates_keep_relative_children(tmp_path, alias_kind):
    """Reuse an inactive template while resolving children from each include directory."""
    directories = [tmp_path / "left", tmp_path / "right"]
    for directory in directories:
        directory.mkdir()
        (directory / "child.yaml").write_text(
            "pipeline:\n  inputs:\n    - name: dummy\n", encoding="utf-8"
        )
    template = directories[0] / "template.yaml"
    template.write_text(include_text("yaml", ["child.yaml"]), encoding="utf-8")
    alias = directories[1] / "template.yaml"
    try:
        if alias_kind == "symlink":
            alias.symlink_to(template)
        else:
            os.link(template, alias)
    except OSError as exc:
        pytest.skip(f"{alias_kind} is unavailable: {exc}")
    main = tmp_path / "main.yaml"
    main.write_text(include_text("yaml", ["left/template.yaml", "right/template.yaml"]),
                    encoding="utf-8")
    result = run_config(main, tmp_path, False)
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junctions")
def test_yaml_include_cycle_through_directory_junction(tmp_path):
    """Reject a Windows include cycle whose pathname grows through a junction."""
    main = tmp_path / "main.yaml"
    main.write_text(include_text("yaml", ["loop/main.yaml"]), encoding="utf-8")
    junction = tmp_path / "loop"
    created = subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(tmp_path)],
                             capture_output=True, text=True)
    if created.returncode != 0:
        pytest.skip(f"directory junction is unavailable: {created.stderr}")
    try:
        result = run_config(main, tmp_path, False)
        assert result.returncode != 0
        # Junction contexts can grow until the nesting or Windows path limit.
    finally:
        junction.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows directory junctions")
def test_yaml_active_template_preserves_junction_context(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    left, right = tmp_path / "left", tmp_path / "right"
    left.mkdir()
    right.mkdir()
    (shared / "main.yaml").write_text(include_text("yaml", ["../child.yaml"]),
                                       encoding="utf-8")
    (left / "child.yaml").write_text(
        include_text("yaml", [str(right / "template" / "main.yaml")]), encoding="utf-8"
    )
    (right / "child.yaml").write_text("pipeline:\n  inputs:\n    - name: dummy\n",
                                       encoding="utf-8")
    junctions = []
    try:
        for parent in (left, right):
            junction = parent / "template"
            created = subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(shared)],
                                     capture_output=True, text=True)
            if created.returncode != 0:
                pytest.skip(f"directory junction is unavailable: {created.stderr}")
            junctions.append(junction)
        result = run_config(left / "template" / "main.yaml", tmp_path, False)
        assert result.returncode == 0, result.stderr
    finally:
        for junction in junctions:
            junction.rmdir()


@pytest.mark.parametrize("depth", [256, 257])
def test_yaml_include_nesting_boundary(tmp_path, depth):
    for index in range(depth):
        text = (include_text("yaml", [f"{index + 1}.yaml"]) if index + 1 < depth
                else "pipeline:\n  inputs:\n    - name: dummy\n")
        (tmp_path / f"{index}.yaml").write_text(text, encoding="utf-8")
    result = run_config(tmp_path / "0.yaml", tmp_path, False)
    if depth == 256:
        assert result.returncode == 0, result.stderr
    else:
        assert result.returncode != 0
        assert "maximum YAML include depth (256)" in result.stderr, result.stderr


@pytest.mark.parametrize("alias_kind", ["symlink", "hardlink"])
def test_yaml_active_linked_template_keeps_relative_context(tmp_path, alias_kind):
    """Reenter a physical template when its new relative children terminate inclusion."""
    left, right = tmp_path / "left", tmp_path / "right"
    left.mkdir()
    right.mkdir()
    template = left / "template.yaml"
    alias = right / "template.yaml"
    template.write_text(include_text("yaml", ["child.yaml"]), encoding="utf-8")
    (left / "child.yaml").write_text(
        include_text("yaml", ["../right/template.yaml"]), encoding="utf-8"
    )
    (right / "child.yaml").write_text(
        "pipeline:\n  inputs:\n    - name: dummy\n", encoding="utf-8"
    )
    try:
        if alias_kind == "symlink":
            alias.symlink_to(template)
        else:
            os.link(template, alias)
    except OSError as exc:
        pytest.skip(f"{alias_kind} is unavailable: {exc}")
    result = run_config(template, tmp_path, False)
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(sys.platform != "linux", reason="Linux bind-mount context")
def test_yaml_active_template_preserves_bind_mount_context(tmp_path):
    """Identical directories at different mounts can resolve parent includes differently."""
    if shutil.which("unshare") is None or shutil.which("mount") is None:
        pytest.skip("bind-mount test requires unshare and mount")
    shared = tmp_path / "shared"
    shared.mkdir()
    left, right = tmp_path / "left", tmp_path / "right"
    for parent in (left, right):
        (parent / "template").mkdir(parents=True)
    (shared / "main.yaml").write_text(include_text("yaml", ["../child.yaml"]), encoding="utf-8")
    (left / "child.yaml").write_text(
        include_text("yaml", [str(right / "template" / "main.yaml")]), encoding="utf-8"
    )
    (right / "child.yaml").write_text(
        "pipeline:\n  inputs:\n    - name: dummy\n", encoding="utf-8"
    )
    result = run_config(left / "template" / "main.yaml", tmp_path, False,
                        mounts=(shared, left / "template", right / "template"))
    assert result.returncode == 0, result.stderr
