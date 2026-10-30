"""Configuration includes must reject cycles and aliases before adding plugins."""

import os
import subprocess

import pytest

from utils.fluent_bit_manager import FluentBitManager


def run_config(config, cwd, relative):
    binary = FluentBitManager(str(config)).binary_absolute_path
    argument = os.path.relpath(config, cwd) if relative else str(config)
    return subprocess.run(
        [binary, "--dry-run", "-c", argument], cwd=cwd,
        capture_output=True, text=True, timeout=10,
    )


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
