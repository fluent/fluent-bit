import json
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from utils.fluent_bit_manager import _default_binary_path
from utils.valgrind import assert_valgrind_clean
from utils.memory_check import memory_check_enabled


BINARY = os.environ.get("FLUENT_BIT_BINARY") or _default_binary_path()
REPO_ROOT = Path(__file__).resolve().parents[5]
VALGRIND = bool(os.environ.get("VALGRIND"))
VALGRIND_STRICT = bool(os.environ.get("VALGRIND_STRICT"))
LEAKS = bool(os.environ.get("LEAKS"))
LEAKS_STRICT = bool(os.environ.get("LEAKS_STRICT"))


def _run_fluent_bit(arguments, tmp_path, name, timeout=15, stdout=None):
    if VALGRIND and LEAKS:
        raise RuntimeError("VALGRIND and LEAKS cannot be enabled together")
    command = [BINARY, *arguments]
    valgrind_log = tmp_path / f"valgrind-{name}.log"

    if VALGRIND:
        command = [
            "valgrind",
            f"--log-file={valgrind_log}",
            "--leak-check=full",
            "--show-leak-kinds=all",
            *command,
        ]
        timeout *= 6

    result = subprocess.run(
        command,
        stdout=subprocess.PIPE if stdout is None else stdout,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )

    if VALGRIND_STRICT:
        assert_valgrind_clean(valgrind_log)

    if LEAKS:
        _check_macos_leaks(arguments, tmp_path, name, result.returncode, stdout)

    return result


def _check_macos_leaks(arguments, tmp_path, name, expected_returncode, stdout):
    if platform.system() != "Darwin":
        raise RuntimeError("LEAKS is only supported on macOS")
    leaks_binary = shutil.which("leaks")
    if not leaks_binary:
        raise RuntimeError("The macOS leaks command was not found")

    # Keep checker output separate from generated YAML and CLI diagnostics.
    output_path = tmp_path / f"leaks-{name}.stdout"
    error_path = tmp_path / f"leaks-{name}.stderr"
    log_path = tmp_path / f"leaks-{name}.log"
    command = [
        leaks_binary, "-quiet", "-fullStacks", "-atExit", "--",
        "/bin/sh", "-c", 'output="$1"; error="$2"; shift 2; exec "$@" >"$output" 2>"$error"',
        "fluent-bit-leaks-target",
        str(output_path) if stdout is None else str(stdout.name),
        str(error_path), BINARY, *arguments,
    ]
    with log_path.open("w", encoding="utf-8") as log:
        checked = subprocess.run(
            command, stdout=log, stderr=subprocess.STDOUT, timeout=120, check=False,
        )
    if LEAKS_STRICT:
        # A rejected CLI command may itself exit nonzero. Require an actual clean
        # checker summary as well, so its status cannot conceal a checker failure.
        report = log_path.read_text(encoding="utf-8")
        assert re.search(r"\b0 leaks for 0 total leaked bytes\b", report), report
        assert checked.returncode in (0, expected_returncode), report


def _supported_options():
    result = subprocess.run(
        [BINARY, "--help"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0
    return result.stdout


def test_generate_config_preserves_cli_configuration(tmp_path):
    help_text = _supported_options()
    storage_path = tmp_path / "storage"
    log_path = tmp_path / "fluent-bit.log"
    parser_path = REPO_ROOT / "conf" / "parsers.conf"
    external_plugin = REPO_ROOT / "build" / "test_logs_go.so"
    storage_path.mkdir()

    arguments = [
        "-b", str(storage_path),
        "-f", "2.5",
        "-C", "calyptia",
        "-p", "api: key=a:b # c",
        "-i", "dummy",
        "-p", 'dummy={"message":"cli"}',
        "-t", "cli.generated",
        "-G",
        "-i", "cpu",
        "-p", "interval_sec=60",
        "-F", "modify",
        "-m", "cli.*",
        "-p", "add=source cli",
        "-o", "stdout",
        "-m", "cli.*",
        "-p", "format=json_lines",
        "-o", "http",
        "-m", "other.*",
        "-p", "host=localhost",
        "-p", "port=9090",
        "-R", str(parser_path),
        "-l", str(log_path),
        "-s", "49152",
        "-Y",
        "-W",
        "--enable-fips",
        "-vv",
    ]

    if "--daemon" in help_text:
        arguments.append("-d")
    if "--http" in help_text:
        arguments.extend(["-H", "-L", "127.0.0.1", "-P", "2021"])
    if "--enable-chunk-trace" in help_text:
        arguments.append("-Z")
    if "--sp-task" in help_text:
        arguments.extend(["-T", "SELECT * FROM STREAM:dummy.0;"])
    if os.name == "nt":
        arguments.extend(["-M", "1024"])
    if external_plugin.exists() and not memory_check_enabled():
        arguments.extend(["-e", str(external_plugin)])

    result = _run_fluent_bit(arguments, tmp_path, "all-options")
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""

    generated = yaml.safe_load(result.stdout)
    service = generated["service"]

    assert service["storage.path"] == str(storage_path)
    assert service["flush"] == "2.5"
    assert service["parsers_file"] == str(parser_path)
    assert service["log_file"] == str(log_path)
    assert service["coro_stack_size"] == "49152"
    assert service["hot_reload"] == "on"
    assert service["hot_reload.ensure_thread_safety"] == "off"
    assert service["security.fips_mode"] == "on"
    assert service["log_level"] == "trace"

    if "--daemon" in help_text:
        assert service["daemon"] == "on"
    if "--http" in help_text:
        assert service["http_server"] == "on"
        assert service["http_listen"] == "127.0.0.1"
        assert service["http_port"] == "2021"
    if "--enable-chunk-trace" in help_text:
        assert service["enable_chunk_trace"] == "on"
    if os.name == "nt":
        assert service["windows.maxstdio"] == "1024"

    assert generated["customs"] == [
        {"name": "calyptia", "api: key": "a:b # c"}
    ]
    assert generated["pipeline"] == {
        "inputs": [
            {
                "name": "dummy",
                "dummy": '{"message":"cli"}',
                "tag": "cli.generated",
            },
            {"name": "cpu", "interval_sec": "60"},
        ],
        "filters": [
            {"name": "modify", "match": "cli.*", "add": "source cli"}
        ],
        "outputs": [
            {"name": "stdout", "match": "cli.*", "format": "json_lines"},
            {
                "name": "http",
                "match": "other.*",
                "host": "localhost",
                "port": "9090",
            },
        ],
    }

    if "--sp-task" in help_text:
        assert generated["stream_processor"] == [
            {
                "name": "flb-console:0",
                "exec": "SELECT * FROM STREAM:dummy.0;",
            }
        ]
    if external_plugin.exists() and not memory_check_enabled():
        assert generated["plugins"] == [str(external_plugin)]


def test_generate_config_preserves_quiet_log_level(tmp_path):
    result = _run_fluent_bit(
        ["-i", "dummy", "-o", "null", "-q", "--generate-config"],
        tmp_path,
        "quiet",
    )

    assert result.returncode == 0, result.stderr
    generated = yaml.safe_load(result.stdout)
    assert generated["service"]["log_level"] == "off"


def test_generate_config_rejects_nonportable_cli_options(tmp_path):
    config_path = tmp_path / "source.yaml"
    config_path.write_text("{}\n", encoding="utf-8")

    cases = [
        (["-c", str(config_path), "-G"], "cannot be used with --config"),
        (["-w", str(tmp_path), "-G"], "cannot preserve --workdir"),
    ]

    if "--trace-input" in _supported_options():
        cases.append(
            (["--trace-input", "dummy.0", "-G"],
             "cannot preserve startup trace options")
        )

    for index, (arguments, expected_error) in enumerate(cases):
        result = _run_fluent_bit(
            arguments,
            tmp_path,
            f"unsupported-{index}",
        )
        assert result.returncode != 0
        assert expected_error in result.stderr
        assert result.stdout == ""


def test_generated_config_runs_as_a_pipeline(tmp_path):
    generation = _run_fluent_bit(
        [
            "-i", "dummy",
            "-p", "samples=1",
            "-t", "generated.runtime",
            "-F", "modify",
            "-m", "generated.*",
            "-p", "add=first one",
            "-p", "add=second two",
            "-o", "stdout",
            "-m", "generated.*",
            "-p", "format=json_lines",
            "-o", "exit",
            "-m", "generated.*",
            "-p", "flush_count=1",
            "-G",
        ],
        tmp_path,
        "runtime-generation",
    )
    assert generation.returncode == 0, generation.stderr

    generated = yaml.safe_load(generation.stdout)
    assert generated["pipeline"]["filters"][0]["add"] == ["first one", "second two"]

    config_path = tmp_path / "generated.yaml"
    config_path.write_text(generation.stdout, encoding="utf-8")

    execution = _run_fluent_bit(
        ["-c", str(config_path)],
        tmp_path,
        "runtime-execution",
        timeout=15,
    )
    assert execution.returncode == 0, execution.stdout + execution.stderr

    records = [json.loads(line) for line in execution.stdout.splitlines() if line.startswith("{")]
    assert records
    assert all(record["first"] == "one" and record["second"] == "two" for record in records)


def test_generate_config_preserves_control_characters(tmp_path):
    value = "before" + "".join(chr(c) for c in range(0x80, 0xa0)) + "\n\r\t\b\f\x01\x7f😀after"
    result = _run_fluent_bit(
        ["-i", "dummy", "-t", value, "-o", "null", "-G"], tmp_path, "unicode",
    )
    assert result.returncode == 0, result.stderr
    assert yaml.safe_load(result.stdout)["pipeline"]["inputs"][0]["tag"] == value
    config_path = tmp_path / "unicode.yaml"
    config_path.write_text(result.stdout, encoding="utf-8")
    validation = _run_fluent_bit(["-D", "-c", str(config_path)], tmp_path, "unicode-validation")
    assert validation.returncode == 0, validation.stderr


def test_generate_config_uses_final_service_setting(tmp_path):
    result = _run_fluent_bit(["-f", "1", "-f", "2", "-G"], tmp_path, "repeated-service")
    assert result.returncode == 0, result.stderr
    assert result.stdout.count('"flush":') == 1
    assert yaml.safe_load(result.stdout)["service"]["flush"] == "2"


def test_generate_config_rejects_repeated_parser_files(tmp_path):
    parser_path = REPO_ROOT / "conf" / "parsers.conf"
    result = _run_fluent_bit(
        ["-R", str(parser_path), "-R", str(parser_path), "-G"], tmp_path, "repeated-parsers",
    )
    assert result.returncode != 0
    assert "cannot preserve repeated parsers_file" in result.stderr
    assert result.stdout == ""


@pytest.mark.skipif(not Path("/dev/full").exists(), reason="requires /dev/full")
def test_generate_config_reports_write_failure(tmp_path):
    with open("/dev/full", "w") as output:
        result = _run_fluent_bit(["-G"], tmp_path, "write-failure", stdout=output)
    assert result.returncode != 0
    assert "failed to generate YAML configuration" in result.stderr


@pytest.mark.skipif(os.name == "nt", reason="supervisor is a POSIX option")
@pytest.mark.parametrize("option", ["-G", "--generate-config", "-qG", "--generate-con"])
def test_generate_config_bypasses_supervisor(tmp_path, option):
    result = _run_fluent_bit(
        ["--supervisor", "-i", "dummy", "-o", "null", option], tmp_path, "supervisor",
    )
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert yaml.safe_load(result.stdout)["pipeline"]["inputs"][0]["name"] == "dummy"
    rejected = _run_fluent_bit(
        ["--supervisor", option, "-w", str(tmp_path)], tmp_path, "supervisor-rejected",
    )
    assert rejected.returncode != 0
    assert "cannot preserve --workdir" in rejected.stderr
    assert "[supervisor]" not in rejected.stderr


@pytest.mark.parametrize("report, checker_status, valid", [
    ("Process 123: 0 leaks for 0 total leaked bytes.\n", 0, True),
    ("Process 123: 0 leaks for 0 total leaked bytes.\n", 1, True),
    ("Process 123: 1 leaks for 16 total leaked bytes.\n", 1, False),
    ("leaks: could not inspect process\n", 1, False),
])
def test_macos_checker_requires_clean_summary(monkeypatch, tmp_path, report, checker_status, valid):
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    monkeypatch.setattr(shutil, "which", lambda command: "/usr/bin/leaks")
    monkeypatch.setitem(_check_macos_leaks.__globals__, "LEAKS_STRICT", True)

    def run_checker(command, **kwargs):
        assert command[:6] == ["/usr/bin/leaks", "-quiet", "-fullStacks", "-atExit", "--", "/bin/sh"]
        assert command[-2:] == [BINARY, "-G"]
        kwargs["stdout"].write(report)
        return subprocess.CompletedProcess(command, checker_status)

    monkeypatch.setattr(subprocess, "run", run_checker)
    if valid:
        _check_macos_leaks(["-G"], tmp_path, "mocked", 1, None)
    else:
        with pytest.raises(AssertionError):
            _check_macos_leaks(["-G"], tmp_path, "mocked", 1, None)
