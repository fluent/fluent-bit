import os
import subprocess
from pathlib import Path

import yaml

from utils.fluent_bit_manager import _default_binary_path
from utils.valgrind import assert_valgrind_clean


BINARY = os.environ.get("FLUENT_BIT_BINARY") or _default_binary_path()
REPO_ROOT = Path(__file__).resolve().parents[5]
VALGRIND = bool(os.environ.get("VALGRIND"))
VALGRIND_STRICT = bool(os.environ.get("VALGRIND_STRICT"))


def _run_fluent_bit(arguments, tmp_path, name, timeout=15):
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
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )

    if VALGRIND_STRICT:
        assert_valgrind_clean(valgrind_log)

    return result


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
    if external_plugin.exists() and not VALGRIND:
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
    if external_plugin.exists() and not VALGRIND:
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
            "-o", "exit",
            "-m", "generated.*",
            "-p", "flush_count=1",
            "-G",
        ],
        tmp_path,
        "runtime-generation",
    )
    assert generation.returncode == 0, generation.stderr

    config_path = tmp_path / "generated.yaml"
    config_path.write_text(generation.stdout, encoding="utf-8")

    execution = _run_fluent_bit(
        ["-c", str(config_path)],
        tmp_path,
        "runtime-execution",
        timeout=15,
    )
    assert execution.returncode == 0, execution.stdout + execution.stderr
