"""
Robustness tests for the logs tag-records telemetry configuration.

A malformed configuration must never crash Fluent Bit (no SIGSEGV/SIGABRT/core
dump). It must either reject the config with a clean non-zero exit, or start
normally when the questionable value is leniently ignored. These tests run the
binary directly because the configs are not expected to reach a healthy state.
"""

import os
import signal
import subprocess
import tempfile

import pytest

from utils.fluent_bit_manager import _default_binary_path
from utils.valgrind import assert_valgrind_clean


BINARY = os.environ.get("FLUENT_BIT_BINARY") or _default_binary_path()
CONFIG_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "config")
)

# Honor the suite-wide valgrind switches. Because these tests run the binary
# directly (the configs are not expected to reach a healthy state), we wrap it
# with valgrind ourselves so VALGRIND runs also cover the bad-config paths.
VALGRIND = bool(os.environ.get("VALGRIND"))
VALGRIND_STRICT = bool(os.environ.get("VALGRIND_STRICT"))

CRASH_SIGNALS = {
    signal.SIGSEGV,
    signal.SIGABRT,
    signal.SIGILL,
    signal.SIGFPE,
    signal.SIGBUS,
}

# Configs that must be rejected cleanly (non-zero exit, no crash).
REJECT_CONFIGS = [
    # invalid scalar values
    "bad_tag_records_enabled_value.yaml",      # enabled: notabool
    "bad_tag_records_numeric_bool.yaml",       # enabled: 2 (numeric bool not 0/1)
    "bad_tag_records_type.yaml",               # tag_records: [array]
    "bad_tag_records_bool_form.yaml",          # tag_records: true (must be a map)
    "bad_tag_records_max_series_value.yaml",   # max_series: notanumber (strict int)
    # malformed / unknown shapes
    "bad_tag_records_malformed_metrics.yaml",  # metrics: true (not a map)
    "bad_tag_records_unknown_option.yaml",     # max_serie typo (tag_records key)
    "bad_tag_records_unknown_parent_key.yaml", # tag_record typo (parent map key)
    "bad_tag_records_nested_unknown.yaml",     # unknown nested service block
    "bad_tag_records_telemetry_scalar.yaml",   # telemetry: oops (not a map)
    # dotted-key form is not supported (must be a nested block)
    "bad_tag_records_dotted_service.yaml",     # service-level dotted key
    "bad_tag_records_dotted_key.yaml",         # input-level dotted key
    # input-level constraints
    "bad_tag_records_input_value.yaml",        # input tag_records: maybe
    "bad_tag_records_input_service_only.yaml", # max_series on an input
]

# Valid-but-empty block: must start normally (feature disabled), not crash.
LENIENT_CONFIGS = [
    "lenient_tag_records_empty_block.yaml",
]


def _run(config_file, timeout):
    path = os.path.join(CONFIG_DIR, config_file)
    cmd = [BINARY, "-c", path]
    vg_log = None
    if VALGRIND:
        vg_log = tempfile.NamedTemporaryFile(
            prefix="vg_badcfg_", suffix=".log", delete=False
        ).name
        cmd = [
            "valgrind",
            f"--log-file={vg_log}",
            "--leak-check=full",
            "--show-leak-kinds=all",
            *cmd,
        ]
        timeout *= 6  # valgrind is much slower

    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    try:
        out = proc.communicate(timeout=timeout)[0]
        started = False  # exited on its own
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            out = proc.communicate(timeout=20)[0]
        except subprocess.TimeoutExpired:
            proc.kill()
            out = proc.communicate()[0]
        started = True  # was still running (started OK)
    return proc.returncode, out, started, vg_log


def _assert_not_crashed(returncode, output, started):
    # When we stopped a running process ourselves it exits via SIGTERM; that is
    # not a crash. Only a self-inflicted fatal signal counts as a crash.
    if not started and returncode is not None and returncode < 0:
        sig = -returncode
        assert sig not in CRASH_SIGNALS, (
            f"Fluent Bit crashed with signal {sig}\n{output}"
        )
        pytest.fail(f"Fluent Bit was killed by signal {sig}\n{output}")
    assert "core dumped" not in output.lower()
    assert "addresssanitizer" not in output.lower()


def _check_valgrind(vg_log):
    if not vg_log:
        return
    try:
        if VALGRIND_STRICT:
            assert_valgrind_clean(vg_log)
    finally:
        try:
            os.unlink(vg_log)
        except OSError:
            pass


@pytest.mark.parametrize("config_file", REJECT_CONFIGS)
def test_bad_config_is_rejected_without_crash(config_file):
    returncode, output, started, vg_log = _run(config_file, timeout=15)
    _assert_not_crashed(returncode, output, started)
    assert not started, f"{config_file} unexpectedly started instead of failing"
    # Under valgrind the wrapper relays the child's exit code; a clean reject is
    # still a non-zero exit.
    assert returncode is not None and returncode != 0, (
        f"{config_file} should exit non-zero, got {returncode}\n{output}"
    )
    _check_valgrind(vg_log)


@pytest.mark.parametrize("config_file", LENIENT_CONFIGS)
def test_lenient_config_starts_without_crash(config_file):
    returncode, output, started, vg_log = _run(config_file, timeout=6)
    _assert_not_crashed(returncode, output, started)
    assert started, (
        f"{config_file} should start (value ignored), but exited "
        f"{returncode}\n{output}"
    )
    _check_valgrind(vg_log)
