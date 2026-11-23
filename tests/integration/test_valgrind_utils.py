from pathlib import Path

import pytest

from utils.valgrind import assert_valgrind_clean, parse_valgrind_log


def test_parse_valgrind_log_detects_clean_run(tmp_path):
    log_path = tmp_path / "valgrind.log"
    log_path.write_text(
        "\n".join(
            [
                "==1== HEAP SUMMARY:",
                "==1==     in use at exit: 0 bytes in 0 blocks",
                "==1==   total heap usage: 10 allocs, 10 frees, 100 bytes allocated",
                "==1== All heap blocks were freed -- no leaks are possible",
                "==1== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)",
            ]
        ),
        encoding="utf-8",
    )

    summary = parse_valgrind_log(log_path)

    assert summary.definitely_lost == 0
    assert summary.error_count == 0
    assert summary.has_leaks is False


def test_assert_valgrind_clean_rejects_leaks(tmp_path):
    log_path = tmp_path / "valgrind.log"
    log_path.write_text(
        "\n".join(
            [
                "==1== definitely lost: 45 bytes in 2 blocks",
                "==1== indirectly lost: 0 bytes in 0 blocks",
                "==1== possibly lost: 0 bytes in 0 blocks",
                "==1== still reachable: 0 bytes in 0 blocks",
                "==1== ERROR SUMMARY: 2 errors from 2 contexts (suppressed: 0 from 0)",
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(AssertionError):
        assert_valgrind_clean(log_path)


def test_assert_valgrind_clean_reports_bounded_error_context(tmp_path):
    log_path = tmp_path / "valgrind.log"
    stack_lines = [f"==42==    by 0x{i:08X}: frame_{i} (worker.c:{i})" for i in range(30)]
    log_path.write_text(
        "\n".join(
            [
                "==42== Invalid read of size 8",
                "==42==    at 0x00123456: flush_complete (output.c:123)",
                *stack_lines,
                "==42==",
                "==42== HEAP SUMMARY:",
                "==42==     in use at exit: 0 bytes in 0 blocks",
                "==42== ERROR SUMMARY: 2 errors from 1 contexts (suppressed: 0 from 0)",
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(AssertionError) as raised:
        assert_valgrind_clean(log_path)

    message = str(raised.value)
    assert "errors=2" in message
    assert "Invalid read of size 8" in message
    assert "flush_complete (output.c:123)" in message
    assert "frame_17" in message
    assert "frame_18" not in message
    assert "Valgrind context truncated" in message
    assert "HEAP SUMMARY" not in message
