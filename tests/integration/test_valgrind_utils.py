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

