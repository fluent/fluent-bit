from pathlib import Path

import pytest

from utils.leaks import assert_leaks_clean


def test_assert_leaks_clean_accepts_clean_exit(tmp_path):
    log_path = tmp_path / "leaks.log"

    assert_leaks_clean(0, log_path)


@pytest.mark.parametrize(
    ("return_code", "message"),
    [
        (1, "memory leaks were detected"),
        (2, "leaks command failed with exit code 2"),
    ],
)
def test_assert_leaks_clean_rejects_nonzero_exit(tmp_path, return_code, message):
    log_path = tmp_path / "leaks.log"

    with pytest.raises(AssertionError, match=message) as exc_info:
        assert_leaks_clean(return_code, log_path)

    assert str(Path(log_path)) in str(exc_info.value)
