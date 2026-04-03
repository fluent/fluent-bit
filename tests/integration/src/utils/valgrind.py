import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ValgrindSummary:
    definitely_lost: int = 0
    indirectly_lost: int = 0
    possibly_lost: int = 0
    still_reachable: int = 0
    suppressed: int = 0
    error_count: int = 0
    context_count: int = 0
    invalid_read_count: int = 0
    invalid_write_count: int = 0
    invalid_free_count: int = 0
    uninitialised_count: int = 0

    @property
    def has_leaks(self):
        return any(
            [
                self.definitely_lost,
                self.indirectly_lost,
                self.possibly_lost,
            ]
        )

    @property
    def has_errors(self):
        return self.error_count > 0


def _parse_bytes(text, label):
    pattern = rf"{label}:\s*([0-9,]+) bytes"
    match = re.search(pattern, text)
    if not match:
        return 0
    return int(match.group(1).replace(",", ""))


def parse_valgrind_log(log_path):
    text = Path(log_path).read_text(encoding="utf-8")
    summary = ValgrindSummary(
        definitely_lost=_parse_bytes(text, "definitely lost"),
        indirectly_lost=_parse_bytes(text, "indirectly lost"),
        possibly_lost=_parse_bytes(text, "possibly lost"),
        still_reachable=_parse_bytes(text, "still reachable"),
        suppressed=_parse_bytes(text, "suppressed"),
    )

    error_match = re.search(r"ERROR SUMMARY:\s*([0-9,]+) errors from ([0-9,]+) contexts", text)
    if error_match:
        summary.error_count = int(error_match.group(1).replace(",", ""))
        summary.context_count = int(error_match.group(2).replace(",", ""))

    summary.invalid_read_count = len(re.findall(r"Invalid read", text))
    summary.invalid_write_count = len(re.findall(r"Invalid write", text))
    summary.invalid_free_count = len(re.findall(r"Invalid free", text))
    summary.uninitialised_count = len(re.findall(r"uninitialised|Uninitialised|Use of uninitialised", text))

    return summary


def assert_valgrind_clean(log_path, *, allow_definitely_lost=0, allow_error_count=0):
    summary = parse_valgrind_log(log_path)
    problems = []

    if summary.definitely_lost > allow_definitely_lost:
        problems.append(f"definitely lost={summary.definitely_lost}")
    if summary.indirectly_lost:
        problems.append(f"indirectly lost={summary.indirectly_lost}")
    if summary.possibly_lost:
        problems.append(f"possibly lost={summary.possibly_lost}")
    if summary.error_count > allow_error_count:
        problems.append(f"errors={summary.error_count}")

    if problems:
        raise AssertionError(
            f"Valgrind issues found in {log_path}: " + ", ".join(problems)
        )

    return summary
