"""Wait for asynchronous engine diagnostics without delaying successful checks."""

import time
from pathlib import Path


def read_log(path, *expected, offset=0, timeout=30):
    deadline = time.monotonic() + timeout
    while True:
        text = Path(path).read_text(encoding="utf-8")[offset:]
        missing = [message for message in expected if message not in text]
        if not missing:
            return text
        if time.monotonic() >= deadline:
            raise AssertionError(f"Missing diagnostics {missing!r} in {path}:\n{text[-5000:]}")
        time.sleep(0.05)
