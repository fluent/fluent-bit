"""Check that negative browser scenarios cannot mask sanitizer failures."""

import unittest

from browser_page_test import assert_no_sanitizer_errors


class SanitizerOutputTests(unittest.TestCase):
    def test_configuration_failure_is_allowed(self):
        assert_no_sanitizer_errors("[error] yaml error\nFAIL: C test exited with code 1")

    def test_sanitizer_failure_is_rejected(self):
        for diagnostic in (
            "ERROR: AddressSanitizer: heap-buffer-overflow",
            "ERROR: LeakSanitizer: detected memory leaks",
            "SUMMARY: AddressSanitizer: 12 byte(s) leaked",
            "AddressSanitizer: CHECK failed: asan_thread.cpp",
            "AddressSanitizer:DEADLYSIGNAL",
            "ASan is ignoring requested __asan_handle_no_return",
        ):
            with self.subTest(diagnostic=diagnostic):
                with self.assertRaises(AssertionError):
                    assert_no_sanitizer_errors("[error] yaml error\n" + diagnostic)


if __name__ == "__main__":
    unittest.main()
