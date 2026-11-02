"""Exercise CI scheduling controls and failure propagation without compiling Fluent Bit."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


DRIVER = Path(__file__).resolve().parents[1] / "run-unit-tests.sh"


@unittest.skipUnless(sys.platform.startswith("linux"), "uses GNU time resource output")
class UnitTestDriverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="flb-ci-driver-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        tools = self.root / "tools"
        tools.mkdir()
        mock = tools / "mock"
        mock.write_text(f"#!{sys.executable}\n" + '''
import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
with open(os.environ["CALL_LOG"], "a") as output:
    output.write(json.dumps([name, *sys.argv[1:]]) + "\\n")
if name == "getconf":
    print("4")
elif name == "uname":
    print("Linux")
elif name == "ip":
    print("inet6 ::1/128")
elif name == "ctest":
    pathlib.Path(sys.argv[sys.argv.index("--output-junit") + 1]).write_text("<testsuite/>")
    sys.exit(int(os.environ.get("TEST_EXIT_CODE", "0")))
elif name == "cmake" and "--build" in sys.argv:
    sys.exit(int(os.environ.get("BUILD_EXIT_CODE", "0")))
''')
        mock.chmod(0o755)
        for name in ("getconf", "uname", "ip", "cmake", "ctest", "gcovr"):
            (tools / name).symlink_to(mock)
        self.env = {
            **{k: v for k, v in os.environ.items()
               if k not in ("FLB_BUILD_JOBS", "FLB_TEST_JOBS", "FLB_OPT", "LDFLAG")},
            "PATH": f"{tools}:{os.environ['PATH']}",
            "SOURCE_DIR": str(self.root),
            "CALL_LOG": str(self.root / "calls.jsonl"),
        }

    def run_driver(self, **env):
        result = subprocess.run(["bash", str(DRIVER)], env={**self.env, **env},
                                capture_output=True, text=True)
        log = self.root / "calls.jsonl"
        calls = [json.loads(line) for line in log.read_text().splitlines()]
        return result, calls

    def test_linux_defaults_and_artifacts(self):
        result, calls = self.run_driver()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(["cmake", "--build", ".", "--parallel", "4"], calls)
        ctest = next(call for call in calls if call[0] == "ctest")
        self.assertEqual(ctest[1:3], ["--parallel", "12"])
        results = self.root / "build/ci-results"
        self.assertTrue((results / "unit-tests.xml").exists())
        for phase in ("configure", "build", "tests"):
            self.assertTrue((results / f"{phase}.resources.txt").exists())
            self.assertRegex((results / "timings.tsv").read_text(), rf"{phase}\t\d+\t0")

    def test_explicit_overrides(self):
        result, calls = self.run_driver(FLB_BUILD_JOBS="2", FLB_TEST_JOBS="12")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(["cmake", "--build", ".", "--parallel", "2"], calls)
        self.assertEqual(next(c for c in calls if c[0] == "ctest")[2], "12")

    def test_sanitizer_keeps_core_count_and_expands_stack(self):
        result, calls = self.run_driver(FLB_OPT="-DFLB_SANITIZE_THREAD=On")
        self.assertEqual(result.returncode, 0, result.stderr)
        configure = next(c for c in calls if c[0] == "cmake")
        self.assertIn("-DFLB_SANITIZE_THREAD=On", configure)
        self.assertIn("-DFLB_CORO_STACK_SIZE=4194304", configure)
        self.assertEqual(next(c for c in calls if c[0] == "ctest")[2], "4")

    def test_ctest_failure_is_preserved_and_coverage_is_not_run(self):
        result, calls = self.run_driver(TEST_EXIT_CODE="8", FLB_OPT="-DFLB_COVERAGE=On")
        self.assertEqual(result.returncode, 8)
        self.assertFalse(any(c[0] == "gcovr" for c in calls))
        self.assertRegex((self.root / "build/ci-results/timings.tsv").read_text(),
                         r"tests\t\d+\t8")

    def test_build_failure_does_not_run_ctest(self):
        result, calls = self.run_driver(BUILD_EXIT_CODE="2")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(any(c[0] == "ctest" for c in calls))

    def test_invalid_parallel_level_is_rejected(self):
        result, calls = self.run_driver(FLB_TEST_JOBS="0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("positive integers", result.stderr)
        self.assertFalse(any(c[0] == "cmake" for c in calls))

    def test_build_override_is_validated_before_arithmetic(self):
        marker = self.root / "unexpected-command"
        expression = f'a[$(touch "{marker}")]'
        result, calls = self.run_driver(FLB_BUILD_JOBS=expression)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("positive integers", result.stderr)
        self.assertFalse(marker.exists())
        self.assertFalse(any(c[0] == "cmake" for c in calls))


if __name__ == "__main__":
    unittest.main()
