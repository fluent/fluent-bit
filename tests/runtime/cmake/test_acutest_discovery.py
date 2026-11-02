"""Exercise runtime-case discovery with real Acutest, CMake, and CTest."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
MODULE = ROOT / "tests/runtime/cmake/FluentBitTest.cmake"
HEADER = ROOT / "tests/lib/acutest/acutest.h"


@unittest.skipUnless(shutil.which("cmake") and shutil.which("ninja"),
                     "requires CMake, Ninja, and a C compiler")
class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="flb acutest ")
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name)
        self.build = self.source / "build"
        self.source.joinpath("CMakeLists.txt").write_text(f'''
cmake_minimum_required(VERSION 3.12)
project(acutest_discovery C)
enable_testing()
include([=[{MODULE.as_posix()}]=])
add_executable(cases cases.c)
flb_add_runtime_test_cases(cases)
''')

    def command(self, *args, success=True):
        result = subprocess.run(args, capture_output=True, text=True, timeout=60)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def configure(self, *, multi_config=False, empty=False, duplicate=False):
        entries = [] if empty else [
            '{"alpha", pass_case}',
            '{"alpha with spaces", pass_case}',
            '{"failure", fail_case}',
        ]
        if duplicate:
            entries.append('{"alpha", pass_case}')
        self.source.joinpath("cases.c").write_text(f'''
#include "{HEADER.as_posix()}"
static void pass_case(void) {{ TEST_CHECK(1); }}
static void fail_case(void) {{ TEST_CHECK(0); }}
TEST_LIST = {{
#if 0
    {{"not_compiled", pass_case}},
#endif
    {", ".join(entries) + "," if entries else ""}
    {{NULL, NULL}}
}};
''')
        self.command("cmake", "-S", str(self.source), "-B", str(self.build),
                     "-G", "Ninja Multi-Config" if multi_config else "Ninja",
                     "-DCMAKE_BUILD_TYPE=Debug")

    def build_cases(self, config="Debug"):
        self.command("cmake", "--build", str(self.build), "--config", config)

    def list_cases(self, config=None, success=True):
        command = ["ctest", "--test-dir", str(self.build), "--show-only=json-v1"]
        if config:
            command += ["-C", config]
        result = self.command(*command, success=success)
        return json.loads(result.stdout)["tests"] if success else result

    def test_compiled_cases_names_labels_and_exact_selection(self):
        self.configure()
        self.build_cases()
        tests = self.list_cases()
        self.assertEqual([test["name"] for test in tests],
                         ["cases/alpha", "cases/alpha with spaces", "cases/failure"])
        self.assertEqual([test["name"] for test in self.list_cases("Release")],
                         [test["name"] for test in tests])
        for test in tests:
            properties = {p["name"]: p["value"] for p in test["properties"]}
            self.assertEqual(properties["LABELS"], ["runtime"])
            self.assertEqual(properties["WORKING_DIRECTORY"], str(self.build))
            self.assertEqual(test["command"][1:],
                             ["--no-exec", "--", test["name"].split("/", 1)[1]])
        result = self.command("ctest", "--test-dir", str(self.build),
                              "-R", "^cases/alpha with spaces$", "--output-on-failure")
        self.assertIn("100% tests passed", result.stdout)
        self.assertIn("out of 1", result.stdout)

    def test_case_failures_reach_ctest(self):
        self.configure()
        self.build_cases()
        result = self.command("ctest", "--test-dir", str(self.build),
                              "-R", "^cases/failure$", "--output-on-failure", success=False)
        self.assertIn("cases/failure", result.stdout)
        self.assertIn("0% tests passed", result.stdout)

    def test_unbuilt_target_is_visible(self):
        self.configure()
        self.assertEqual([test["name"] for test in self.list_cases()], ["cases/not_built"])

    def test_empty_and_duplicate_lists_fail_discovery(self):
        for mode in ("empty", "duplicate"):
            with self.subTest(mode=mode):
                self.configure(**{mode: True})
                self.build_cases()
                result = self.list_cases(success=False)
                self.assertIn("No Acutest cases" if mode == "empty" else "Duplicate",
                              result.stderr)

    def test_multi_config_uses_selected_executable(self):
        self.configure(multi_config=True)
        for config in ("Debug", "Release"):
            with self.subTest(config=config):
                self.build_cases(config)
                tests = self.list_cases(config)
                self.assertEqual(len(tests), 3)
                self.assertTrue(all(f"/{config}/" in t["command"][0] for t in tests))
                self.command("ctest", "--test-dir", str(self.build), "-C", config,
                             "-R", "^cases/alpha$", "--output-on-failure")


if __name__ == "__main__":
    unittest.main()
