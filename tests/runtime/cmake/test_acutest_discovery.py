"""Exercise runtime-case discovery with real Acutest, CMake, and CTest."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
MODULE = ROOT / "tests/runtime/cmake/FluentBitTest.cmake"
HEADER = ROOT / "tests/lib/acutest/acutest.h"


def cmake_version():
    if not shutil.which("cmake"):
        return ()
    result = subprocess.run(["cmake", "--version"], capture_output=True, text=True, timeout=10)
    match = re.search(r"cmake version (\d+)\.(\d+)", result.stdout)
    return tuple(map(int, match.groups())) if match else ()


CMAKE_VERSION = cmake_version()


@unittest.skipUnless(CMAKE_VERSION >= (3, 12) and shutil.which("ninja"),
                     "requires CMake 3.12+, Ninja, and a C compiler")
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

    def command(self, *args, success=True, cwd=None):
        result = subprocess.run(args, capture_output=True, text=True, timeout=60, cwd=cwd)
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
        self.build.mkdir(exist_ok=True)
        self.command("cmake", str(self.source),
                     "-G", "Ninja Multi-Config" if multi_config else "Ninja",
                     "-DCMAKE_BUILD_TYPE=Debug", cwd=self.build)

    def build_cases(self, config="Debug"):
        self.command("cmake", "--build", str(self.build), "--config", config)

    def list_cases(self, config=None, success=True):
        command = ["ctest", "--show-only=json-v1"]
        if config:
            command += ["-C", config]
        result = self.command(*command, success=success, cwd=self.build)
        return json.loads(result.stdout)["tests"] if success else result

    @unittest.skipUnless(CMAKE_VERSION >= (3, 14), "CTest JSON output requires CMake 3.14+")
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
        result = self.command("ctest", "-R", "^cases/alpha with spaces$",
                              "--output-on-failure", cwd=self.build)
        self.assertIn("100% tests passed", result.stdout)
        self.assertIn("out of 1", result.stdout)

    def test_case_failures_reach_ctest(self):
        self.configure()
        self.build_cases()
        result = self.command("ctest", "-R", "^cases/failure$", "--output-on-failure",
                              success=False, cwd=self.build)
        self.assertIn("cases/failure", result.stdout)
        self.assertIn("0% tests passed", result.stdout)

    def test_unbuilt_target_is_visible(self):
        self.configure()
        result = self.command("ctest", "-N", "-L", "runtime", cwd=self.build)
        self.assertIn("cases/not_built", result.stdout)

    def test_empty_and_duplicate_lists_fail_discovery(self):
        for mode in ("empty", "duplicate"):
            with self.subTest(mode=mode):
                self.configure(**{mode: True})
                self.build_cases()
                result = self.command("ctest", "-N", cwd=self.build)
                self.assertIn("cases/discovery_failed", result.stdout)
                self.assertIn("No Acutest cases" if mode == "empty" else "Duplicate",
                              result.stderr)
                failed = self.command("ctest", "-R", "^cases/discovery_failed$",
                                      "--output-on-failure", success=False, cwd=self.build)
                self.assertIn("No Acutest cases" if mode == "empty" else "Duplicate",
                              failed.stdout)

    def test_unrunnable_executable_fails_discovery(self):
        self.configure()
        self.build_cases()
        executable = self.build / ("cases.exe" if os.name == "nt" else "cases")
        executable.write_bytes(b"not an executable\n")
        result = self.command("ctest", "-N", cwd=self.build)
        self.assertIn("Cannot discover cases", result.stderr)
        self.assertIn("cases/discovery_failed", result.stdout)
        failed = self.command("ctest", "-R", "^cases/discovery_failed$",
                              "--output-on-failure", success=False, cwd=self.build)
        self.assertIn("Cannot discover cases", failed.stdout)

    @unittest.skipUnless(CMAKE_VERSION >= (3, 17), "Ninja Multi-Config requires CMake 3.17+")
    def test_multi_config_uses_selected_executable(self):
        self.configure(multi_config=True)
        for config in (None, "Unknown"):
            with self.subTest(config=config):
                command = ["ctest", "-R", "^cases/discovery_failed$", "--output-on-failure"]
                if config:
                    command += ["-C", config]
                result = self.command(*command, success=False, cwd=self.build)
                self.assertIn("Select a test configuration", result.stdout)
        for config in ("Debug", "Release"):
            with self.subTest(config=config):
                self.build_cases(config)
                tests = self.list_cases(config)
                self.assertEqual(len(tests), 3)
                self.assertTrue(all(f"/{config}/" in t["command"][0] for t in tests))
                self.command("ctest", "-C", config, "-R", "^cases/alpha$",
                             "--output-on-failure", cwd=self.build)


if __name__ == "__main__":
    unittest.main()
