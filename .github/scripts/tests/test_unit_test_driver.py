"""Exercise CI scheduling controls and failure propagation without compiling Fluent Bit."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest


DRIVER = Path(__file__).resolve().parents[1] / "run-unit-tests.sh"
ROOT = Path(__file__).resolve().parents[3]


@unittest.skipUnless(shutil.which("node"), "workflow selector requires Node.js")
class UnitTestWorkflowFilters(unittest.TestCase):
    def workflow_matches(self, paths, event="pull_request", labels=(), return_outputs=False):
        source = (ROOT / ".github/workflows/unit-tests.yaml").read_text()
        selector = source.split("  select-unit-tests:\n", 1)[1].split("\n  run-ubuntu-unit-tests:", 1)[0]
        script = re.search(r"          script: \|\n((?:            .*\n|\n)+)", selector)
        self.assertIsNotNone(script)
        # Execute the actual workflow JavaScript with read-only API stubs.
        harness = '''
const fixture = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const outputs = {};
let apiCalls = 0;
const core = {setOutput: (name, value) => {outputs[name] = value;}};
const context = {eventName: fixture.event, repo: {owner: 'fluent', repo: 'fluent-bit'},
  payload: {pull_request: {number: 12707, labels: fixture.labels.map(name => ({name}))}}};
const github = {rest: {pulls: {listFiles: () => {}}}, paginate: async () => {
  apiCalls++;
  return fixture.files;
}};
(async () => {
  const select = async () => {
''' + textwrap.dedent(script.group(1)) + '''
  };
  await select();
  process.stdout.write(JSON.stringify({outputs, apiCalls}));
})().catch(error => {console.error(error); process.exit(1);});
'''
        files = [{"filename": p} if isinstance(p, str) else p for p in paths]
        result = subprocess.run(["node", "-e", harness],
                                input=json.dumps({"event": event, "files": files, "labels": labels}),
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        response = json.loads(result.stdout)
        self.assertEqual(response["apiCalls"], 1 if event == "pull_request" else 0)
        return response["outputs"] if return_outputs else response["outputs"]["run"]

    def test_qemu_requires_exact_pr_label(self):
        for labels, expected in [((), False), (("ci:qemu",), True),
                                 (("other",), False), (("ci:qemu-extra",), False)]:
            with self.subTest(labels=labels):
                result = self.workflow_matches(["src/flb_lib.c"], labels=labels,
                                               return_outputs=True)
                self.assertTrue(result["run"])
                self.assertEqual(result["qemu"], expected)

    def test_qemu_label_overrides_path_filter(self):
        result = self.workflow_matches(["packaging/example.spec"], labels=("ci:qemu",),
                                       return_outputs=True)
        self.assertEqual(result, {"run": True, "qemu": True})

    def test_push_and_manual_keep_qemu(self):
        for event in ("push", "workflow_dispatch"):
            self.assertEqual(self.workflow_matches([], event=event, return_outputs=True),
                             {"run": True, "qemu": True})

    def test_required_check_propagates_selected_qemu_failures(self):
        source = (ROOT / ".github/workflows/unit-tests.yaml").read_text()
        gate = source.split("      - name: Check build matrix status", 1)[1]
        expression = re.search(r"if: \$\{\{ (.+) \}\}", gate).group(1)
        for selected in ("true", "false"):
            for result in ("success", "failure", "cancelled", "skipped"):
                values = {
                    "needs.select-unit-tests.result": "success",
                    "needs.select-unit-tests.outputs.run": "true",
                    "needs.select-unit-tests.outputs.qemu": selected,
                    "needs.run-ubuntu-unit-tests.result": "success",
                    "needs.run-qemu-ubuntu-unit-tests.result": result,
                }
                js = expression
                for key, value in values.items():
                    js = js.replace(key, json.dumps(value))
                output = subprocess.check_output(
                    ["node", "-e", "process.stdout.write(JSON.stringify(" + js + "));"],
                    text=True)
                self.assertEqual(json.loads(output), selected == "true" and result != "success")

    def test_label_events_preserve_the_required_check(self):
        source = (ROOT / ".github/workflows/unit-tests.yaml").read_text()
        selector = source.split("  select-unit-tests:\n", 1)[1]
        gate = re.search(r"if: \$\{\{ (.+) \}\}", selector).group(1)
        aggregate = source.split("  run-all-unit-tests:\n", 1)[1]
        name = re.search(r"name: \$\{\{ (.+) \}\}", aggregate).group(1)
        for action in ("opened", "synchronize", "labeled", "unlabeled"):
            for label in ("ci:qemu", "docs-required", "ok-package-test"):
                expected = action not in ("labeled", "unlabeled") or label == "ci:qemu"
                values = {"github.event_name": "pull_request", "github.event.action": action,
                          "github.event.label.name": label}
                expressions = []
                for expression in (gate, name):
                    for key, value in values.items():
                        expression = expression.replace(key, json.dumps(value))
                    expressions.append(expression)
                output = subprocess.check_output(
                    ["node", "-e", "process.stdout.write(JSON.stringify([" +
                     ",".join(expressions) + "]));"], text=True)
                run, check_name = json.loads(output)
                self.assertEqual(run, expected)
                self.assertEqual(check_name == "Unit tests (matrix)", expected)
        self.assertIn("if: always() && needs.select-unit-tests.result != 'skipped'", aggregate)

    def test_ci_driver_and_workflow_changes_run_real_tests(self):
        for path in (".github/scripts/run-unit-tests.sh",
                     ".github/scripts/tests/test_unit_test_driver.py",
                     ".github/workflows/unit-tests.yaml",
                     ".github/workflows/skipped-unit-tests.yaml"):
            with self.subTest(path=path):
                self.assertTrue(self.workflow_matches([path]))

    def test_source_changes_still_run_real_tests(self):
        for path in ("src/flb_lib.c", "tests/runtime/cmake/FluentBitTest.cmake"):
            with self.subTest(path=path):
                self.assertTrue(self.workflow_matches([path]))

    def test_unrelated_packaging_and_workflow_changes_remain_skipped(self):
        for path in ("packaging/example.spec", "dockerfiles/example/Dockerfile",
                     ".github/workflows/release.yaml", ".gitignore"):
            with self.subTest(path=path):
                self.assertFalse(self.workflow_matches([path]))

    def test_mixed_changes_run_tests(self):
        self.assertTrue(self.workflow_matches([
            ".github/scripts/run-unit-tests.sh", "packaging/example.spec"]))
        self.assertFalse(self.workflow_matches([
            "packaging/example.spec", ".github/workflows/release.yaml"]))

    def test_renames_check_the_previous_path(self):
        self.assertTrue(self.workflow_matches([{
            "filename": "packaging/old-driver.sh",
            "previous_filename": ".github/scripts/run-unit-tests.sh"}]))

    def test_push_and_manual_runs_do_not_need_the_pr_api(self):
        for event in ("push", "workflow_dispatch"):
            with self.subTest(event=event):
                self.assertTrue(self.workflow_matches([], event=event))

    def test_empty_and_truncated_responses_run_tests(self):
        self.assertTrue(self.workflow_matches([]))
        self.assertTrue(self.workflow_matches(["packaging/example.spec"] * 3000))

    def test_only_one_workflow_publishes_the_required_check(self):
        self.assertFalse((ROOT / ".github/workflows/skipped-unit-tests.yaml").exists())
        workflows = list((ROOT / ".github/workflows").glob("*.yaml"))
        required = [p for p in workflows if "Unit tests (matrix)" in p.read_text()]
        self.assertEqual([p.name for p in required], ["unit-tests.yaml"])


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
               if k not in ("FLB_BUILD_JOBS", "FLB_TEST_JOBS", "FLB_TEST_SCOPE", "FLB_OPT", "LDFLAG")},
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

    def test_overrides_are_decimal(self):
        result, calls = self.run_driver(FLB_BUILD_JOBS="08", FLB_TEST_JOBS="012")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(["cmake", "--build", ".", "--parallel", "8"], calls)
        self.assertEqual(next(c for c in calls if c[0] == "ctest")[2], "12")

    def test_default_parallelism_uses_decimal_build_override(self):
        result, calls = self.run_driver(FLB_BUILD_JOBS="08")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(["cmake", "--build", ".", "--parallel", "8"], calls)
        self.assertEqual(next(c for c in calls if c[0] == "ctest")[2], "24")

    def test_sanitizer_keeps_core_count_and_expands_stack(self):
        result, calls = self.run_driver(FLB_OPT="-DFLB_SANITIZE_THREAD=On")
        self.assertEqual(result.returncode, 0, result.stderr)
        configure = next(c for c in calls if c[0] == "cmake")
        self.assertIn("-DFLB_SANITIZE_THREAD=On", configure)
        self.assertIn("-DFLB_CORO_STACK_SIZE=4194304", configure)
        self.assertEqual(next(c for c in calls if c[0] == "ctest")[2], "4")
        self.assertNotIn("-R", next(c for c in calls if c[0] == "ctest"))

    def test_sanitizer_smoke_scope_is_explicit_and_builds_selected_targets(self):
        result, calls = self.run_driver(FLB_OPT="-DFLB_SANITIZE_THREAD=On",
                                        FLB_TEST_SCOPE="sanitizer-smoke")
        self.assertEqual(result.returncode, 0, result.stderr)
        build = next(c for c in calls if c[:2] == ["cmake", "--build"])
        self.assertEqual(build[-4:],
                         ["--target", "flb-it-pack", "flb-it-config_map", "flb-it-plugin_alias"])
        ctest = next(c for c in calls if c[0] == "ctest")
        self.assertEqual(ctest[-2:], ["-R", "^flb-it-(pack|config_map|plugin_alias)$"])
        runner = (self.root / "build/ci-results/runner.txt").read_text()
        self.assertIn("test_scope=sanitizer-smoke", runner)

    def test_full_scope_does_not_filter_tests(self):
        result, calls = self.run_driver(FLB_TEST_SCOPE="full")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("--target", next(c for c in calls if c[:2] == ["cmake", "--build"]))
        self.assertNotIn("-R", next(c for c in calls if c[0] == "ctest"))

    def test_unknown_scope_is_rejected(self):
        result, calls = self.run_driver(FLB_TEST_SCOPE="smok")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unknown test scope", result.stderr)
        self.assertFalse(any(c[0] == "cmake" for c in calls))

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
        for value in ("0", "00", "000", "-1", "1+1"):
            with self.subTest(value=value):
                result, calls = self.run_driver(FLB_TEST_JOBS=value)
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
