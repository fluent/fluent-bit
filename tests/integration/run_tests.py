#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import sys
from collections import OrderedDict
from pathlib import Path


SUITE_ROOT = Path(__file__).resolve().parent
VENV_PYTHON = SUITE_ROOT / ".venv" / "bin" / "python3"
REEXEC_ENV = "FLB_SUITE_WRAPPER_REEXEC"


def _maybe_reexec_in_venv() -> None:
    if os.environ.get(REEXEC_ENV) == "1":
        return

    if not VENV_PYTHON.is_file():
        return

    current = Path(sys.executable).resolve()
    target = VENV_PYTHON.resolve()

    if current == target:
        return

    env = os.environ.copy()
    env[REEXEC_ENV] = "1"
    os.execve(str(target), [str(target), str(Path(__file__).resolve()), *sys.argv[1:]], env)


_maybe_reexec_in_venv()

try:
    import pytest  # noqa: E402
except ModuleNotFoundError:
    if VENV_PYTHON.is_file() and os.environ.get(REEXEC_ENV) != "1":
        env = os.environ.copy()
        env[REEXEC_ENV] = "1"
        os.execve(str(VENV_PYTHON), [str(VENV_PYTHON), str(Path(__file__).resolve()), *sys.argv[1:]], env)
    raise


STATUS_PENDING = "pending"
STATUS_RUNNING = "running"
STATUS_PASSED = "passed"
STATUS_FAILED = "failed"
STATUS_SKIPPED = "skipped"

STATUS_ICON = {
    STATUS_PENDING: "[ ]",
    STATUS_RUNNING: "[>]",
    STATUS_PASSED: "[x]",
    STATUS_FAILED: "[!]",
    STATUS_SKIPPED: "[-]",
}


def scenario_name_from_nodeid(nodeid: str) -> str:
    path = nodeid.split("::", 1)[0]
    parts = path.split("/")
    if "scenarios" in parts:
        index = parts.index("scenarios")
        if index + 1 < len(parts):
            return parts[index + 1]
    return Path(path).stem


def short_name_from_nodeid(nodeid: str) -> str:
    path, _, test_name = nodeid.partition("::")
    return f"{Path(path).name}::{test_name}" if test_name else Path(path).name


class CollectPlugin:
    def __init__(self) -> None:
        self.nodeids: list[str] = []

    def pytest_collection_modifyitems(self, session, config, items):
        self.nodeids = [item.nodeid for item in items]


class CheckboxProgressPlugin:
    def __init__(self) -> None:
        self.nodeids: list[str] = []
        self.statuses: OrderedDict[str, str] = OrderedDict()
        self.terminal_reporter = None
        self.use_tty = sys.stdout.isatty()
        self._listed_non_tty = False

    def pytest_configure(self, config):
        self.terminal_reporter = config.pluginmanager.getplugin("terminalreporter")

    def pytest_collection_modifyitems(self, session, config, items):
        self.nodeids = [item.nodeid for item in items]
        self.statuses = OrderedDict((nodeid, STATUS_PENDING) for nodeid in self.nodeids)
        self._render()

    def pytest_runtest_logstart(self, nodeid, location):
        if nodeid in self.statuses and self.statuses[nodeid] == STATUS_PENDING:
            self.statuses[nodeid] = STATUS_RUNNING
            self._render(changed_nodeid=nodeid)

    def pytest_runtest_logreport(self, report):
        nodeid = report.nodeid
        if nodeid not in self.statuses:
            return

        if report.when == "setup" and report.skipped:
            self.statuses[nodeid] = STATUS_SKIPPED
            self._render(changed_nodeid=nodeid)
            return

        if report.when == "call":
            if report.passed:
                self.statuses[nodeid] = STATUS_PASSED
            elif report.failed:
                self.statuses[nodeid] = STATUS_FAILED
            elif report.skipped:
                self.statuses[nodeid] = STATUS_SKIPPED
            self._render(changed_nodeid=nodeid)
            return

        if report.when == "teardown" and report.failed:
            self.statuses[nodeid] = STATUS_FAILED
            self._render(changed_nodeid=nodeid)

    def pytest_sessionfinish(self, session, exitstatus):
        self._render(final=True)

    def _summary(self) -> dict[str, int]:
        counts = {
            STATUS_PENDING: 0,
            STATUS_RUNNING: 0,
            STATUS_PASSED: 0,
            STATUS_FAILED: 0,
            STATUS_SKIPPED: 0,
        }
        for status in self.statuses.values():
            counts[status] += 1
        return counts

    def _grouped_lines(self) -> list[str]:
        groups: OrderedDict[str, list[str]] = OrderedDict()
        for nodeid in self.nodeids:
            groups.setdefault(scenario_name_from_nodeid(nodeid), []).append(nodeid)

        lines: list[str] = []
        for scenario, nodeids in groups.items():
            lines.append(f"{scenario}")
            for nodeid in nodeids:
                lines.append(f"  {STATUS_ICON[self.statuses[nodeid]]} {short_name_from_nodeid(nodeid)}")
        return lines

    def _render(self, final: bool = False, changed_nodeid: str | None = None):
        if not self.terminal_reporter or not self.nodeids:
            return

        summary = self._summary()
        done = (
            summary[STATUS_PASSED]
            + summary[STATUS_FAILED]
            + summary[STATUS_SKIPPED]
        )
        total = len(self.nodeids)
        lines = [
            "Suite Progress",
            (
                f"  done {done}/{total}  "
                f"passed {summary[STATUS_PASSED]}  "
                f"failed {summary[STATUS_FAILED]}  "
                f"skipped {summary[STATUS_SKIPPED]}  "
                f"running {summary[STATUS_RUNNING]}  "
                f"pending {summary[STATUS_PENDING]}"
            ),
            "",
            *self._grouped_lines(),
        ]
        output = "\n".join(lines)

        if self.use_tty:
            self.terminal_reporter.write("\x1b[2J\x1b[H" + output + ("\n" if final else ""), flush=True)
        else:
            if not self._listed_non_tty:
                self.terminal_reporter.write_line(f"Collected {total} tests")
                for line in self._grouped_lines():
                    self.terminal_reporter.write_line(line)
                self._listed_non_tty = True
                return

            if changed_nodeid is not None:
                self.terminal_reporter.write_line(
                    f"{STATUS_ICON[self.statuses[changed_nodeid]]} {changed_nodeid}"
                )

            if final:
                self.terminal_reporter.write_line(
                    (
                        f"Summary: passed {summary[STATUS_PASSED]}, "
                        f"failed {summary[STATUS_FAILED]}, "
                        f"skipped {summary[STATUS_SKIPPED]}"
                    )
                )


def build_pytest_args(args, passthrough: list[str]) -> list[str]:
    pytest_args = [
        "--rootdir",
        str(SUITE_ROOT),
    ]

    if not args.show_logs:
        pytest_args.extend(["-o", "log_cli=false"])

    if args.list_only:
        pytest_args.extend(["--collect-only", "-q"])
    elif args.quiet:
        pytest_args.append("-q")
    else:
        pytest_args.append("-vv")

    pytest_args.extend(passthrough)

    if not passthrough:
        pytest_args.append("scenarios")

    return pytest_args


def print_collected_tests(nodeids: list[str]) -> None:
    groups: OrderedDict[str, list[str]] = OrderedDict()
    for nodeid in nodeids:
        groups.setdefault(scenario_name_from_nodeid(nodeid), []).append(nodeid)

    total = len(nodeids)
    print(f"Collected {total} tests")
    for scenario, scenario_tests in groups.items():
        print()
        print(f"{scenario} ({len(scenario_tests)})")
        for nodeid in scenario_tests:
            print(f"  [ ] {short_name_from_nodeid(nodeid)}")


def parse_args(argv: list[str]) -> tuple[argparse.Namespace, list[str]]:
    parser = argparse.ArgumentParser(
        description="List and run the Fluent Bit Python test suite with a simple checkbox progress view."
    )
    parser.add_argument("--list", dest="list_only", action="store_true", help="List collected tests and exit.")
    parser.add_argument("--binary", help="Set FLUENT_BIT_BINARY for this run.")
    parser.add_argument("--valgrind", action="store_true", help="Run with VALGRIND=1.")
    parser.add_argument(
        "--valgrind-strict",
        action="store_true",
        help="Run with VALGRIND=1 and VALGRIND_STRICT=1.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Use quieter pytest output; checkbox progress still renders.",
    )
    parser.add_argument(
        "--show-logs",
        action="store_true",
        help="Keep pytest live logs enabled instead of the cleaner wrapper view.",
    )
    return parser.parse_known_args(argv)


def main(argv: list[str] | None = None) -> int:
    args, passthrough = parse_args(argv or sys.argv[1:])

    os.chdir(SUITE_ROOT)

    if args.binary:
        os.environ["FLUENT_BIT_BINARY"] = args.binary
    if args.valgrind or args.valgrind_strict:
        os.environ["VALGRIND"] = "1"
    if args.valgrind_strict:
        os.environ["VALGRIND_STRICT"] = "1"

    if args.list_only:
        collector = CollectPlugin()
        exit_code = pytest.main(build_pytest_args(args, passthrough), plugins=[collector])
        if exit_code != 0:
            return exit_code
        print_collected_tests(collector.nodeids)
        return 0

    progress = CheckboxProgressPlugin()
    return pytest.main(build_pytest_args(args, passthrough), plugins=[progress])


if __name__ == "__main__":
    raise SystemExit(main())
