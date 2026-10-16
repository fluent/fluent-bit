#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


SUITE_ROOT = Path(__file__).resolve().parent
VENV_PYTHON = SUITE_ROOT / ".venv" / "bin" / "python3"
REEXEC_ENV = "MONKEY_INTEGRATION_REEXEC"


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


def parse_args(argv: list[str]) -> tuple[argparse.Namespace, list[str]]:
    parser = argparse.ArgumentParser(description="Run Monkey integration tests.")
    parser.add_argument("--plain-binary", help="Set MONKEY_BIN_PLAIN for this run.")
    parser.add_argument("--openssl-binary", help="Set MONKEY_BIN_OPENSSL for this run.")
    parser.add_argument("--mbedtls-binary", help="Set MONKEY_BIN_MBEDTLS for this run.")
    parser.add_argument(
        "--binaries",
        choices=["all", "plain", "openssl", "mbedtls"],
        default="all",
        help="Limit the suite to a specific Monkey binary family.",
    )
    parser.add_argument("--valgrind", action="store_true", help="Run Monkey under valgrind.")
    parser.add_argument(
        "--valgrind-strict",
        action="store_true",
        help="Run Monkey under valgrind and fail on reported leaks/errors.",
    )
    parser.add_argument("--quiet", action="store_true", help="Run pytest with -q.")
    return parser.parse_known_args(argv)


def build_pytest_args(args: argparse.Namespace, passthrough: list[str]) -> list[str]:
    pytest_args = ["--rootdir", str(SUITE_ROOT)]

    if args.quiet:
        pytest_args.append("-q")
    else:
        pytest_args.append("-vv")

    pytest_args.extend(passthrough)
    if not passthrough:
        pytest_args.append(str(SUITE_ROOT / "tests"))

    return pytest_args


def main(argv: list[str]) -> int:
    args, passthrough = parse_args(argv)

    if args.plain_binary:
        os.environ["MONKEY_BIN_PLAIN"] = args.plain_binary
    if args.openssl_binary:
        os.environ["MONKEY_BIN_OPENSSL"] = args.openssl_binary
    if args.mbedtls_binary:
        os.environ["MONKEY_BIN_MBEDTLS"] = args.mbedtls_binary
    if args.binaries != "all":
        os.environ["MONKEY_TEST_BINARIES"] = args.binaries
    if args.valgrind:
        os.environ["MONKEY_VALGRIND"] = "1"
    if args.valgrind_strict:
        os.environ["MONKEY_VALGRIND"] = "1"
        os.environ["MONKEY_VALGRIND_STRICT"] = "1"

    return pytest.main(build_pytest_args(args, passthrough))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
