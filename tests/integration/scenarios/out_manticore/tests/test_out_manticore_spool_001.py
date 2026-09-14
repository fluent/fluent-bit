#!/usr/bin/env python3

"""Single-chunk retention and replay regressions using real Fluent Bit."""

import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time
import threading
import unittest

import pytest

from test_out_manticore_001 import read_request, send_response
from utils.fluent_bit_manager import FluentBitManager


pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="Manticore single_chunk is not supported on Windows"
)


CONFIG_FILE = Path(__file__).resolve().parent.parent / "config" / "out_manticore_spool.yaml"


SUCCESS = ("200 OK", {"errors": False})
RETRY = ("503 Service Unavailable", {"errors": True})
UNAUTHORIZED = ("401 Unauthorized", {"error": "authentication required"})
PERMANENT_ITEM = {"errors": True, "items": [{"insert": {"status": 409}}]}


class Receiver:
    def __init__(self, replies):
        self.replies = replies
        self.requests = []
        self.errors = []
        self.stopped = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stopped.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                with connection:
                    connection.settimeout(30)
                    request, headers, chunks = read_request(connection)
                    number = len(self.requests)
                    self.requests.append((request, headers, b"".join(chunks)))
                    status, body = self.replies[number]
                    send_response(connection, json.dumps(body).encode(), status)
            except Exception as error:
                self.errors.append(repr(error))

    def close(self):
        self.stopped.set()
        self.listener.close()
        self.thread.join(timeout=35)


class SpoolRecoveryTests(unittest.TestCase):
    def setUp(self):
        evidence = os.environ.get("MANTICORE_TEST_RESULTS")
        if evidence:
            self.root = Path(evidence) / self._testMethodName
            self.root.mkdir(parents=True, exist_ok=False)
        else:
            temporary = tempfile.TemporaryDirectory(prefix="manticore-spool-")
            self.addCleanup(temporary.cleanup)
            self.root = Path(temporary.name)
        self.spool = self.root / "spool.ndjson"
        self.journal = self.root / "spool.ndjson.commit"
        self.parser = self.root / "parsers.conf"
        self.fluent_bit = FluentBitManager().binary_absolute_path
        self.parser.write_text("[PARSER]\n    Name spool_json\n    Format json\n")
        self.receiver = None

    def tearDown(self):
        if self.receiver:
            self.receiver.close()
            requests = []
            for number, (request, headers, body) in enumerate(self.receiver.requests):
                (self.root / "request-{}.ndjson".format(number)).write_bytes(body)
                requests.append({"request": request, "headers": headers,
                                 "bytes": len(body)})
            (self.root / "requests.json").write_text(json.dumps(requests, indent=2))
            self.assertFalse(self.receiver.thread.is_alive())
            self.assertEqual(self.receiver.errors, [])

    def start_receiver(self, replies):
        self.receiver = Receiver(replies)

    def run_session(self, label, records, env=None, signal_after_spool=False):
        source = self.root / (label + ".json")
        source.write_text("".join(json.dumps(record) + "\n" for record in records))
        command = [self.fluent_bit, "-c", str(CONFIG_FILE)]
        session_env = os.environ.copy()
        session_env.update({
            "MANTICORE_INPUT_PATH": str(source),
            "MANTICORE_PARSERS_FILE": str(self.parser),
            "MANTICORE_PORT": str(self.receiver.port),
            "MANTICORE_SPOOL_PATH": str(self.spool),
            "MANTICORE_EXIT_ON_EOF": "false" if signal_after_spool else "true",
        })
        if env:
            session_env.update(env)
        (self.root / (label + "-command.json")).write_text(json.dumps(command))
        if signal_after_spool:
            child = subprocess.Popen(command, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True,
                                     env=session_env)
            deadline = time.monotonic() + 30
            while not self.spool.exists() and child.poll() is None:
                if time.monotonic() >= deadline:
                    child.kill()
                    output, _ = child.communicate()
                    self.fail("Manticore spool was not populated\n{}".format(output))
                time.sleep(0.1)
            if child.poll() is not None:
                output, _ = child.communicate()
                self.fail("Fluent Bit exited before SIGTERM\n{}".format(output))
            child.send_signal(signal.SIGTERM)
            output, _ = child.communicate(timeout=120)
            process = subprocess.CompletedProcess(command, child.returncode,
                                                  output, None)
        else:
            process = subprocess.run(command, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True,
                                     timeout=120, env=session_env)
        (self.root / (label + ".log")).write_text(process.stdout)
        (self.root / (label + "-exit.txt")).write_text(str(process.returncode))
        for name, path in [("spool", self.spool), ("journal", self.journal)]:
            if path.exists():
                (self.root / (label + "." + name)).write_bytes(path.read_bytes())
        return process

    def assert_exit(self, process, expected):
        self.assertEqual(process.returncode, expected, process.stdout)

    def assert_removed(self):
        self.assertFalse(self.spool.exists())
        self.assertFalse(self.journal.exists())

    def assert_ids(self, expected):
        actual = []
        for request, headers, body in self.receiver.requests:
            self.assertEqual(request, "POST /bulk?bulk_import=spool_logs HTTP/1.1")
            self.assertEqual(headers["transfer-encoding"].lower(), "chunked")
            actual.append([json.loads(line)["insert"]["id"]
                           for line in body.splitlines()])
        self.assertEqual(actual, expected)

    def check_rejection(self, rejection):
        self.start_receiver([rejection, SUCCESS])
        failed = self.run_session("rejected", [{"id": 101, "message": "retained"}])
        self.assert_exit(failed, 0)
        self.assertIn("preserving spool", failed.stdout)
        self.assertTrue(self.spool.exists())
        self.assertEqual(self.spool.read_bytes(), self.receiver.requests[0][2])
        recovered = self.run_session("recovered", [])
        self.assert_exit(recovered, 0)
        self.assert_ids([[101], [101]])
        self.assertEqual(self.receiver.requests[0][2], self.receiver.requests[1][2])
        self.assert_removed()

    def test_replay_then_new_input(self):
        self.start_receiver([RETRY, SUCCESS, RETRY, SUCCESS])
        first = self.run_session("first", [{"id": 101, "message": "old"}])
        self.assert_exit(first, 0)
        second = self.run_session("second", [{"id": 102, "message": "new"}])
        self.assert_exit(second, 0)
        third = self.run_session("third", [])
        self.assert_exit(third, 0)
        self.assert_ids([[101], [101], [102], [102]])
        self.assertEqual(self.receiver.requests[2][2], self.receiver.requests[3][2])
        self.assert_removed()

    def test_auth_rejection_retains_accepted_data(self):
        self.check_rejection(UNAUTHORIZED)

    def test_permanent_item_in_http_500_retains_accepted_data(self):
        self.check_rejection(("500 Internal Server Error", PERMANENT_ITEM))

    def test_permanent_item_in_http_200_retains_accepted_data(self):
        self.check_rejection(("200 OK", PERMANENT_ITEM))

    def test_transient_rejection_retains_accepted_data(self):
        self.check_rejection(RETRY)

    def test_signal_final_rejection_is_best_effort(self):
        self.start_receiver([RETRY, SUCCESS])
        failed = self.run_session("signal-failed", [{"id": 101, "message": "retained"}],
                                  signal_after_spool=True)
        self.assert_exit(failed, 0)
        self.assertIn("preserving spool", failed.stdout)
        self.assertTrue(self.spool.exists())
        self.assertTrue(self.journal.exists())
        recovered = self.run_session("signal-recovered", [])
        self.assert_exit(recovered, 0)
        self.assert_ids([[101], [101]])
        self.assert_removed()

    def test_rejected_startup_replay_preserves_data(self):
        self.start_receiver([RETRY, UNAUTHORIZED, SUCCESS])
        first = self.run_session("first", [{"id": 101, "message": "pending"}])
        self.assert_exit(first, 0)
        spool, journal = self.spool.read_bytes(), self.journal.read_bytes()
        rejected = self.run_session("rejected-replay", [])
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout)
        self.assertEqual(self.spool.read_bytes(), spool)
        self.assertEqual(self.journal.read_bytes(), journal)
        recovered = self.run_session("recovered", [])
        self.assert_exit(recovered, 0)
        self.assert_ids([[101], [101], [101]])
        self.assert_removed()
