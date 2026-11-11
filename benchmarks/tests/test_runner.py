"""Measurement contracts and failure paths, independent of a Fluent Bit build."""

import argparse
import http.server
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location("benchmark_runner", ROOT / "run.py")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def observation(system, repetition, cpu, status="valid"):
    return {"system": system, "repetition": repetition, "status": status,
            "cpu_seconds_per_million_records": cpu,
            "completed_records_per_second": 1000,
            "sampled_peak_rss_mib": 20, "cooldown_rss_mib": 15,
            "request_ack_p99_us": 50}


class RunnerTests(unittest.TestCase):
    def test_missing_counter_is_unknown(self):
        with self.assertRaises(ValueError):
            runner.required_counter({}, "records")
        self.assertEqual(runner.required_counter({"records": 0}, "records"), 0)

    def test_reject_negative_counter(self):
        for value in (-1, float("nan"), float("inf"), True):
            with self.assertRaises(ValueError):
                runner.required_counter({"records": value}, "records")

    def test_reconciliation_rejects_loss_and_excess(self):
        for completed in (9, 11):
            with self.assertRaises(ValueError):
                runner.reconcile({"accepted": 10, "completed": completed,
                                  "errors": 0, "dropped": 0}, 10)

    def test_reconciliation_rejects_errors_even_with_matching_counts(self):
        with self.assertRaises(ValueError):
            runner.reconcile({"accepted": 10, "completed": 10,
                              "errors": 1, "dropped": 0}, 10)

    def test_summary_exposes_excluded_runs(self):
        rows = [observation("base", 1, 10), observation("base", 2, 100, "invalid")]
        summary = runner.summarize(rows)["base"]
        self.assertEqual(summary["runs"], 2)
        self.assertEqual(summary["valid_runs"], 1)
        self.assertEqual(summary["cpu_seconds_per_million_records"]["median"], 10)

    def test_pair_by_repetition_and_exclude_invalid_pairs(self):
        rows = [observation("base", 1, 10), observation("base", 2, 100),
                observation("new", 2, 50), observation("new", 1, 1, "invalid")]
        comparison = runner.compare(rows)["new"]
        self.assertEqual(comparison["valid_pairs"], 1)
        self.assertEqual(comparison["status"], "insufficient_repetitions")
        self.assertEqual(comparison["changes"]["cpu_seconds_per_million_records"]
                         ["median_change_percent"], -50)

    def test_json_payload_does_not_require_protobuf(self):
        with mock.patch.dict(sys.modules, {"google.protobuf.json_format": None}):
            payload = runner.otlp.make_payloads(7, ("json",))["json"]
        request = json.loads(payload)
        self.assertEqual(len(request["resourceLogs"][0]["scopeLogs"][0]["logRecords"]), 7)

    def test_generated_worker_count(self):
        config = runner.otlp.fluent_config(1000, 1001, False, 0.5, "", workers=7)
        self.assertIn("http_server.workers: 7", config)

    def test_metric_adapter_rejects_missing_instances(self):
        with mock.patch.object(runner.otlp, "scrape", return_value='{"input":{},"output":{}}'):
            with self.assertRaises(ValueError):
                runner.metrics(1, "missing", "missing")

    def test_mismatch_fails_without_waiting_for_deadline(self):
        process = mock.Mock()
        process.poll.return_value = None
        args = argparse.Namespace(input_instance="in", output_instance="out")
        with mock.patch.object(runner, "metrics", return_value={
                "accepted": 12, "completed": 12, "errors": 0, "dropped": 0}):
            with self.assertRaisesRegex(ValueError, "accounting mismatch"):
                runner.wait_count(process, 1, args, 10, time.monotonic() + 20)

    def test_missing_metrics_deadline(self):
        process = mock.Mock()
        process.poll.return_value = None
        args = argparse.Namespace(input_instance="in", output_instance="out")
        with mock.patch.object(runner, "metrics", side_effect=ValueError("missing")):
            with self.assertRaisesRegex(TimeoutError, "missing"):
                runner.wait_count(process, 1, args, 10, time.monotonic() + 0.01)

    @unittest.skipUnless(sys.platform == "linux", "Linux runner")
    def test_failed_binary_preserves_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "run"
            result = runner.main(["--system", "failure=/bin/false", "--records", "100",
                                  "--warmup-records", "0", "--runs", "1",
                                  "--output", str(output)])
            self.assertEqual(result, 2)
            self.assertEqual(json.loads((output / "manifest.json").read_text())["status"], "needs_review")
            self.assertEqual(json.loads((output / "results.json").read_text())[0]["status"], "invalid")
            self.assertTrue((output / "01-failure/config.yaml").exists())
            self.assertTrue((output / "01-failure/server.log").exists())
            self.assertTrue((output / "report.md").exists())

    @unittest.skipUnless(sys.platform == "linux", "Linux runner")
    def test_campaign_rotates_order_and_retains_interruption(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "run"
            order = []

            def trial(binary, directory, *args):
                order.append(directory.name)
                if len(order) == 4:
                    raise KeyboardInterrupt()
                row = observation("unused", 0, 10)
                del row["system"]
                del row["repetition"]
                return row

            with mock.patch.object(runner, "run_trial", side_effect=trial):
                with self.assertRaises(KeyboardInterrupt):
                    runner.main(["--system", "a=/bin/true", "--system", "b=/bin/true",
                                 "--records", "100", "--runs", "2", "--output", str(output)])
            self.assertEqual(order, ["01-a", "01-b", "02-b", "02-a"])
            self.assertEqual(json.loads((output / "manifest.json").read_text())["status"], "interrupted")
            self.assertEqual(len(json.loads((output / "results.json").read_text())), 3)
            self.assertTrue((output / "results.csv").exists())

    def test_sender_rejects_partial_success_and_http_errors(self):
        for status, body in ((200, b'{"partialSuccess":{"rejectedLogRecords":"1"}}'),
                             (503, b"busy"), (201, b"{}")):
            with self.subTest(status=status):
                class Handler(http.server.BaseHTTPRequestHandler):
                    def do_POST(self):
                        self.rfile.read(int(self.headers["Content-Length"]))
                        self.send_response(status)
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)

                    def log_message(self, *args):
                        pass

                server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
                thread = threading.Thread(target=server.serve_forever)
                thread.start()
                runner.send.content_type = "application/json"
                try:
                    if status == 201:
                        result = runner.send(server.server_port, b"{}", 1, 1, 1, 0,
                                             time.monotonic() + 5)
                        self.assertEqual(len(result[0]), 1)
                    else:
                        with self.assertRaises(RuntimeError):
                            runner.send(server.server_port, b"{}", 1, 1, 1, 0,
                                        time.monotonic() + 5)
                finally:
                    server.shutdown()
                    thread.join()
                    server.server_close()


if __name__ == "__main__":
    unittest.main()
