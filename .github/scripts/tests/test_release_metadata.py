"""Focused release metadata checks, including anonymous HTTP failures."""
import contextlib
import copy
import importlib.util
import io
import json
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("release_metadata", Path(__file__).parents[1] / "release_metadata.py")
metadata = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(metadata)
VERSION = "5.1.3"


def sample(version=VERSION):
    doc = {"fluent-bit": {"version": version, "schema_version": "1.0", "os": "Linux"}}
    for catalog, kind in (("customs", "custom"), ("inputs", "input"), ("processors", "processor"),
                          ("filters", "filter"), ("outputs", "output")):
        doc[catalog] = [{"name": "example", "type": kind, "description": "example plugin", "properties": {}}]
    return doc


class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.doc = sample()
        self.write_pair()

    def write_pair(self):
        for name, indent in zip(metadata.filenames(VERSION), (None, 2)):
            (self.directory / name).write_text(json.dumps(self.doc, indent=indent))

    def test_valid_pair_and_optional_v(self):
        self.assertEqual(metadata.validate_pair(self.directory, "v" + VERSION), self.doc)
        self.doc["fluent-bit"]["version"] = "v" + VERSION
        self.write_pair()
        metadata.validate_pair(self.directory, VERSION)
        for version in ("vv5.1.3", "master", "../5.1.3", "5.1", None):
            with self.subTest(version=version), self.assertRaises(ValueError):
                metadata.release_version(version)

    def test_missing_empty_malformed_and_nonstandard_json(self):
        path = self.directory / metadata.filenames(VERSION)[0]
        path.unlink()
        with self.assertRaisesRegex(ValueError, "No such file"):
            metadata.validate_pair(self.directory, VERSION)
        for data in (b"", b" \n", b"{", b"null", b'[]', b'{"x":NaN}', b'{"x":1,"x":2}'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                path.write_bytes(data)
                metadata.validate_pair(self.directory, VERSION)

    def test_wrong_version_and_mismatched_variants(self):
        with self.assertRaisesRegex(ValueError, "version mismatch"):
            metadata.validate(json.dumps(sample("5.1.2")), VERSION)
        self.doc["inputs"][0]["description"] = "changed"
        (self.directory / metadata.filenames(VERSION)[1]).write_text(json.dumps(self.doc))
        with self.assertRaisesRegex(ValueError, "variants differ"):
            metadata.validate_pair(self.directory, VERSION)

    def test_required_structure(self):
        for key in self.doc:
            bad = copy.deepcopy(self.doc)
            del bad[key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                metadata.validate(json.dumps(bad), VERSION)
        for field in ("schema_version", "os"):
            bad = copy.deepcopy(self.doc)
            del bad["fluent-bit"][field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                metadata.validate(json.dumps(bad), VERSION)
        for value in ({}, "bad", None, []):
            bad = copy.deepcopy(self.doc)
            bad["inputs"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                metadata.validate(json.dumps(bad), VERSION)
        for field, value in (("type", "output"), ("name", ""), ("properties", []), ("description", None)):
            bad = copy.deepcopy(self.doc)
            bad["inputs"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                metadata.validate(json.dumps(bad), VERSION)

    def test_maintenance_catalogs(self):
        for version in ("2.0.14", "2.1.10", "3.2.10"):
            doc = sample(version)
            del doc["processors"]
            metadata.validate(json.dumps(doc), version)
        doc["fluent-bit"]["version"] = "4.0.0"
        with self.assertRaisesRegex(ValueError, "processors"):
            metadata.validate(json.dumps(doc), "4.0.0")
        # Customs and processors can legitimately have no registered plugins.
        self.doc["customs"] = []
        self.doc["processors"] = []
        metadata.validate(json.dumps(self.doc), VERSION)

    @contextlib.contextmanager
    def server(self, responses):
        requests = []
        directory = self.directory

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append((self.path, dict(self.headers)))
                status, override = responses[min(len(requests) - 1, len(responses) - 1)]
                self.send_response(status)
                self.end_headers()
                if status == 200:
                    self.wfile.write(override if override is not None else (directory / self.path.rsplit('/', 1)[1]).read_bytes())

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                yield f"http://127.0.0.1:{server.server_port}", requests
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_public_success_is_anonymous_and_checks_both_paths(self):
        with self.server([(200, None)]) as (url, requests):
            metadata.verify(self.directory, VERSION, url, attempts=1, delay=0)
        self.assertEqual([p for p, h in requests], [f"/{VERSION}/{name}" for name in metadata.filenames(VERSION)])
        for _, headers in requests:
            self.assertNotIn("Authorization", headers)
            self.assertNotIn("Cookie", headers)

    def test_public_403_and_404_fail(self):
        for status in (403, 404):
            with self.subTest(status=status), self.server([(status, None)]) as (url, requests):
                with self.assertRaisesRegex(ValueError, f"{status}"):
                    metadata.verify(self.directory, VERSION, url, attempts=2, delay=0)
                self.assertEqual(len(requests), 4)

    def test_transient_failures_retry_then_succeed(self):
        with self.server([(503, None), (404, None), (200, None)]) as (url, requests):
            metadata.verify(self.directory, VERSION, url, attempts=2, delay=0)
            self.assertEqual(len(requests), 4)

    def test_public_invalid_wrong_version_mismatch_and_reformatted(self):
        variants = [b"", b"{", json.dumps(sample("5.1.2")).encode()]
        changed = sample()
        changed["outputs"][0]["description"] = "changed"
        variants += [json.dumps(changed).encode(), json.dumps(self.doc, indent=4).encode()]
        for data in variants:
            with self.subTest(data=data[:30]), self.server([(200, data)]) as (url, _):
                with self.assertRaisesRegex(ValueError, "Public metadata unavailable"):
                    metadata.verify(self.directory, VERSION, url, attempts=1, delay=0)

    def test_github_release_asset_paths(self):
        with self.server([(200, None)]) as (url, requests):
            metadata.verify(self.directory, VERSION, url, attempts=1, delay=0, release_assets=True)
        self.assertEqual([p for p, h in requests], [f"/v{VERSION}/{name}" for name in metadata.filenames(VERSION)])

    def test_final_http_redirect_is_not_success(self):
        result = subprocess.CompletedProcess([], 0, stdout=json.dumps(self.doc).encode() + b"\n302", stderr=b"")
        with patch.object(metadata.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(ValueError, "unsuccessful public HTTP response"):
                metadata.fetch("https://example.test/metadata.json")

    def test_staged_image_mismatch_fails_comparison(self):
        reference = self.directory / "reference"
        reference.mkdir()
        changed = sample()
        changed["inputs"][0]["description"] = "wrong image catalog"
        for name in metadata.filenames(VERSION):
            (reference / name).write_text(json.dumps(changed))
        with patch("sys.argv", ["release_metadata.py", "compare", "--version", VERSION,
                               "--directory", str(self.directory), "--reference-directory", str(reference)]), \
                contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(metadata.main(), 1)
            self.assertIn("exact release image", errors.getvalue())

    def test_network_error_is_bounded(self):
        with patch.object(metadata, "fetch", side_effect=subprocess.TimeoutExpired("curl", 35)), \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError, "bounded retries"):
                metadata.verify(self.directory, VERSION, attempts=2, delay=0)

    def test_generation_pins_image_and_has_no_tty(self):
        image = "ghcr.io/fluent/fluent-bit/staging@sha256:" + "a" * 64
        with patch.object(metadata.subprocess, "check_output", return_value=json.dumps(self.doc).encode()) as run, \
                patch("sys.argv", ["release_metadata.py", "generate", "--version", VERSION,
                                   "--image", image, "--directory", str(self.directory)]):
            self.assertEqual(metadata.main(), 0)
        self.assertEqual(run.call_args.args[0], ["docker", "run", "--rm", "--platform", "linux/amd64", image, "-J"])
        metadata.validate_pair(self.directory, VERSION)


if __name__ == "__main__":
    unittest.main()
