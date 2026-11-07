"""Public API export stays lossless, deterministic and strict about drift."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest


TOOL = Path(__file__).resolve().parents[1] / "export_api_schema.py"
SPEC = importlib.util.spec_from_file_location("export_api_schema", TOOL)
API = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(API)


class ExportApiTests(unittest.TestCase):
    """Exercise API contracts and strict declaration parsing."""

    def setUp(self):
        """Load the canonical declarations and their exported manifest."""
        self.source = API.DEFAULT_SOURCE.read_text(encoding="utf-8")
        self.manifest = API.export(self.source)

    def test_runtime_contract_and_optional_context(self):
        """Preserve action values and optional telemetry context fields."""
        constants = {c["name"]: c for c in self.manifest["constants"]}
        self.assertEqual(constants["KEEP"]["value"], "keep")
        self.assertEqual(constants["DROP"]["value"], "drop")
        self.assertNotIn("MODIFY", constants)
        self.assertNotIn("ERROR", constants)
        self.assertNotIn("value", constants["null"])
        fields = {f["name"]: f for f in self.manifest["types"]["FtsLogRecord"]["fields"]}
        self.assertEqual(fields["body"]["type"], "FtsMap")
        self.assertTrue(fields["attributes"]["optional"])
        self.assertTrue(fields["resource"]["optional"])
        self.assertNotIn("severity_number", fields)
        for name, expected in [("FtsResource", {"schema_url": "string?",
                                               "dropped_attributes_count": "integer?"}),
                               ("FtsScope", {"name": "string?", "version": "string?"})]:
            fields = {f["name"]: f for f in self.manifest["types"][name]["fields"]}
            for field, expression in expected.items():
                self.assertTrue(fields[field]["optional"])
                self.assertEqual(fields[field]["type"], expression)

    def test_function_contracts_are_preserved(self):
        """Retain signatures, availability, inheritance and callback aliases."""
        functions = {f["name"]: f for f in self.manifest["modules"]["fb"]["functions"]}
        self.assertEqual(functions["parse_json"]["returns"][0]["type"], "FtsValue")
        self.assertTrue(functions["parse_json"]["nodiscard"])
        self.assertFalse(functions["redact"]["nodiscard"])
        self.assertTrue(functions["redact"]["parameters"][-1]["optional"])
        self.assertEqual(functions["log_field"]["signals"], ["logs"])
        self.assertEqual(functions["literal"]["modes"], ["pack"])
        types = self.manifest["types"]
        self.assertEqual(types["FtsArray"]["generics"], ["T"])
        self.assertEqual(types["FtsUInt64"]["extends"], "FtsValue")
        self.assertIn("FtsClassicResultCode", types["FtsClassicFilterCallback"]["type"])
        self.assertIn("timestamp: FtsTimestamp|number", types["FtsClassicFilterCallback"]["type"])
        self.assertIn("FtsTimestamp|number|nil", types["FtsClassicFilterCallback"]["type"])
        window = {m["name"]: m for m in types["FtsMetricWindow"]["methods"]}
        self.assertEqual(len(window["get"]["returns"]), 3)

    def test_cli_deterministic_export_and_stale_detection(self):
        """Check stable CLI output and failure on stale generated artifacts."""
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "nested/api.json"
            command = [sys.executable, str(TOOL), "--output", str(output)]
            subprocess.run(command, check=True)
            self.assertEqual(json.loads(output.read_text()), self.manifest)
            original = output.read_bytes()
            subprocess.run(command, check=True)
            self.assertEqual(output.read_bytes(), original)
            subprocess.run(command + ["--check"], check=True)
            output.write_text("{}\n")
            result = subprocess.run(command + ["--check"], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn("stale API manifest", result.stderr)

    def test_json_helper_signatures_and_availability(self):
        """Expose safe JSON decoding with its tuple returns and log-only helper."""
        functions = {f["name"]: f for f in self.manifest["modules"]["fb"]["functions"]}
        for name, result in [("try_parse_json", "FtsValue?"), ("decode_json", "boolean"),
                             ("unpack_json", "boolean")]:
            self.assertEqual([r["type"] for r in functions[name]["returns"]], [result, "string?"])
        self.assertTrue(functions["try_parse_json"]["nodiscard"])
        self.assertFalse(functions["decode_json"]["nodiscard"])
        self.assertFalse(functions["unpack_json"]["nodiscard"])
        self.assertEqual(functions["decode_json"]["signals"], ["logs", "metrics", "traces"])
        self.assertEqual(functions["unpack_json"]["signals"], ["logs"])
        self.assertTrue(functions["unpack_json"]["parameters"][1]["optional"])

    def test_unsupported_or_incomplete_declarations_fail(self):
        """Reject unsupported syntax and annotations without a declaration."""
        for old, new in [
            ("---@param text string", "---@unknown text string"),
            ("---@param text string", "---@param text string | nil"),
            ("---@param text string", "---@param text string| nil"),
            ("function fb.map() end", "function fb.map(untyped) end"),
            ("function fb.map() end", "function missing.map() end"),
            ("---@class FtsMap: FtsValue", "---@class FtsValue"),
            ("return fb", "---@type string\nreturn fb"),
            ("return fb", "--- Unattached description.\nreturn fb"),
        ]:
            with self.subTest(new=new), self.assertRaises(ValueError):
                API.export(self.source.replace(old, new, 1))
        with self.assertRaises(ValueError):
            API.export("")

    def test_generic_names_and_dotted_literals(self):
        """Trim generic names and parse dotted values as JSON literals."""
        source = self.source.replace("FtsArray<T>", "FtsArray<T, U>", 1)
        source = source.replace("return fb", '''---@type string
fb.test_string = "api.example.com"
---@type number
fb.test_number = 1.5
return fb''')
        manifest = API.export(source)
        self.assertEqual(manifest["types"]["FtsArray"]["generics"], ["T", "U"])
        constants = {constant["name"]: constant for constant in manifest["constants"]}
        self.assertEqual(constants["test_string"]["value"], "api.example.com")
        self.assertEqual(constants["test_number"]["value"], 1.5)


if __name__ == "__main__":
    unittest.main()
