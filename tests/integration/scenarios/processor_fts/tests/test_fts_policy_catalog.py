"""Replay the consumable catalog against the real native runtime."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[5]
CATALOG = ROOT / "packs/fts"
spec = importlib.util.spec_from_file_location("fts_catalog_fixture", ROOT / "tools/fts/fts_fixture.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def test_pack_directories_match_declared_signals():
    manifests = list(CATALOG.rglob("pack.json"))
    assert len(manifests) == 21
    for path in manifests:
        manifest = json.loads(path.read_text())
        signals = {signal for block in manifest["blocks"] for signal in block["signals"]}
        assert signals and signals <= {"logs", "metrics", "traces"}
        category = next(iter(signals)) if len(signals) == 1 else "multisignal"
        assert path.parent.parent == CATALOG / category
        assert not path.parent.name[0].isdigit()
        assert (path.parent / "README.md").is_file()



def test_policy_catalog_real_runtime():
    catalog = json.loads((CATALOG / "catalog.json").read_text())
    entries = catalog["policies"]
    assert len(entries) == 20
    assert len({entry["id"] for entry in entries}) == len(entries)
    assert all("number" not in entry for entry in entries)
    pending = [entry for entry in entries if entry["status"] == "pending"]
    assert {entry["id"] for entry in pending} == {"ocsf", "tenant-egress"}
    for entry in pending:
        assert entry["dependency"]
        assert not (CATALOG / entry["path"] / "pack.json").exists()
    fixtures = []
    expected_cases = 0
    available = [entry for entry in entries if entry["status"] != "pending"]
    assert len(available) == 18
    for entry in available:
        directory = CATALOG / entry["path"]
        manifest = json.loads((directory / "pack.json").read_text())
        signals = {signal for block in manifest["blocks"] for signal in block["signals"]}
        assert set(entry["signals"]) == signals
        category = next(iter(signals)) if len(signals) == 1 else "multisignal"
        assert directory.parent == CATALOG / category
        assert manifest["fixtures"]
        for reference in manifest["fixtures"]:
            path = directory / reference
            fixtures.append(path)
            expected_cases += len(runner.load_fixture(path)["cases"])
    assert expected_cases >= 51
    command = [sys.executable, str(ROOT / "tools/fts/fts_fixture.py"),
        "--binary", os.environ.get("FLUENT_BIT_BINARY", str(ROOT / "build/bin/fluent-bit"))]
    if os.environ.get("VALGRIND") == "1":
        command.append("--valgrind")
    command += [str(path) for path in fixtures]
    result = subprocess.run(command, capture_output=True, text=True, timeout=600)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.count("PASS ") == expected_cases
