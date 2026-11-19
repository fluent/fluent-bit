"""Exercise release payload integrity and the publication dependency graph."""
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("wasm_release", ROOT / ".github/scripts/wasm_release.py")
RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE)
SHA = "a" * 40


class PayloadTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.files = {name: b"SDK asset\n" for name in RELEASE.REQUIRED}
        self.files["fluent-bit-runtime.wasm"] = b"\x00asm\x01\x00\x00\x00"
        self.files["package.json"] = b'{"version":"0.1.0-experimental"}'
        self.files["build-info.json"] = json.dumps({
            "source_commit": SHA, "build_commit": SHA, "sanitizer": "none",
            "experimental": True, "emscripten": "6.0.9",
        }).encode()

    def bundle(self, extra=None, bad_inner=False):
        sums = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n"
                       for name, data in sorted(self.files.items()) if name != "SHA256SUMS")
        self.files["SHA256SUMS"] = sums.encode()
        if bad_inner:
            self.files["fluent-bit.js"] = b"modified after checksum generation"
        archive = self.directory / f"{RELEASE.PACKAGE}.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            for name, data in self.files.items():
                entry = tarfile.TarInfo(f"{RELEASE.PACKAGE}/{name}")
                entry.size = len(data)
                output.addfile(entry, io.BytesIO(data))
            if extra:
                output.addfile(extra)
        checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
        self.directory.joinpath(f"{archive.name}.sha256").write_text(f"{checksum}  {archive.name}\n")
        return archive

    def prepare(self, tag=""):
        return RELEASE.prepare(self.directory, self.directory / "out", SHA, SHA,
                               "https://github.com/fluent/fluent-bit/actions/runs/1", tag)

    def test_snapshot_preserves_tested_archive_bytes(self):
        archive = self.bundle()
        manifest = self.prepare()
        self.assertEqual(manifest["release_tag"], f"wasm-browser-{SHA}")
        self.assertEqual((self.directory / "out" / manifest["archive"]).read_bytes(), archive.read_bytes())
        self.assertEqual(manifest["sha256"], hashlib.sha256(archive.read_bytes()).hexdigest())
        self.assertIn("ASan", manifest["validation"])
        self.assertEqual(len(list((self.directory / "out").iterdir())), 3)

    def test_version_assets_have_versioned_names(self):
        self.bundle()
        manifest = self.prepare("v5.2.0-rc1")
        self.assertEqual(manifest["archive"], f"{RELEASE.PACKAGE}-v5.2.0-rc1.tar.gz")
        self.assertEqual(manifest["release_tag"], "v5.2.0-rc1")

    def test_rejects_corrupt_archive(self):
        self.bundle().write_bytes(b"corrupt")
        with self.assertRaisesRegex(ValueError, "archive checksum"):
            self.prepare()

    def test_rejects_corrupt_sdk_file(self):
        self.bundle(bad_inner=True)
        with self.assertRaisesRegex(ValueError, "SDK file checksum"):
            self.prepare()

    def test_rejects_incomplete_sdk(self):
        del self.files["fluent-bit-pthread.js"]
        self.bundle()
        with self.assertRaisesRegex(ValueError, "incomplete SDK"):
            self.prepare()

    def test_rejects_wrong_build_and_sanitized_artifacts(self):
        for key, value in (("source_commit", "b" * 40), ("build_commit", "b" * 40),
                           ("sanitizer", "address"), ("experimental", False)):
            with self.subTest(key=key):
                original = self.files["build-info.json"]
                info = json.loads(original)
                info[key] = value
                self.files["build-info.json"] = json.dumps(info).encode()
                self.bundle()
                with self.assertRaisesRegex(ValueError, "build identity"):
                    self.prepare()
                self.files["build-info.json"] = original

    def test_rejects_links_and_path_traversal(self):
        for name, kind in (("../outside", tarfile.REGTYPE),
                           (f"{RELEASE.PACKAGE}/link", tarfile.SYMTYPE)):
            with self.subTest(name=name):
                entry = tarfile.TarInfo(name)
                entry.type = kind
                entry.linkname = "/etc/passwd"
                self.bundle(extra=entry)
                with self.assertRaisesRegex(ValueError, "archive"):
                    self.prepare()

    def test_rejects_unsafe_tag(self):
        self.bundle()
        with self.assertRaisesRegex(ValueError, "release tag"):
            self.prepare("../../master")


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workflow = yaml.safe_load((ROOT / ".github/workflows/wasm-browser.yaml").read_text())
        self.jobs = self.workflow["jobs"]

    def test_publication_requires_successful_complete_matrix(self):
        self.assertEqual(self.jobs["wasm"]["strategy"]["matrix"]["sanitizer"], ["none", "address"])
        self.assertIn("wasm", self.jobs["release-payload"]["needs"])
        self.assertIn("release-payload", self.jobs["publish"]["needs"])
        for name in ("wasm", "release-payload", "publish"):
            self.assertNotIn("always()", self.jobs[name].get("if", ""))
            self.assertFalse(self.jobs[name].get("continue-on-error", False))
            for step in self.jobs[name]["steps"]:
                self.assertFalse(step.get("continue-on-error", False))
        steps = self.jobs["wasm"]["steps"]
        commands = "\n".join(step.get("run", "") for step in steps)
        for script in ("sdk_test.py", "--pthread-only", "browser_page_test.py", "--fts-only"):
            self.assertIn(script, commands)
        self.assertGreater(next(i for i, step in enumerate(steps) if "Studio deployment" in step.get("name", "")),
                           next(i for i, step in enumerate(steps) if "startup failures" in step.get("name", "")))

    def test_only_publication_has_write_permission(self):
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})
        self.assertEqual(self.jobs["publish"]["permissions"], {"contents": "write"})
        condition = self.jobs["publish"]["if"]
        self.assertIn("github.event_name == 'push' && github.ref == 'refs/heads/master'", condition)
        self.assertIn("github.event_name != 'pull_request'", condition)
        self.assertIn("github.repository == 'fluent/fluent-bit'", condition)

    def test_staging_calls_sdk_workflow_after_release_creation(self):
        staging = yaml.safe_load((ROOT / ".github/workflows/staging-release.yaml").read_text())
        job = staging["jobs"]["staging-release-browser-sdk"]
        self.assertEqual(job["needs"], "staging-release-create-release")
        self.assertEqual(job["uses"], "./.github/workflows/wasm-browser.yaml")
        self.assertEqual(job["with"]["release_tag"], "v${{ inputs.version }}")

    def test_version_upload_is_idempotent_and_detects_remote_corruption(self):
        step = next(step for step in self.jobs["publish"]["steps"]
                    if step.get("name") == "Attach experimental SDK to version release")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assets = root / "release-assets"
            remote = root / "remote"
            assets.mkdir()
            remote.mkdir()
            for name in ("sdk.tar.gz", "sdk.tar.gz.sha256", "sdk.json"):
                (assets / name).write_text(name)
            (remote / "sdk.json").write_text("sdk.json")
            gh = root / "gh"
            gh.write_text("""#!/usr/bin/env python3
import pathlib, shutil, sys
args = sys.argv[1:]
remote = pathlib.Path('remote')
if args[:2] == ['release', 'view']:
    print('\\n'.join(p.name for p in remote.iterdir()))
elif args[:2] == ['release', 'download']:
    name = args[args.index('--pattern') + 1]
    shutil.copyfile(remote / name, pathlib.Path(args[args.index('--dir') + 1]) / name)
elif args[:2] == ['release', 'upload']:
    source = pathlib.Path(args[3])
    destination = remote / source.name
    assert not destination.exists(), 'existing asset must never be overwritten'
    shutil.copyfile(source, destination)
else:
    sys.exit('unexpected GitHub command: ' + repr(args))
""")
            gh.chmod(0o755)
            env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}", RELEASE_TAG="v5.2.0")
            for _ in range(2):
                result = subprocess.run(['bash', '-c', step['run']], cwd=root, env=env,
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                for asset in assets.iterdir():
                    self.assertEqual(asset.read_bytes(), (remote / asset.name).read_bytes())
                # Each Actions retry receives a fresh workspace.
                shutil.rmtree(root / 'existing')
            (remote / "sdk.json").write_text("changed remotely")
            result = subprocess.run(['bash', '-c', step['run']], cwd=root, env=env,
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((remote / "sdk.json").read_text(), "changed remotely")

    def test_assets_are_never_overwritten_and_are_verified_after_upload(self):
        uploads = [step for step in self.jobs["publish"]["steps"]
                   if "softprops/action-gh-release@" in step.get("uses", "")]
        self.assertEqual(len(uploads), 1)
        for step in uploads:
            self.assertFalse(step["with"]["overwrite_files"])
        self.assertFalse(uploads[0]["with"]["make_latest"])
        self.assertTrue(uploads[0]["with"]["prerelease"])
        attachment = next(step for step in self.jobs["publish"]["steps"]
                          if step.get("name") == "Attach experimental SDK to version release")
        self.assertIn('gh release upload "$RELEASE_TAG" "$flb_asset"', attachment["run"])
        self.assertNotIn("--clobber", attachment["run"])
        self.assertIn('cmp "$flb_asset" "existing/$flb_name"', attachment["run"])
        self.assertIn("gh release download", self.jobs["publish"]["steps"][-1]["run"])


if __name__ == "__main__":
    unittest.main()
