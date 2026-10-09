"""Guard required release metadata dependencies and explicit file transfers."""
import fnmatch
import shlex
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]


def workflow(name):
    return yaml.safe_load((ROOT / ".github/workflows" / name).read_text())


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.release = workflow("staging-release.yaml")["jobs"]

    def ancestors(self, name, visiting=None):
        visiting = set() if visiting is None else visiting
        self.assertNotIn(name, visiting, "workflow dependency cycle")
        needs = self.release[name].get("needs", [])
        if isinstance(needs, str):
            needs = [needs]
        result = set(needs)
        for dependency in needs:
            self.assertIn(dependency, self.release)
            result.update(self.ancestors(dependency, visiting | {name}))
        return result

    def test_publication_and_reporting_require_public_verification(self):
        names = ["yum-packages", "apt-packages", "update-non-linux-s3", "update-base-s3",
                 "source-s3", "images", "images-arch-specific-legacy-tags", "images-latest-tags", "images-windows",
                 "images-sign", "upload-cosign-key", "create-release", "create-docs-pr", "create-version-update-pr"]
        for suffix in names:
            name = "staging-release-" + suffix
            with self.subTest(job=name):
                self.assertIn("staging-release-publish-schema", self.ancestors(name))
                self.assertNotIn("always()", str(self.release[name].get("if", "")))
        for name in self.release:
            self.ancestors(name)

    def test_schema_steps_are_required_and_explicit(self):
        for name in ("staging-release-validate-schema", "staging-release-publish-schema"):
            job = self.release[name]
            self.assertNotIn("continue-on-error", job)
            for step in job["steps"]:
                self.assertFalse(step.get("continue-on-error", False))
                self.assertNotIn("*.json", str(step))
        publish = str(self.release["staging-release-publish-schema"]["steps"])
        self.assertIn("fluent-bit-schema-$VERSION.json", publish)
        self.assertIn("fluent-bit-schema-pretty-$VERSION.json", publish)
        self.assertIn("release_metadata.py verify", publish)
        self.assertNotIn("--acl", publish)

    def test_image_publication_is_pinned_to_validated_manifest(self):
        for name in ("staging-release-images", "staging-release-images-latest-tags"):
            job = self.release[name]
            self.assertIn("staging-release-validate-schema", job["needs"])
            self.assertIn("outputs.digest", job["env"]["SOURCE_DIGEST"])
            self.assertIn("outputs.debug-digest", job["env"]["SOURCE_DIGEST"])
            commands = "\n".join(step.get("run", "") for step in job["steps"])
            self.assertIn("docker://$STAGING_IMAGE_NAME@$SOURCE_DIGEST", commands)
            self.assertNotIn("docker://$STAGING_IMAGE_NAME:$TAG", commands)

    def test_github_assets_for_every_release_branch(self):
        steps = self.release["staging-release-create-release"]["steps"]
        actions = [step for step in steps if "softprops/action-gh-release@" in step.get("uses", "")]
        self.assertGreaterEqual(len(actions), 8)
        for step in actions:
            with self.subTest(branch=step["name"]):
                self.assertTrue(step["with"]["fail_on_unmatched_files"])
                self.assertTrue(step["with"]["overwrite_files"])
                self.assertEqual(step["with"]["files"].splitlines(), [
                    "metadata/fluent-bit-schema-${{ inputs.version }}.json",
                    "metadata/fluent-bit-schema-pretty-${{ inputs.version }}.json"])
        self.assertIn("--github-repository", steps[-1]["run"])
        for name in ("staging-release-create-docs-pr", "staging-release-create-version-update-pr"):
            self.assertIn("staging-release-create-release", self.ancestors(name))

    def test_staging_generation_and_transfer(self):
        jobs = workflow("staging-build.yaml")["jobs"]
        upload = jobs["staging-build-upload-schema-s3"]
        self.assertIn("staging-build-images", upload["needs"])
        for step in upload["steps"]:
            self.assertFalse(step.get("continue-on-error", False))
        self.assertIn("release_metadata.py validate", str(upload["steps"]))
        jobs = workflow("call-build-images.yaml")["jobs"]
        generate = jobs["call-build-images-generate-schema"]
        self.assertIn("call-build-container-image-manifests", generate["needs"])
        self.assertIn("--image \"$IMAGE@$DIGEST\"", str(generate["steps"]))
        self.assertNotIn("*.json", str(generate["steps"]))

    def test_staging_upload_survives_unrelated_image_failure(self):
        upload = workflow("staging-build.yaml")["jobs"]["staging-build-upload-schema-s3"]
        condition = upload["if"]
        self.assertIn("!cancelled()", condition)
        self.assertIn("needs.staging-build-get-meta.result == 'success'", condition)
        self.assertIn("needs.staging-build-images.result == 'success'", condition)
        self.assertIn("needs.staging-build-images.result == 'failure'", condition)
        self.assertFalse(upload.get("continue-on-error", False))
        downloads = [step for step in upload["steps"]
                     if step.get("uses", "").startswith("actions/download-artifact@")]
        self.assertEqual(len(downloads), 1)
        self.assertEqual(downloads[0]["with"]["name"],
                         "fluent-bit-schema-${{ needs.staging-build-get-meta.outputs.version }}")
        # Without a run-id override, the required artifact comes from this run.
        self.assertNotIn("run-id", downloads[0]["with"])
        transfer = next(step["run"] for step in upload["steps"]
                        if "aws s3 cp" in step.get("run", ""))
        self.assertLess(transfer.index("release_metadata.py validate"), transfer.index("aws s3 cp"))

    def test_manual_recovery_uses_same_gate_before_sync(self):
        script = (ROOT / "packaging/update-repos.sh").read_text()
        self.assertIn("RELEASE_VERSION:?", script)
        self.assertIn('"$METADATA_TOOL" compare', script)
        self.assertIn('"$METADATA_TOOL" verify', script)
        self.assertLess(script.index('"$METADATA_TOOL" verify'), script.index('aws s3 sync'))

    def test_repository_cleanup_preserves_versioned_schema(self):
        job = workflow("call-build-linux-packages.yaml")["jobs"]["call-build-linux-packages-repo"]
        script = next(step["run"] for step in job["steps"]
                      if "--delete" in step.get("run", ""))
        for version in ("5.0.11", "5.1.3", "5.0.12-rc.1"):
            rendered = script.replace("${{ inputs.version }}", version).replace("\\\n", " ")
            commands = [shlex.split(line) for line in rendered.splitlines()
                        if line.strip().startswith("aws s3 sync")]
            cleanup = next(command for command in commands if "--delete" in command)
            self.assertEqual(cleanup[3:5], ["./latest/", "s3://$AWS_S3_BUCKET"])
            filters = [(arg, cleanup[index + 1]) for index, arg in enumerate(cleanup)
                       if arg in ("--exclude", "--include")]

            def selected(key):
                included = True
                for option, pattern in filters:
                    if fnmatch.fnmatchcase(key, pattern):
                        included = option == "--include"
                return included

            # Excluded destination keys survive --delete, whether uploaded before
            # or after repository construction, including on a job retry.
            for name in (f"fluent-bit-schema-{version}.json",
                         f"fluent-bit-schema-pretty-{version}.json"):
                with self.subTest(version=version, name=name):
                    self.assertFalse(selected(f"{version}/{name}"))
            for key in (f"{version}/rockylinux/9/package.rpm", "rockylinux/9/repodata/old.xml",
                        f"{version}/unexpected.json", "latest-version.txt"):
                with self.subTest(version=version, key=key):
                    self.assertTrue(selected(key))


if __name__ == "__main__":
    unittest.main()
