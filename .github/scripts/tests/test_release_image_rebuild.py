"""Guard the rebuild of released container images: planning, gating, report and publication."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / ".github/scripts"))

import release_image_rebuild as rebuild  # noqa: E402

TAGS = """\
aaa\trefs/tags/v5.1.4
bbb\trefs/tags/v5.1.5
ccc\trefs/tags/v5.1.5^{}
ddd\trefs/tags/v5.2.0
eee\trefs/tags/v5.10.0-rc1
fff\trefs/tags/v4.2.9
ggg\trefs/tags/wasm-browser-0123
hhh\trefs/tags/v5.0.11
""".splitlines()


def scan(directory, name, entries, system=("debian", "13.7")):
    """Write a minimal Trivy report: entries are (id, severity, package, fixed version)."""
    path = Path(directory) / name
    path.write_text(json.dumps({
        "Metadata": {"OS": {"Family": system[0], "Name": system[1]}},
        "Results": [{"Vulnerabilities": [
            {"VulnerabilityID": identifier, "Severity": severity, "PkgName": package,
             "InstalledVersion": "1.0", "FixedVersion": fixed, "Status": "affected",
             "PrimaryURL": f"https://example.invalid/{identifier}"}
            for identifier, severity, package, fixed in entries]}, {"Target": "empty"}]}))
    return path


REGISTRY = ["5.2.0", "5.2.0-debug", "windows-2022-5.2.0", "windows-2025-5.2.0", "windows-nano-2025-5.2.0",
            "5.1.5", "5.1.5-debug", "5.1.4", "5.1.4-debug", "windows-2022-5.1.4", "windows-2022-5.1.50",
            "5.0.11", "5.0.11-debug", "windows-2022-5.0.11", "4.2.9"]


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.versions = rebuild.stable_versions(TAGS)

    def test_only_stable_release_tags_are_considered(self):
        self.assertEqual(self.versions, [(4, 2, 9), (5, 0, 11), (5, 1, 4), (5, 1, 5), (5, 2, 0)])

    def test_newest_release_moves_every_floating_tag(self):
        for requested in ("", "5.2.0", "v5.2.0"):
            with self.subTest(requested=requested):
                plan = rebuild.plan(requested, self.versions, "20261116", REGISTRY)
                self.assertEqual(plan["version"], "5.2.0")
                self.assertEqual(plan["ref"], "v5.2.0")
                self.assertEqual(plan["tags"], [
                    "5.2.0", "5.2.0-20261116", "5.2", "latest",
                    "5.2.0-debug", "5.2.0-20261116-debug", "5.2-debug", "latest-debug"])

    def test_floating_tags_never_move_backwards(self):
        plan = rebuild.plan("5.1.5", self.versions, "20261116", REGISTRY)
        self.assertEqual(plan["tags"], ["5.1.5", "5.1.5-20261116", "5.1",
                                        "5.1.5-debug", "5.1.5-20261116-debug", "5.1-debug"])
        plan = rebuild.plan("5.1.4", self.versions, "20261116", REGISTRY)
        self.assertEqual(plan["tags"], ["5.1.4", "5.1.4-20261116",
                                        "5.1.4-debug", "5.1.4-20261116-debug"])

    def test_report_covers_newest_patch_of_recent_series(self):
        plan = rebuild.plan("5.1.4", self.versions, "20261116", REGISTRY)
        self.assertEqual(plan["report-versions"], ["5.2.0", "5.1.5", "5.0.11"])
        self.assertEqual(plan["report-tags"][:2], ["5.2.0", "5.2.0-debug"])
        self.assertEqual(rebuild.plan("", self.versions, "20261116", REGISTRY, 1)["report-versions"], ["5.2.0"])

    def test_invalid_requests_are_rejected(self):
        for requested, date in (("5.2.1", "20261116"), ("master", "20261116"), ("5.2", "20261116"),
                                ("5.2.0-rc1", "20261116"), ("5.2.0; id", "20261116"),
                                ("5.2.0", "2026-11-16")):
            with self.subTest(requested=requested, date=date), self.assertRaises(ValueError):
                rebuild.plan(requested, self.versions, date, REGISTRY)
        with self.assertRaises(ValueError):
            rebuild.plan("", [], "20261116", REGISTRY)

    def test_only_originally_published_images_are_rebuilt(self):
        plan = rebuild.plan("5.2.0", self.versions, "20261116", REGISTRY)
        self.assertEqual(plan["windows-images"], ["windows-2022", "windows-2025", "windows-nano-2025"])
        self.assertEqual(plan["windows-tags"][0], "windows-2022-5.2.0")
        plan = rebuild.plan("5.0.11", self.versions, "20261116", REGISTRY)
        self.assertEqual(plan["windows-images"], ["windows-2022"])
        self.assertEqual(plan["windows-tags"], ["windows-2022-5.0.11"])
        self.assertEqual(rebuild.plan("5.1.5", self.versions, "20261116", REGISTRY)["windows-tags"], [])
        with self.assertRaisesRegex(ValueError, "no published container images"):
            rebuild.plan("4.2.9", self.versions, "20261116", REGISTRY)


class GateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.dirty = scan(self.directory.name, "dirty.json", [
            ("CVE-1", "HIGH", "libssl3", "3.0.1"), ("CVE-2", "CRITICAL", "zlib1g", "1.3.2"),
            ("CVE-3", "HIGH", "libc6", ""), ("CVE-4", "MEDIUM", "libc6", "2.42"),
            ("CVE-1", "HIGH", "libssl3", "3.0.1")])
        self.unfixed = scan(self.directory.name, "unfixed.json", [("CVE-3", "HIGH", "libc6", "")])
        self.partial = scan(self.directory.name, "partial.json", [("CVE-1", "HIGH", "libssl3", "3.0.1")])

    def test_findings_split_by_fix_and_ignore_lower_severities(self):
        result = rebuild.findings(self.dirty)
        self.assertEqual([entry["id"] for entry in result["fixable"]], ["CVE-2", "CVE-1"])
        self.assertEqual([entry["id"] for entry in result["unfixed"]], ["CVE-3"])
        self.assertEqual(result["os"], "debian 13.7")

    def test_rebuild_only_when_a_fix_exists_or_forced(self):
        self.assertTrue(rebuild.decide_rebuild("if-needed", [self.dirty, self.unfixed])["rebuild"])
        self.assertFalse(rebuild.decide_rebuild("if-needed", [self.unfixed])["rebuild"])
        self.assertTrue(rebuild.decide_rebuild("always", [self.unfixed])["rebuild"])
        self.assertFalse(rebuild.decide_rebuild("report-only", [self.dirty])["rebuild"])

    def test_promotion_requires_an_improvement_unless_forced(self):
        cases = [("if-needed", self.dirty, self.unfixed, True), ("if-needed", self.dirty, self.partial, True),
                 ("if-needed", self.dirty, self.dirty, False), ("if-needed", self.unfixed, self.unfixed, False),
                 ("always", self.unfixed, self.unfixed, True), ("always", self.dirty, self.dirty, True),
                 ("always", self.partial, self.dirty, False), ("if-needed", self.unfixed, self.partial, False)]
        for mode, before, after, expected in cases:
            with self.subTest(mode=mode, before=before.name, after=after.name):
                self.assertEqual(rebuild.decide_promote(mode, [before], [after])["promote"], expected)

    def test_outputs_use_workflow_encodings(self):
        output = Path(self.directory.name) / "output"
        os.environ["GITHUB_OUTPUT"] = str(output)
        self.addCleanup(os.environ.pop, "GITHUB_OUTPUT")
        self.assertEqual(rebuild.main(["decide-rebuild", "--mode", "if-needed", str(self.dirty)]), 0)
        self.assertEqual(output.read_text(), "fixable=2\nrebuild=true\n")
        self.assertEqual(rebuild.main(["decide-rebuild", "--mode", "always", "missing.json"]), 1)

    def test_report_lists_images_dated_tags_and_missing_scans(self):
        directory = Path(self.directory.name)
        scan(directory, "trivy-5.2.0.json", [("CVE-1", "HIGH", "lib|ssl", "3.0.1"), ("CVE-3", "HIGH", "libc6", "")])
        (directory / "inspect-5.2.0.json").write_text(json.dumps(
            {"Digest": "sha256:abc", "Created": "2026-11-16T10:00:00Z"}))
        scan(directory, "trivy-5.2.0-debug.json", [])
        (directory / "inspect-5.2.0-debug.json").write_text(json.dumps(
            {"Digest": "sha256:def", "Created": "2026-11-09T10:00:00Z"}))
        registry = ["5.2.0", "5.2.0-20261101", "5.2.0-20261116", "5.2.0-20261116-debug-extra",
                    "5.2.0-amd64", "5.2.00-20270101"]
        page = rebuild.render(["5.2.0", "5.2.0-debug", "5.1.5"], directory, registry,
                              ["docker.io/fluent/fluent-bit"], "now", "https://example.invalid/run")
        self.assertIn("| `5.2.0` | 2026-11-16 | `5.2.0-20261116` | `sha256:abc` | debian 13.7 | 0 / 1 | 0 / 1 |", page)
        self.assertIn("| `5.2.0-debug` | 2026-11-09 | original release | `sha256:def` |", page)
        self.assertIn("| `5.1.5` | scan unavailable |", page)
        self.assertIn("lib\\|ssl", page)
        self.assertIn("[this workflow run](https://example.invalid/run)", page)


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        text = (ROOT / ".github/workflows/release-rebuild-images.yaml").read_text()
        self.workflow = yaml.safe_load(text)
        self.jobs = self.workflow["jobs"]

    def ancestors(self, name):
        needs = self.jobs[name].get("needs", [])
        needs = [needs] if isinstance(needs, str) else needs
        result = set(needs)
        for dependency in needs:
            result.update(self.ancestors(dependency))
        return result

    def test_manual_only_with_minimal_default_permissions(self):
        self.assertEqual(list(self.workflow[True]), ["workflow_dispatch"])
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})

    def test_rebuild_uses_release_tag_and_fresh_base_images(self):
        build = self.jobs["rebuild-build"]
        self.assertEqual(build["with"]["ref"], "${{ needs.rebuild-plan.outputs.ref }}")
        self.assertIs(build["with"]["refresh-base-images"], True)
        self.assertEqual(build["with"]["environment"], "staging")
        shared = (ROOT / ".github/workflows/call-build-images.yaml").read_text()
        self.assertIn("pull: ${{ inputs.refresh-base-images }}", shared)
        self.assertIn("no-cache: ${{ inputs.refresh-base-images }}", shared)
        self.assertIn("'--pull --no-cache'", shared)
        self.assertEqual(build["with"]["windows-images"], "${{ needs.rebuild-plan.outputs.windows-images }}")
        windows = yaml.safe_load(shared)["jobs"]["call-build-windows-container"]
        self.assertEqual(json.loads(yaml.safe_load(shared)[True]["workflow_call"]["inputs"]["windows-images"]["default"]),
                         [entry["image-tag-prefix"] for entry in windows["strategy"]["matrix"]["include"]])
        self.assertEqual(list(rebuild.WINDOWS_IMAGES),
                         [entry["image-tag-prefix"] for entry in windows["strategy"]["matrix"]["include"]])
        for step in windows["steps"]:
            self.assertIn("env.REQUESTED == 'true'", step["if"])
        self.assertEqual(yaml.safe_load(shared)[True]["workflow_call"]["inputs"]["scan-exit-code"]["default"], "1")

    def test_publication_requires_verified_rebuild_and_release_environment(self):
        publishing = [name for name in self.jobs if name.startswith("rebuild-release-")]
        self.assertEqual(len(publishing), 5)
        for name in publishing:
            with self.subTest(job=name):
                job = self.jobs[name]
                self.assertEqual(job["environment"], "release")
                self.assertLessEqual({"rebuild-verify", "rebuild-test", "rebuild-build"}, self.ancestors(name))
                self.assertNotIn("always()", str(job.get("if", "")))
                self.assertNotIn("cancelled()", str(job.get("if", "")))
        for name in ("rebuild-release-images", "rebuild-release-images-windows"):
            self.assertTrue(self.jobs[name]["if"].startswith(
                "inputs.promote && needs.rebuild-verify.outputs.promote == 'true'"))

    def test_linux_images_are_promoted_by_verified_digest(self):
        job = self.jobs["rebuild-release-images"]
        self.assertIn("outputs.digest", job["env"]["SOURCE_DIGEST"])
        self.assertIn("outputs.debug-digest", job["env"]["SOURCE_DIGEST"])
        commands = "\n".join(step.get("run", "") for step in job["steps"])
        self.assertEqual(commands.count("docker://$STAGING_IMAGE_NAME@$SOURCE_DIGEST"), 2)
        self.assertNotIn("docker://$STAGING_IMAGE_NAME:", commands)
        verify = "\n".join(step.get("run", "") for step in self.jobs["rebuild-verify"]["steps"])
        self.assertIn('"amd64,arm,arm64"', verify)

    def test_status_page_runs_without_a_rebuild_and_only_it_can_write(self):
        for name in ("rebuild-report-scan", "rebuild-report-publish"):
            self.assertIn("!cancelled()", self.jobs[name]["if"])
            self.assertIn("needs.rebuild-plan.result == 'success'", self.jobs[name]["if"])
        writers = [name for name, job in self.jobs.items()
                   if job.get("permissions", {}).get("contents") == "write"]
        self.assertEqual(writers, ["rebuild-report-publish"])
        push = self.jobs["rebuild-report-publish"]["steps"][-1]
        self.assertEqual(push["if"], "inputs.update-wiki")
        self.assertIn(".wiki.git", push["run"])

    def test_failed_jobs_are_rerun_a_bounded_number_of_times(self):
        retry = yaml.safe_load((ROOT / ".github/workflows/release-rebuild-images-retry.yaml").read_text())
        self.assertEqual(retry[True]["workflow_run"]["workflows"], [self.workflow["name"]])
        self.assertEqual(retry[True]["workflow_run"]["types"], ["completed"])
        job = retry["jobs"]["rebuild-retry-failed-jobs"]
        self.assertIn("workflow_run.conclusion == 'failure'", job["if"])
        self.assertIn("workflow_run.run_attempt < 3", job["if"])
        self.assertEqual(job["permissions"], {"actions": "write"})
        self.assertIn("--failed", job["steps"][0]["run"])
        # A stale event must not start a further attempt.
        self.assertIn('"$CURRENT" != "$ATTEMPT completed failure"', job["steps"][0]["run"])
        self.assertEqual(job["steps"][0]["env"]["ATTEMPT"], "${{ github.event.workflow_run.run_attempt }}")
        self.assertEqual(job["concurrency"], {"group": "rebuild-retry-${{ github.event.workflow_run.id }}",
                                              "cancel-in-progress": False})

    def test_transient_build_failures_are_handled(self):
        jobs = yaml.safe_load((ROOT / ".github/workflows/call-build-images.yaml").read_text())["jobs"]
        build = next(step for step in jobs["call-build-windows-container"]["steps"]
                     if step["name"] == "Build the production images")
        self.assertIn("for ATTEMPT in 1 2 3", build["run"])
        self.assertIn('PULL_FLAGS=""', build["run"])
        steps = jobs["call-build-single-arch-container-images"]["steps"]
        names = [step["name"] for step in steps]
        check = names.index("Check native 32-bit ARM support")
        self.assertEqual(steps[check]["if"], "matrix.platform == 'arm/v7'")
        self.assertLess(check, next(i for i, step in enumerate(steps) if step.get("id") == "build"))
        self.assertNotIn("setup-qemu-action", str(steps))


if __name__ == "__main__":
    unittest.main()
