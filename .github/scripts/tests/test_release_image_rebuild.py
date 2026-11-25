"""Guard the rebuild of released container images: planning, gating, report and publication."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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
                plan = rebuild.plan(requested, self.versions, "20261116", REGISTRY, "20261109")
                self.assertEqual(plan["version"], "5.2.0")
                self.assertEqual(plan["ref"], "v5.2.0")
                self.assertEqual(plan["tags"], [
                    "5.2.0", "5.2.0-20261116", "5.2", "latest",
                    "5.2.0-debug", "5.2.0-20261116-debug", "5.2-debug", "latest-debug"])

    def test_floating_tags_never_move_backwards(self):
        plan = rebuild.plan("5.1.5", self.versions, "20261116", REGISTRY, "20261021")
        self.assertEqual(plan["tags"], ["5.1.5", "5.1.5-20261116", "5.1",
                                        "5.1.5-debug", "5.1.5-20261116-debug", "5.1-debug"])
        plan = rebuild.plan("5.1.4", self.versions, "20261116", REGISTRY, "20261001")
        self.assertEqual(plan["tags"], ["5.1.4", "5.1.4-20261116",
                                        "5.1.4-debug", "5.1.4-20261116-debug"])

    def test_report_covers_newest_patch_of_recent_series(self):
        plan = rebuild.plan("5.1.4", self.versions, "20261116", REGISTRY, "20261001")
        self.assertEqual(plan["report-versions"], ["5.2.0", "5.1.5", "5.0.11"])
        self.assertEqual(plan["report-tags"][:2], ["5.2.0", "5.2.0-debug"])
        self.assertEqual(rebuild.plan("", self.versions, "20261116", REGISTRY, "20261109", 1)["report-versions"], ["5.2.0"])

    def test_invalid_requests_are_rejected(self):
        for requested, date in (("5.2.1", "20261116"), ("master", "20261116"), ("5.2", "20261116"),
                                ("5.2.0-rc1", "20261116"), ("5.2.0; id", "20261116"),
                                ("5.2.0", "2026-11-16")):
            with self.subTest(requested=requested, date=date), self.assertRaises(ValueError):
                rebuild.plan(requested, self.versions, date, REGISTRY, "20261109")
        with self.assertRaises(ValueError):
            rebuild.plan("", [], "20261116", REGISTRY)

    def test_only_originally_published_images_are_rebuilt(self):
        plan = rebuild.plan("5.2.0", self.versions, "20261116", REGISTRY, "20261109")
        self.assertEqual(plan["windows-images"], ["windows-2022", "windows-2025", "windows-nano-2025"])
        self.assertEqual(plan["windows-tags"][0], "windows-2022-5.2.0")
        plan = rebuild.plan("5.0.11", self.versions, "20261116", REGISTRY, "20261009")
        self.assertEqual(plan["windows-images"], ["windows-2022"])
        self.assertEqual(plan["windows-tags"], ["windows-2022-5.0.11"])
        self.assertEqual(rebuild.plan("5.1.5", self.versions, "20261116", REGISTRY, "20261021")["windows-tags"], [])
        with self.assertRaisesRegex(ValueError, "no published container images"):
            rebuild.plan("4.2.9", self.versions, "20261116", REGISTRY)

    def test_partial_builds_in_either_registry_reserve_their_ids(self):
        primary = REGISTRY + ["5.2.0-20261109", "5.2.0-20261116-debug"]
        mirror = ["windows-2022-5.2.0-20261116.2", "5.2.0-20261116.3"]
        plan = rebuild.plan("5.2.0", self.versions, "20261116", primary, mirror_tags=mirror)
        self.assertEqual(plan["build"], "20261116.4")

    def test_original_release_is_kept_before_its_tags_move(self):
        plan = rebuild.plan("5.0.11", self.versions, "20261116", REGISTRY, "20261009")
        self.assertEqual(plan["build"], "20261116")
        self.assertEqual(plan["preserve"], [
            {"from": "5.0.11", "to": "5.0.11-20261009"},
            {"from": "5.0.11-debug", "to": "5.0.11-20261009-debug"},
            {"from": "windows-2022-5.0.11", "to": "windows-2022-5.0.11-20261009"}])
        for created in ("", "2026-10-09", "unknown"):
            with self.subTest(created=created), self.assertRaisesRegex(ValueError, "build date"):
                rebuild.plan("5.0.11", self.versions, "20261116", REGISTRY, created)

    def test_interrupted_preservation_is_resumed(self):
        # A previous run kept the production image and failed before the other images or registry.
        plan = rebuild.plan("5.0.11", self.versions, "20261116", REGISTRY + ["5.0.11-20261009"])
        self.assertEqual(plan["build"], "20261116")
        self.assertEqual([item["to"] for item in plan["preserve"]],
                         ["5.0.11-20261009", "5.0.11-20261009-debug", "windows-2022-5.0.11-20261009"])
        # Once a rebuild is published the version tags have moved and must not be kept as original.
        registry = REGISTRY + ["5.0.11-20261009", "5.0.11-20261116"]
        self.assertEqual(rebuild.plan("5.0.11", self.versions, "20261117", registry)["preserve"], [])

    def test_every_build_gets_a_dated_tag_of_its_own(self):
        # Released and rebuilt on the same day: the rebuild must not take the original's tag.
        plan = rebuild.plan("5.2.0", self.versions, "20261109", REGISTRY, "20261109")
        self.assertEqual(plan["build"], "20261109.2")
        self.assertEqual(plan["tags"][:2], ["5.2.0", "5.2.0-20261109.2"])
        self.assertIn("5.2.0-20261109.2-debug", plan["tags"])
        registry = REGISTRY + ["5.2.0-20261109", "5.2.0-20261116", "5.2.0-20261116.2", "5.2.0-20261116-debug",
                               "5.2.0-20261116.02", "5.2.0-2026111", "5.2.00-20261116.9"]
        self.assertEqual(rebuild.builds("5.2.0", registry), ["20261109", "20261116", "20261116.2"])
        plan = rebuild.plan("5.2.0", self.versions, "20261116", registry)
        self.assertEqual(plan["build"], "20261116.3")
        self.assertEqual(plan["preserve"], [])
        self.assertEqual(rebuild.plan("5.2.0", self.versions, "20261120", registry)["build"], "20261120")
        self.assertEqual(rebuild.image_tag("windows-2022", "5.2.0", "20261116.2"), "windows-2022-5.2.0-20261116.2")
        self.assertEqual(rebuild.image_tag("debug", "5.2.0"), "5.2.0-debug")


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.version = "5.2.0"
        self.build = "20261116"
        self.staging = "ghcr.io/fluent/fluent-bit/staging"
        self.registries = ["ghcr.io/fluent/fluent-bit", "docker.io/fluent/fluent-bit"]
        self.digests = dict(zip(("production", "debug", "windows-2022"),
                                (f"sha256:{char * 64}" for char in "abc")))
        self.tags = ["5.2.0", "5.2.0-20261116", "5.2", "latest", "5.2.0-debug",
                     "5.2.0-20261116-debug", "5.2-debug", "latest-debug"]
        self.versions = rebuild.stable_versions(TAGS)
        self.published = {registry: {} for registry in self.registries}
        self.copies = []

    def registry(self, command, *, text):
        self.assertTrue(text)
        self.assertEqual(command[0], "regctl")
        group, action, ref = command[1:4]
        if (group, action) == ("tag", "ls"):
            return "\n".join(self.published[ref])
        if (group, action) == ("image", "digest"):
            registry, tag = ref.rsplit(":", 1)
            return self.published[registry][tag]
        self.assertEqual((group, action), ("image", "copy"))
        registry, tag = command[4].rsplit(":", 1)
        self.published[registry][tag] = ref.split("@", 1)[1]
        self.copies.append((ref, command[4]))
        return ""

    def publish(self):
        with patch.object(rebuild.subprocess, "check_output", side_effect=self.registry):
            rebuild.publish(self.staging, self.registries, self.version, self.build, self.tags,
                            self.digests, self.versions)

    def test_retry_keeps_matching_tags_and_fills_each_registry_before_moving_aliases(self):
        ghcr, dockerhub = self.registries
        self.published[ghcr]["5.2.0-20261116"] = self.digests["production"]
        self.published[dockerhub]["5.2.0-20261116-debug"] = self.digests["debug"]
        self.publish()
        dated_copies = self.copies[:4]
        self.assertTrue(all(src.startswith(self.staging + "@") for src, _ in dated_copies))
        self.assertTrue(all("20261116" in dst for _, dst in dated_copies))
        self.assertNotIn(f"{ghcr}:5.2.0-20261116", [dst for _, dst in self.copies])
        self.assertNotIn(f"{dockerhub}:5.2.0-20261116-debug", [dst for _, dst in self.copies])
        for registry in self.registries:
            self.assertEqual(self.published[registry]["windows-2022-5.2.0-20261116"],
                             self.digests["windows-2022"])
            self.assertEqual(self.published[registry]["latest"], self.digests["production"])
        self.copies.clear()
        self.publish()
        self.assertTrue(self.copies)
        self.assertTrue(all("20261116" not in dst for _, dst in self.copies))

    def test_conflicting_partial_publication_stops_before_any_write(self):
        self.published[self.registries[1]]["windows-2022-5.2.0-20261116"] = "sha256:" + "d" * 64
        with self.assertRaisesRegex(ValueError, "different build"):
            self.publish()
        self.assertEqual(self.copies, [])

    def test_registry_failure_stops_before_any_write(self):
        def registry(command, *, text):
            if command[1:] == ["tag", "ls", self.registries[1]]:
                raise subprocess.CalledProcessError(1, command)
            return self.registry(command, text=text)

        with patch.object(rebuild.subprocess, "check_output", side_effect=registry):
            with self.assertRaises(subprocess.CalledProcessError):
                rebuild.publish(self.staging, self.registries, self.version, self.build,
                                self.tags, self.digests, self.versions)
        self.assertEqual(self.copies, [])

    def test_older_retry_cannot_move_aliases_back(self):
        self.published[self.registries[0]]["5.2.0-20261116.2-debug"] = self.digests["debug"]
        with self.assertRaisesRegex(ValueError, "newer build"):
            self.publish()
        self.assertEqual(self.copies, [])

    def test_retry_rechecks_series_and_latest_aliases(self):
        for newer, expected in (((5, 3, 0), {"5.2", "5.2-debug"}), ((5, 2, 1), set())):
            with self.subTest(newer=newer):
                self.versions = rebuild.stable_versions(TAGS) + [newer]
                self.copies.clear()
                self.publish()
                moved = {dst.rsplit(":", 1)[1] for _, dst in self.copies}
                self.assertIn("5.2.0", moved)
                self.assertEqual(moved & {"5.2", "5.2-debug", "latest", "latest-debug"}, expected)

    def test_failed_dated_copy_leaves_aliases_untouched_until_retry(self):
        failed = f"{self.registries[1]}:5.2.0-20261116-debug"

        def registry(command, *, text):
            if command[1:3] == ["image", "copy"] and command[-1] == failed:
                raise subprocess.CalledProcessError(1, command)
            return self.registry(command, text=text)

        with patch.object(rebuild.subprocess, "check_output", side_effect=registry):
            with self.assertRaises(subprocess.CalledProcessError):
                rebuild.publish(self.staging, self.registries, self.version, self.build,
                                self.tags, self.digests, self.versions)
        written = {dst for _, dst in self.copies}
        self.assertEqual(len(written), 4)
        self.assertTrue(all("20261116" in dst for dst in written))
        self.copies.clear()
        self.publish()
        dated, aliases = self.copies[:2], self.copies[2:]
        self.assertIn(failed, [dst for _, dst in dated])
        self.assertTrue(all("20261116" in dst for _, dst in dated))
        self.assertTrue(all("20261116" not in dst for _, dst in aliases))
        self.assertTrue(written.isdisjoint(dst for _, dst in self.copies))


class IndexTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.versions = rebuild.stable_versions(TAGS)
        self.registry = REGISTRY + ["5.2.0-20261109", "5.2.0-20261109-debug", "windows-2022-5.2.0-20261109",
                                    "5.2.0-20261116", "5.2.0-20261116-debug", "windows-2022-5.2.0-20261116"]

    def inspect(self, tag, digest, created="2026-11-09T02:00:00Z"):
        (Path(self.directory.name) / f"inspect-{tag}.json").write_text(json.dumps(
            {"Digest": "sha256:" + digest * 16, "Created": created}))

    def test_index_tags_cover_every_image_of_every_build(self):
        tags = rebuild.index_tags(self.versions, self.registry)
        for tag in ("5.2.0", "5.2.0-20261109", "5.2.0-20261116-debug", "windows-2022-5.2.0-20261116",
                    "windows-nano-2025-5.2.0", "5.1.5", "5.1.4", "windows-2022-5.1.4", "5.0.11-debug"):
            self.assertIn(tag, tags)
        self.assertNotIn("4.2.9", tags)
        self.assertNotIn("windows-2022-5.1.50", tags)
        self.assertEqual(len(tags), len(set(tags)))
        self.assertLessEqual(set(tags), set(self.registry))

    def test_index_lists_history_with_short_and_full_digests(self):
        self.inspect("5.2.0", "bbbb", "2026-11-16T02:00:00Z")
        self.inspect("5.2.0-20261116", "bbbb", "2026-11-16T02:00:00Z")
        self.inspect("5.2.0-20261109", "aaaa")
        self.inspect("5.2.0-20261116-debug", "cccc")
        self.inspect("5.1.5", "dddd", "2026-10-21T02:00:00Z")
        self.inspect("5.1.4", "eeee", "2026-10-01T02:00:00Z")
        page = rebuild.render_index(self.versions, self.registry, self.directory.name,
                                    ["fluent/fluent-bit", "ghcr.io/fluent/fluent-bit"], "now")
        self.assertIn("| 5.2.0 | `5.2.0` | `5.2.0-20261116` | `bbbbbbbbbbbb` | 2026-11-16 | rebuild | current |", page)
        self.assertIn("| 5.2.0 | – | `5.2.0-20261109` | `aaaaaaaaaaaa` | 2026-11-09 | release | "
                      "superseded by `5.2.0-20261116` |", page)
        self.assertIn("| 5.1.5 | `5.1.5` | – | `dddddddddddd` | 2026-10-21 | release | current |", page)
        self.assertIn("| 5.1.4 | `5.1.4` | – | `eeeeeeeeeeee` | 2026-10-01 | release | superseded by `5.1.5` |", page)
        self.assertIn("| debug | `5.2.0-20261116-debug` | `fluent/fluent-bit@sha256:" + "cccc" * 16 + "` |", page)
        self.assertIn("| windows-2022 | `windows-2022-5.2.0-20261116` | unavailable |", page)
        self.assertIn("| 5.0.11 | `5.0.11` | – | unavailable | unavailable | release | current |", page)
        self.assertLess(page.index("## 5.2"), page.index("## 5.1"))
        self.assertNotIn("4.2.9", page)

    def test_version_tag_is_shown_only_on_the_build_it_points_to(self):
        # A partial publication left the version tag on the previous build.
        self.inspect("5.2.0", "aaaa")
        self.inspect("5.2.0-20261116", "bbbb")
        self.inspect("5.2.0-20261109", "aaaa")
        page = rebuild.render_index(self.versions, self.registry, self.directory.name, ["fluent/fluent-bit"], "now")
        self.assertIn("| 5.2.0 | – | `5.2.0-20261116` | `bbbbbbbbbbbb` |", page)
        self.assertIn("| 5.2.0 | `5.2.0` | `5.2.0-20261109` | `aaaaaaaaaaaa` |", page)


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
        (directory / "inspect-5.2.0-20261116.json").write_text(json.dumps(
            {"Digest": "sha256:abc", "Created": "2026-11-16T10:00:00Z"}))
        (directory / "inspect-5.2.0-20261117.json").write_text(json.dumps(
            {"Digest": "sha256:other", "Created": "2026-11-17T10:00:00Z"}))
        scan(directory, "trivy-5.2.0-debug.json", [])
        (directory / "inspect-5.2.0-debug.json").write_text(json.dumps(
            {"Digest": "sha256:def", "Created": "2026-11-09T10:00:00Z"}))
        registry = ["5.2.0", "5.2.0-20261101", "5.2.0-20261116", "5.2.0-20261117",
                    "5.2.0-20261117-debug", "5.2.0-20261116-debug-extra",
                    "5.2.0-amd64", "5.2.00-20270101"]
        page = rebuild.render(["5.2.0", "5.2.0-debug", "5.1.5"], directory, registry,
                              ["docker.io/fluent/fluent-bit"], "now", "https://example.invalid/run")
        self.assertIn("| `5.2.0` | 2026-11-16 | `5.2.0-20261116` | `sha256:abc` | debian 13.7 | 0 / 1 | 0 / 1 |", page)
        self.assertIn("| `5.2.0-debug` | 2026-11-09 | – | `sha256:def` |", page)
        self.assertNotIn("20261117", page)
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

    def test_implicit_and_explicit_release_versions_share_a_concurrency_group(self):
        self.assertEqual(self.workflow["concurrency"], {
            "group": "release-rebuild-images",
            "queue": "max",
        })

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
        job = self.jobs["rebuild-release-images"]
        self.assertTrue(job["if"].startswith(
            "inputs.promote && needs.rebuild-verify.outputs.promote == 'true'"))

    def test_linux_and_windows_images_are_promoted_by_verified_digest(self):
        job = self.jobs["rebuild-release-images"]
        release = yaml.safe_load((ROOT / ".github/workflows/staging-release.yaml").read_text())
        self.assertEqual(job["concurrency"], {"group": release["concurrency"], "queue": "max"})
        publish = job["steps"][-1]
        self.assertIn("release_image_rebuild.py publish", publish["run"])
        self.assertIn("--tags-file release-tags.txt", publish["run"])
        self.assertIn('--registry "$GHCR_RELEASE_IMAGE_NAME" --registry "$DH_RELEASE_IMAGE_NAME"',
                      publish["run"])
        for variant, output in (("PRODUCTION_DIGEST", "digest"), ("DEBUG_DIGEST", "debug-digest"),
                                ("WINDOWS_DIGESTS", "windows-digests")):
            self.assertEqual(publish["env"][variant], "${{ needs.rebuild-verify.outputs." + output + " }}")
        verify = "\n".join(step.get("run", "") for step in self.jobs["rebuild-verify"]["steps"])
        self.assertIn('"amd64,arm,arm64"', verify)
        self.assertIn('"$STAGING_IMAGE_NAME:$IMAGE-$VERSION"', verify)
        plan = "\n".join(step.get("run", "") for step in self.jobs["rebuild-plan"]["steps"])
        self.assertIn("--mirror-tags mirror-tags.json", plan)

    def test_windows_digest_verification_fails_on_lookup_error_or_invalid_output(self):
        step = next(step for step in self.jobs["rebuild-verify"]["steps"] if step.get("id") == "image")
        mock_docker = """
docker() {
    case "$4 $5" in
        *' --raw')
            echo '{"manifests":[{"platform":{"os":"linux","architecture":"amd64"}},
                                {"platform":{"os":"linux","architecture":"arm"}},
                                {"platform":{"os":"linux","architecture":"arm64"}}]}'
            ;;
        *windows-2022*)
            case "$LOOKUP" in
                failure) return 1 ;;
                invalid) echo "bad-digest" ;;
                valid) printf 'sha256:%064d\\n' 1 ;;
            esac
            ;;
        *) printf 'sha256:%064d\\n' 2 ;;
    esac
}
"""
        for lookup in ("failure", "invalid", "valid", "empty"):
            with self.subTest(lookup=lookup), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "output"
                result = subprocess.run(
                    ["bash", "-eo", "pipefail", "-c", mock_docker + step["run"]],
                    env={**os.environ, "GITHUB_OUTPUT": str(output), "LOOKUP": lookup,
                         "STAGING_IMAGE_NAME": "ghcr.io/fluent/fluent-bit/staging", "VERSION": "5.2.0",
                         "WINDOWS_IMAGES": '[]' if lookup == "empty" else '["windows-2022"]'},
                    capture_output=True, text=True)
                if lookup in ("failure", "invalid"):
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn("windows-digests=", output.read_text())
                    continue
                self.assertEqual(result.returncode, 0, result.stderr)
                output_line = output.read_text().splitlines()[-1]
                self.assertTrue(output_line.startswith("windows-digests="))
                expected = {} if lookup == "empty" else {"windows-2022": f"sha256:{1:064d}"}
                self.assertEqual(json.loads(output_line.split("=", 1)[1]), expected)

    def test_original_release_is_kept_before_any_tag_moves(self):
        keep = self.jobs["rebuild-release-preserve-original"]
        self.assertEqual(keep["if"], "inputs.promote && needs.rebuild-verify.outputs.promote == 'true'")
        run = keep["steps"][0]["run"]
        self.assertIn("--preserve-digests", run)
        self.assertEqual(run.count("list-tags"), 1)
        self.assertIn("'.Tags | index($tag)' existing-tags.json", run)
        self.assertLess(run.index("is already kept"), run.index("copy --all"))
        self.assertIn('keep "$GHCR_RELEASE_IMAGE_NAME" "$GHCR_CREDS"', run)
        self.assertIn('keep "$DH_RELEASE_IMAGE_NAME" "$DH_CREDS"', run)
        self.assertEqual(keep["steps"][0]["env"]["PRESERVE"], "${{ needs.rebuild-plan.outputs.preserve }}")
        self.assertIn("rebuild-release-preserve-original", self.jobs["rebuild-release-images"]["needs"])

    def test_both_wiki_pages_are_published(self):
        steps = self.jobs["rebuild-report-publish"]["steps"]
        commands = "\n".join(step.get("run", "") for step in steps)
        self.assertIn("release_image_rebuild.py index-tags", commands)
        self.assertIn("release_image_rebuild.py index ", commands)
        self.assertIn('git add "$WIKI_INDEX_PAGE.md" "$WIKI_STATUS_PAGE.md"', commands)
        self.assertEqual(self.workflow["env"]["WIKI_INDEX_PAGE"], "Container-Images")

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
