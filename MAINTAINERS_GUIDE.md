# Fluent Bit Maintainers Guide

This guide is the starting point for maintainers. It says how each recurring task is done and
links to the document that has the details. It does not replace those documents: when a
procedure changes, update the detailed document and keep the summary here short.

If you are contributing a change and are not a maintainer, start with
[CONTRIBUTING.md](CONTRIBUTING.md) instead.

## Where things are documented

| Topic | Document |
|---|---|
| Who the maintainers are | [MAINTAINERS.md](MAINTAINERS.md) |
| Who reviews which part of the code | [CODEOWNERS](CODEOWNERS) |
| Becoming a maintainer, responsibilities, voting | [GOVERNANCE.md](GOVERNANCE.md) |
| Active branches, what is accepted on each, end-of-life dates | [MAINTENANCE.md](MAINTENANCE.md) |
| Supported versions, vulnerability reports, container images | [SECURITY.md](SECURITY.md) |
| CI, releases, nightly builds, container image rebuilds | [.github/workflows/README.md](.github/workflows/README.md) |
| Commit message rules checked by CI | [COMMIT_LINT.md](COMMIT_LINT.md) |
| Linux, Windows and macOS packages | [packaging/README.md](packaging/README.md) |
| Container image builds | [dockerfiles/README.md](dockerfiles/README.md) |
| Development setup and internals | [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) |

## Reviewing and merging pull requests

- Changes land in `master` first. See [Backports](#backports) for the other branches.
- Every commit needs a `Signed-off-by` line and a subject prefixed with the component it
  touches. The commit lint workflow enforces this; the rules are in
  [COMMIT_LINT.md](COMMIT_LINT.md).
- CI runs the unit tests, compile checks, lint, Windows builds, fuzzing and container image
  builds on a pull request when the relevant files change. The list is in
  [PR checks](.github/workflows/README.md#pr-checks).
- Some checks only run when a maintainer adds a label:

  | Label | Effect |
  |---|---|
  | `ok-to-test` | Run the integration tests |
  | `ok-package-test` | Build the packages for all targets |
  | `ci:qemu` | Also run the unit tests under QEMU |
  | `docs-required` | Documentation is still needed; remove before merging |
  | `long-term`, `exempt-stale` | Keep the stale check away from an issue |

  The full list is in [Available labels](.github/workflows/README.md#available-labels).
- Issues with no activity for 90 days are marked stale and closed 5 days later. Pull requests
  are marked stale but never closed automatically.

## Bundled third-party libraries

Only maintainers update the third-party libraries bundled under `lib/`. This is a trust and
supply chain security rule: a library update is a large diff that cannot be reviewed line by
line, so it has to come from someone accountable for the project who fetched it from the
upstream source.

- Do not merge a pull request from a non-maintainer that updates, replaces or adds a bundled
  library, even when the change looks correct. Ask the contributor to open an issue with the
  reason for the update, and have a maintainer do it.
- A maintainer takes the release from the upstream project, not from a contributor branch or
  fork, and keeps the update in its own commit, separate from Fluent Bit changes.
- A fix inside a bundled library goes to the upstream project first. A local patch is the
  exception, is done by a maintainer and is sent upstream as well.
- [CODEOWNERS](CODEOWNERS) decides who reviews each path. A change under `lib/` hidden in a
  larger pull request is a reason to stop and look, not to approve.

## Backports

The branches and what each accepts are listed in [MAINTENANCE.md](MAINTENANCE.md). In short:

1. The change is merged into `master`.
2. The branch maintainer cherry-picks it into the stable or maintenance branch when it fits
   the policy for that branch: security fixes, critical bug fixes and selected low-risk
   changes.
3. Contributors request a backport by adding a `Target: v<series>` note to the pull request
   or issue and mentioning the branch maintainer.

End-of-life branches receive nothing, including security fixes.

## Publishing a release

The detailed procedure, with screenshots and recovery steps, is in
[Releases](.github/workflows/README.md#releases). The sequence is:

1. Create the tag with a `v` prefix, for example `v5.2.1`, on the branch being released.
2. The [staging build](https://github.com/fluent/fluent-bit/actions/workflows/staging-build.yaml)
   starts by itself and builds every package and container image into staging.
3. The [staging test](https://github.com/fluent/fluent-bit/actions/workflows/staging-test.yaml)
   starts by itself when the build succeeds. Wait until it has finished and passed: the
   release workflow does not check the test result, so nothing else stops a release of a
   build whose tests are still running or failed. Re-run failed jobs only when the failure
   is a download or network error. Any other failure has to be fixed and tagged again.
4. Start the [release from staging](https://github.com/fluent/fluent-bit/actions/workflows/staging-release.yaml)
   workflow by hand. Give the version **without** the `v` prefix, for example `5.2.1`. Only
   the most recent staging build can be released, and the workflow checks the version.
5. Approve the `release` environment. Approval is asked for each job in the sequence, not
   once for the whole run.
6. The workflow copies the staged artifacts to the release locations without rebuilding
   them, publishes the configuration metadata files and verifies them from the public URLs.
   A run that fails that verification is not a finished release, see
   [Recovery without rebuilding or retagging](.github/workflows/README.md#recovery-without-rebuilding-or-retagging).
7. The workflow creates the GitHub release and opens two pull requests. Review and merge
   both:
   - in this repository, the move of the source tree to the next patch version, made with
     [`update_version.sh`](update_version.sh);
   - in [fluent-bit-docs](https://github.com/fluent/fluent-bit-docs), the Windows checksums
     and the container versions. See
     [Documentation PRs](.github/workflows/README.md#documentation-prs).

Linux, macOS and Windows packages and all container images are built by GitHub Actions. No
external CI service is part of a release.

Packages reach `packages.fluentbit.io` through an hourly sync, so they can appear up to an
hour after the workflow finishes.

When a release adds a series or ends one, update [MAINTENANCE.md](MAINTENANCE.md),
[SECURITY.md](SECURITY.md) and the roadmap section of [README.md](README.md) together. The
release workflow also lists every series explicitly and needs the new one added.

## Refreshing the container images of a release

Base image packages receive security fixes without a Fluent Bit release. When a user reports
a CVE in a published image, or the
[status page](https://github.com/fluent/fluent-bit/wiki/Container-Image-Security-Status) shows
fixable findings, rebuild the images of the released version. Nothing is tagged and packages
are not touched.

```shell
# Rebuild one release when its images have fixable critical or high findings.
# Run it once per series that needs it.
gh workflow run release-rebuild-images.yaml --ref master -f version=5.2.0

# Rebuild regardless of the scan, for example for a fixable medium or low finding
gh workflow run release-rebuild-images.yaml --ref master -f version=5.2.0 -f mode=always

# Only regenerate the wiki pages
gh workflow run release-rebuild-images.yaml --ref master -f mode=report-only
```

The same can be done from the **Actions** tab with
**Rebuild released container images on updated base images**.

1. The run scans the published images for critical and high findings and, in the default
   `if-needed` mode, stops when none of them is fixable. Lower severities do not trigger a
   rebuild; use `mode=always` for those.
2. Otherwise it rebuilds from the release tag into staging, tests the images and compares the
   scans. It publishes only when the rebuilt images have fewer fixable critical and high
   findings. With `mode=always` an equal count is published too, a higher one never is.
3. Publishing waits for approval of the `release` environment: open the run and use
   **Review deployments**.
4. The version tag moves to the new build. Every build, including the original release, keeps
   a dated tag such as `5.2.0-20261117` that never moves.
5. Two wiki pages are regenerated: the
   [image index](https://github.com/fluent/fluent-bit/wiki/Container-Images) and the
   [security status](https://github.com/fluent/fluent-bit/wiki/Container-Image-Security-Status).
   Point users to the index.

Run it from `master` with the exact version, such as `5.1.5`, and do not start a second run
for a version while one is still waiting for approval. Inputs, tag rules and failure
handling are in
[Rebuilding released container images](.github/workflows/README.md#rebuilding-released-container-images).

## Handling security reports

The policy users see is [SECURITY.md](SECURITY.md).

- **Vulnerability in Fluent Bit.** Reports arrive privately at the address in
  [SECURITY.md](SECURITY.md). Acknowledge within 72 hours and give a first assessment within
  7 days. Fix on `master`, backport critical and high severity fixes to every active branch,
  release, and publish a GitHub Security Advisory together with the reporter.
- **Finding in a container image that comes from the base image.** This is not a Fluent Bit
  vulnerability and needs no release:
  [refresh the container images](#refreshing-the-container-images-of-a-release). A finding
  the status page lists as not fixed yet has no fixed package available, so a rebuild cannot
  remove it.
- **Third-party CVE that may affect Fluent Bit.** Post the assessment through the channels
  listed in [SECURITY.md](SECURITY.md).

## Nightly and development builds

- Nightly builds run on the schedule of the unstable build workflow, which names the
  branches it builds; a maintained branch is not built unless it is listed there. They
  produce packages and container images that are not official releases. See
  [Unstable/nightly builds](.github/workflows/README.md#unstablenightly-builds).
- Every commit to `master` rebuilds packages and a container image, which then runs the
  integration tests. See [Integration tests](.github/workflows/README.md#integration-tests).

## Access a maintainer needs

- Write access to the repository, to add labels, merge and start workflows.
- Membership of the reviewers of the `release` environment, to approve a release or an image
  rebuild. Publishing jobs only run from protected branches.
- The secrets and environments the workflows expect are listed in
  [Required secrets](.github/workflows/README.md#required-secrets) and
  [Environments](.github/workflows/README.md#environments).

## When a workflow fails

- Download and registry errors are common in package builds and container publishing.
  Re-run the failed jobs before investigating further.
- A failed image rebuild re-runs its failed jobs by itself, at most twice. A run that is
  still red after the third attempt has a real problem.
- A failed release verification means the release is incomplete. Follow
  [Recovery without rebuilding or retagging](.github/workflows/README.md#recovery-without-rebuilding-or-retagging)
  and do not edit published files by hand.
