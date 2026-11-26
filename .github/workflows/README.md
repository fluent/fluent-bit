# Available workflows

| Workflow file                                         | Description               | Run event                                         |
| :---------------------------------------------------- | ------------------------  | ------------------------------------------------- |
| [build-master-packages](./build-master-packages.yaml) | Builds packages using `master` for certain targets | on new commit/push on master / manual |
| [cron-unstable-build](./cron-unstable-build.yaml) | Scheduled builds of `master` and `3.2`, with manual builds for other branches | Scheduled/manual trigger |
| [master-integration-test](./master-integration-test.yaml)     | Runs the integration testing suite on master | on new commit/push on master |
| [staging-build](./staging-build.yaml)            | Builds the distro packages and docker images from a tagged release into staging (S3 and GHCR) | on any new tag / manual |
| [staging-test](./staging-test.yaml)            | Test the staging distro packages and docker images| manually or when `staging-build` completes successfully |
| [staging-release](./staging-release.yaml)        | Publishes the docker images/manifest on hub.docker.io/fluent/ and the distro packages | manual approval |
| [release-rebuild-images](./release-rebuild-images.yaml) | Rebuilds the container images of a released version on updated base images and refreshes the wiki image index and status pages | manually |
| [pr-closed-docker](./pr-closed-docker.yaml)      | Removes docker images for PR on hub.docker.io/fluentbitdev/| on pr closed|
| [pr-compile-check](./pr-compile-check.yaml)      | Runs some compilation sanity checks on a PR |
| [pr-integration-test](./pr-integration-test.yaml)     | Runs the integration testing suite on a PR branch | pr opened / label created 'ok-to-test' / on new commit/push on PR(s) |
| [pr-package-tests](./pr-package-tests.yaml)     | Runs the package build for all targets on a PR branch | pr opened / label created 'ok-package-test' / on new commit/push on PR(s) |
| [cron-stale](./cron-stale.yaml)                  | Marks issues and PR(s) stale after 90 days with no activity and closes stale issues 5 days later; PR(s) are not closed | scheduled daily 01:30 AM UTC|
| [unit-tests](./unit-tests.yaml)     | Runs the unit tests suite on master push or new PR | PR opened, merge in master branch |

## Available labels

| Label name | Description |
| :----------|-------------|
| docs-required| default tag used to request documentation, has to be removed before merge |
| ok-package-test | Build for all possible targets |
| ok-to-test | run all integration tests |
| ok-to-merge | run mergebot and merge (rebase) current PR |
| ci/integration-docker-ok | integration test is able to build docker image |
| ci/integration-test-ok | integration tests passed |
| ci:qemu | also run the unit tests under QEMU on a PR |
| long-term | long running pull request, don't close |
| exempt-stale | prevent stale checks running |

## Required secrets

Building and publishing packages:

* AWS_ACCESS_KEY_ID
* AWS_SECRET_ACCESS_KEY
* AWS_S3_BUCKET_STAGING
* AWS_S3_BUCKET_RELEASE
* AWS_S3_BUCKET_RELEASE_SOURCES
* GPG_PRIVATE_KEY
* GPG_PRIVATE_KEY_PASSPHRASE

Publishing container images to Docker Hub (GHCR uses the workflow token):

* DOCKERHUB_ORGANIZATION
* DOCKERHUB_USERNAME
* DOCKERHUB_TOKEN

Signing container images with Cosign:

* COSIGN_PRIVATE_KEY
* COSIGN_PASSWORD or COSIGN_PRIVATE_KEY_PASSWORD - if set otherwise not required
* COSIGN_PUBLIC_KEY

Creating releases and pull requests in this and other repositories (documentation, nightly
releases):

* GH_PA_TOKEN
* RELEASE_REPO
* RELEASE_TOKEN

Integration tests:

* GCP_SA_KEY
* TF_API_TOKEN
* OPENSEARCH_AWS_ACCESS_ID
* OPENSEARCH_AWS_SECRET_KEY
* OPENSEARCH_ADMIN_PASSWORD
* CALYPTIA_FLEET_TOKEN

## Environments

These environments are used:

* `unstable` for all nightly builds
* `staging` for all staging builds
* `release` for running the promotion of staging to release and the rebuilds of released container images, this can have additional approvals added
* `pr` for the on-demand package build of a PR
* `integration` for the integration tests

If an environment is not present then it will be created but this may not have the appropriate permissions then.

## Pushing to Github Container Registry

Github actions require specific permissions to push to packages, see: <https://github.community/t/403-error-on-container-registry-push-from-github-action/173071/39>
For some reason this is not automatically done via permission inheritance or similar.

1. Verify you can push with a simple test, e.g. `docker pull alpine && docker tag alpine:latest ghcr.io/<repo>/fluent-bit:latest && docker push ghcr.io/<repo>/fluent-bit:latest`
2. Once this is working locally, you should then be able to set up action permissions for the repository. If you already have a package no need to push a test one.
3. Go to `https://github.com/users/USER/packages/container/fluent-bit/settings` and ensure the repository has access to `Write`.

## Version-specific targets

Each major version (e.g. 1.8 & 1.9) supports different targets to build for, e.g. 1.9 includes a CentOS 8 target and 1.8 has some other legacy targets.

This is all handled by the [build matrix generation composite action](../actions/generate-package-build-matrix/action.yaml).
This uses a [JSON file](../../packaging/build-config.json) to specify the targets so ensure this is updated.
The build matrix is then fed into the [reusable job](./call-build-linux-packages.yaml) that builds packages which will then fire for the appropriate targets.
The reusable job is used for all package builds including unstable/nightly and the PR `ok-package-test` triggered ones.

## Releases

The process at a high level is as follows:

1. Tag created with `v` prefix.
2. [Deploy to staging](https://github.com/fluent/fluent-bit/actions/workflows/staging-build.yaml) workflow runs.
3. [Test staging](https://github.com/fluent/fluent-bit/actions/workflows/staging-test.yaml) workflow runs.
4. Manually initiate [release from staging](https://github.com/fluent/fluent-bit/actions/workflows/staging-release.yaml) workflow.
5. A PR is auto-created to move the source tree to the next patch version using the [`update_version.sh`](../../update_version.sh) script.
6. A PR is auto-created in <https://github.com/fluent/fluent-bit-docs> with the Windows checksums and container versions.

Before the first release of a new series, add that series to the per-series steps of the [release workflow](./staging-release.yaml): the GitHub release, the documentation PR, the version update PR and the `latest` tags.
A series that is not listed gets no GitHub release and neither PR, and that only shows after the packages and images are already published.

Breaking the steps down.

### Deploy to staging and test

This should run automatically when a tag is created. Release tags use the `v` prefix, for example `v5.2.1`.
It can also be started manually for a version.

Once this is completed successfully the staging tests should also run automatically.
The release workflow does not check their result, so wait for them to pass before releasing.

![Workflows for staging and test example](./resources/auto-build-test-workflow.png "Example of workflows for build and test")

If both complete successfully then we are good to go.

Occasional failures are seen with package builds not downloading dependencies (CentOS 7 in particular seems bad for this).
A re-run of failed jobs should resolve this.

The workflow builds all Linux, macOS and Windows targets to a staging S3 bucket plus the Linux and Windows container images to ghcr.io.

### Release from staging workflow

This is a manually initiated workflow, the intention is multiple staging builds can happen but we only release one.
Note that currently we do not support parallel staging builds of different versions, e.g. `master` and a maintenance branch.
**We can only release the previous staging build and there is a check to confirm version.**

To trigger: <https://github.com/fluent/fluent-bit/actions/workflows/staging-release.yaml>

All this job does is copy the various artefacts from staging locations to release ones, it does not rebuild them.

![Workflow for release example](./resources/release-from-staging-workflow-incorrect-version.png "Example of workflow for release")

With this example you can see we used the wrong `version` as it requires it without the `v` prefix (it is used for container tag, etc.) and so it fails.

![Workflow for release failure example](./resources/release-version-failure.png "Example of failing workflow for release")

Make sure to provide without the `v` prefix.

![Workflow for release example](./resources/release-from-staging-workflow.png "Example of successful workflow for release")

Once this workflow is initiated you then also need to have it approved by the designated "release team" otherwise it will not progress.

![Release approval example](./resources/release-approval.png "Release approval example")

They will be notified for approval by Github.
Unfortunately it has to be approved for each job in the sequence rather than a global approval for the whole workflow although that can be useful to check between jobs.

![Release approval per-job required](./resources/release-approval-per-job.png "Release approval per-job required")

This is quite useful to delay the final smoke test of packages until after the manual steps are done as it will then verify them all for you.

#### Packages server sync

The workflow above ensures all release artefacts are pushed to the appropriate container registry and S3 bucket for official releases.
The packages server then periodically syncs from this bucket to pull down and serve the new packages so there may be a delay (up to 1 hour) before it serves the new versions.
The syncs happen hourly.
See <https://github.com/fluent/fluent-bit-infra/blob/main/terraform/provision/package-server-provision.sh.tftpl> for details of the dedicated packages server.

The main reason for a separate server is to accurately track download statistics.
Container images are handled by ghcr.io and Docker Hub, not this server.

#### Required configuration metadata for new releases

Every release using these updated workflows must publish both files:

* `fluent-bit-schema-<version>.json`
* `fluent-bit-schema-pretty-<version>.json`

`<version>` is numeric without the tag's `v` prefix, for example `5.1.3`.
The embedded `fluent-bit.version` may have one optional `v`; the validator
normalizes that prefix explicitly. Release dispatch inputs must omit `v` because
package paths and container tags use the numeric version throughout the workflow.

These are Fluent Bit configuration metadata, not JSON Schema standard documents;
no `$schema` field is required. `.github/scripts/release_metadata.py` validates
nonempty strict JSON, `fluent-bit.version`, `schema_version`, `os`, and the plugin
catalogs `customs`, `inputs`, `filters`, and `outputs`. The `processors` catalog is
required from 4.0 onward; 2.x/3.x metadata predates that catalog. Catalog entries
must have the appropriate plugin type, unique nonempty name, description string,
and properties object. The regular and pretty variants must represent the same
JSON. Input, filter and output catalogs must be nonempty; custom and processor
catalogs may legitimately be empty.

Generation uses the immutable production manifest built for the release, without
a TTY (which can mix console output into JSON):

```sh
docker run --rm --platform linux/amd64 "$IMAGE@$DIGEST" -J > "fluent-bit-schema-$VERSION.json"
# The helper generates and validates both variants in one command:
python3 .github/scripts/release_metadata.py generate \
  --image "$IMAGE@$DIGEST" --version "$VERSION" --directory metadata
```

`staging-build` runs automatically on tags or through manual dispatch. Successful
schema generation is part of its reusable image build; artifact download,
validation and explicit uploads of both files to staging are required.
`staging-test` starts automatically only on successful staging builds. Its manual
trigger cannot publish an official release.

`staging-release` is the official manual promotion path. Run it from `master`
for both 5.2 and 6.0 releases. The workflow targets the matching `5.2` branches
for 5.2 GitHub releases, documentation PRs, and version bumps. It targets
`master` for 6.0. A 5.2 promotion updates GitHub Latest and the Linux
`latest` and `latest-debug` tags only when its version is at least as new as
the current GitHub Latest release. The first 6.0 promotion takes over those tags.
The version update PR advances the source to the next patch and pins the
stable BitBake recipe to the tag that was just published.

It resolves version-specific immutable production/debug manifests, regenerates
metadata from the production image and compares it with both staged files.
It retains the validated staging files as a run artifact before any publication.
Version, series and latest Linux tags are promoted from those pinned manifests.
The public metadata gate precedes Linux, Windows, macOS, source, package-index and
container publication. GitHub release creation has an explicit dependency on that
gate, independent of the selected maintenance-series condition.

The authoritative packages URL convention is:

```text
https://packages.fluentbit.io/<version>/fluent-bit-schema-<version>.json
https://packages.fluentbit.io/<version>/fluent-bit-schema-pretty-<version>.json
```

This follows `staging-release-packages-index`'s `BASE_URL` and the version-directory
keys in `AWS_S3_BUCKET_RELEASE`. The former `releases.fluentbit.io` hostname pointed to the
separate source release bucket.
The [infra sync configuration](https://github.com/fluent/fluent-bit-infra/blob/main/terraform/provision/package-server-provision.sh.tftpl)
and packages-server sync description above are operational references, not a reason
to accept authenticated S3 reads as public verification.

Both files are also attached to every GitHub release step, including maintenance
releases, with unmatched-file failures enabled and overwrite enabled for reruns:

```text
https://github.com/fluent/fluent-bit/releases/download/v<version>/fluent-bit-schema-<version>.json
https://github.com/fluent/fluent-bit/releases/download/v<version>/fluent-bit-schema-pretty-<version>.json
```

After uploading, the verifier downloads both files anonymously using curl with
curlrc disabled, HTTPS redirects only, and no authentication/cookies. It requires
successful HTTP responses, validates the downloaded JSON and version, and compares
both JSON and exact bytes against the retained publication artifact. The packages
check retries both files up to 75 times with 60-second delays, allowing the hourly
sync to catch up. Each request has a 10-second connect and 30-second total timeout;
including the subprocess deadline, the maximum retry budget is about 162 minutes.
The publication job has a 180-minute timeout. GitHub asset verification uses 10
attempts at 30-second intervals. Persistent 403/404, network errors, malformed or
stale content all fail the workflow with the exact URL and repair suggestions.
Documentation/version-update jobs require successful GitHub asset verification.
A failure after partial upload can leave public files or a GitHub release visible;
the workflow remains failed until verification succeeds.

No bucket policy or ACL is changed. Existing scoped upload credentials and public
serving/sync/CDN configuration must permit these exact version-directory JSON keys.
If production denies downloads or omits them from sync, the release fails until the
operators repair that configuration. Run promotion for maintenance versions from
the updated default-branch workflow. Before tagging on a maintained branch, adopt
the generation helper and staging changes there; if dispatching promotion from that
branch, adopt the promotion changes as well. An old branch/tag's unchanged workflow
cannot acquire this guarantee from a merge to master alone. Release environment
controls should restrict promotion to reviewed workflow refs; changing those
controls or production infrastructure is outside this patch.

Nightly (`unstable-*` prereleases), PR, and master development builds are not
official versioned releases. Their development labels can be used for generation,
but official staging and promotion do not allow that version-check exception.
The manual `packaging/update-repos.sh` recovery path with `AWS_SYNC=true` requires
`RELEASE_VERSION`, regenerates against the pinned staging image, compares staged
files, and verifies both public locations before proceeding. It preserves the
existing final dry-run behavior and does not upload metadata or change permissions.
Local repository preparation with `AWS_SYNC=false` is not a publication path.
Direct ad hoc bucket writes cannot be guarded by a repository workflow and must
not be used to declare release success.

##### Recovery without rebuilding or retagging

1. For missing/invalid staging artifacts, rerun the tagged staging build with the
   updated tooling. Confirm both explicit filenames and the embedded version.
   Do not generate from master, a debug image, or another release's image.
2. If promotion preflight reports a mismatch, inspect the staged version and image
   digest. Restore the intended immutable release image/staging artifacts; do not
   edit a version string in the JSON to make it pass.
3. For a partial S3 copy or propagation failure, repair only the affected object
   keys or serving/sync configuration, then rerun failed promotion jobs. The
   retained artifact supplies both files; explicit `s3 cp` safely overwrites each
   key and checks again. Neither wildcard sync nor deletion is used for metadata.
4. For partial GitHub asset uploads, rerun the GitHub release job. Both files are
   uploaded again with overwrite enabled and then fetched anonymously. The
   existing release is updated rather than deleted/recreated.
5. If the run artifact has expired, rerun all promotion jobs to regenerate the
   validation artifact from the intended pinned version image. Record the failure
   and repair; do not report release success while a verification job is failed.

For read-only diagnosis against downloaded run artifacts:

```sh
python3 .github/scripts/release_metadata.py validate --version 5.1.3 --directory metadata
python3 .github/scripts/release_metadata.py verify --version 5.1.3 --directory metadata --attempts 1
python3 .github/scripts/release_metadata.py verify --version 5.1.3 --directory metadata \
  --github-repository fluent/fluent-bit --attempts 1
```

##### Historical availability

This is a new-release guarantee after adoption, not a statement that previous
releases have complete metadata. Read-only probes on 2026-10-04 UTC of both
`packages.fluentbit.io/5.1.3/` JSON keys returned HTTP 404 with S3 `NoSuchKey`
responses via curl. Python HTTP requests returned 403, including for the key-file
control URL; that 403 alone does not distinguish a missing object from access or
request filtering. The v5.1.3 GitHub release API reported no attached assets, and
the expected GitHub JSON download URL returned 404. These identify historical
gaps at the configured URLs at probe time, not a complete historical inventory.
No old releases, objects, permissions, or infrastructure were modified.

##### Focused verification

```sh
python3 -m pip install PyYAML==6.0.2
python3 -m unittest discover -s .github/scripts/tests -p 'test_release_*.py' -v
actionlint -shellcheck='' .github/workflows/call-build-images.yaml \
  .github/workflows/staging-build.yaml .github/workflows/staging-release.yaml \
  .github/workflows/test-release-metadata.yaml
bash -n packaging/update-repos.sh
```

The focused CI workflow runs the same metadata/anonymous HTTP tests and dependency
checks plus actionlint. Tests cover missing/empty/malformed files, wrong versions,
missing metadata/catalog structure, mismatched variants, branch compatibility,
403/404, transient failures, content mismatch, and successful public verification.
They use a local HTTP server and test no production writes. Native plugin scenarios
and Valgrind/Leaks are not applicable to this workflow/Python-only change.

#### Transient container publishing failures

The parallel publishing of multiple container tags for the same image seems to fail occasionally with network errors, particularly more for ghcr.io than DockerHub.
This can be resolved by just re-running the failed jobs.

#### Windows builds

Windows packages are built by the [reusable Windows workflow](./call-build-windows.yaml) on GitHub hosted Windows runners as part of the staging build, for the targets listed under `windows_targets` in the [build configuration](../../packaging/build-config.json).
The Windows container images are built by the [reusable image workflow](./call-build-images.yaml).
No external CI service is involved.

#### ARM builds

Linux packages and container images for ARM are built on GitHub hosted ARM runners.
The `arm/v7` container image build needs a runner that can execute 32-bit ARM binaries, it checks that first and fails with a clear message otherwise.

### Manual release

As long as it is built to staging we can manually publish packages as well via the script here: <https://github.com/fluent/fluent-bit/blob/master/packaging/update-repos.sh>

Containers can be promoted manually too, ensure to include all architectures and signatures.

### Documentation PRs

Once the release is published the release workflow computes the Windows checksums from the released files and opens a PR in <https://github.com/fluent/fluent-bit-docs> that updates:

1. Windows checksums: <https://docs.fluentbit.io/manual/installation/windows#installation-packages>
2. Container versions: <https://docs.fluentbit.io/manual/installation/docker#tags-and-versions>

Review and merge that PR. It also opens the PR in this repository that moves the source tree to the next patch version.

## Unstable/nightly builds

These run on a schedule and [reuse the same workflows](./cron-unstable-build.yaml) as the staging build.
The schedule builds `master` at 06:00 and 18:00 UTC and `5.2` at 12:00 UTC.
A manual run can build another branch. The branch name becomes part of file names, so it must not contain a `/`.
All targets are built, including container images and Linux, macOS and Windows packages.

The container images are tagged with the branch, for example:

* `ghcr.io/fluent/fluent-bit/unstable:master`
* `ghcr.io/fluent/fluent-bit/unstable:windows-2022-master`

The packages are attached to the `unstable-<branch>` prerelease.
Every build deletes that prerelease and creates it again, and the job does not fail when either step fails.
A green run is therefore no proof that the prerelease exists: check it when the packages matter, and re-run the `unstable-release` job if it is missing.

## Integration tests

On every commit to `master` we rebuild the [packages](./build-master-packages.yaml) and [container images](./master-integration-test.yaml).
The container images are then used to [run the integration tests](./master-integration-test.yaml) from the <https://github.com/fluent/fluent-bit-ci> repository.
The container images are available as:

* [ghcr.io/fluent/fluent-bit/master:x86_64](ghcr.io/fluent/fluent-bit/master:x86_64)

## PR checks

Various workflows are run for PRs automatically:

* [Unit tests](./unit-tests.yaml)
* [Compile checks on CentOS 7 compilers](./pr-compile-check.yaml)
* [Linting](./pr-lint.yaml)
* [Windows builds](./pr-windows-build.yaml)
* [Fuzzing](./pr-fuzz.yaml)
* [Container image builds](./pr-image-tests.yaml)
* [Install script checks](./pr-install-script.yaml)

We try to guard these to only trigger when relevant files are changed to reduce any delays or resources used.
**All should be able to be triggered manually for explicit branches as well.**

The following workflows can be triggered manually for specific PRs too:

* [Integration tests](./pr-integration-test.yaml): Build a container image and run the integration tests as per commits to `master`.
* [Full package build](./pr-package-tests.yaml): builds all Linux, macOs and Windows packages as well as container images.

To trigger these, apply the relevant label.

## Rebuilding released container images

Base image fixes (distroless, Debian, Windows) do not need a new Fluent Bit release. The
[release-rebuild-images](./release-rebuild-images.yaml) workflow rebuilds the container images of
an already released version from its `v<version>` tag, so the binary is recompiled and linked
against the refreshed base, and publishes the result under the same tags. Packages are untouched.

### Triggering a rebuild

Maintainers with write access trigger it manually, typically after a user reports a base image
CVE or when the status page shows fixable findings.

From the web interface:

1. Open the repository **Actions** tab and select
   **Rebuild released container images on updated base images** in the workflow list.
2. Click **Run workflow**, keep the branch as `master` and fill in the inputs below. Leaving
   `version` empty rebuilds the newest release.
3. Click **Run workflow**. Once the rebuilt images pass the comparison, the publishing jobs wait
   for approval of the `release` environment: open the run, click **Review deployments** and
   approve.
4. When the run finishes, the run summary and the wiki page show the new state.

From the command line:

```shell
# Rebuild the newest release if its images have fixable findings
gh workflow run release-rebuild-images.yaml --ref master

# Rebuild a specific release, repeat per supported series
gh workflow run release-rebuild-images.yaml --ref master -f version=5.1.5

# Force a rebuild even when the scan finds nothing fixable
gh workflow run release-rebuild-images.yaml --ref master -f version=5.2.0 -f mode=always

# Only refresh the wiki pages
gh workflow run release-rebuild-images.yaml --ref master -f mode=report-only

# Follow the run
gh run watch "$(gh run list --workflow release-rebuild-images.yaml --limit 1 --json databaseId --jq '.[0].databaseId')"
```

| Input | Default | Purpose |
|---|---|---|
| `version` | newest release | Released version to rebuild, without the `v` prefix. |
| `mode` | `if-needed` | `if-needed` rebuilds only when the published images have fixable critical or high findings, `always` forces a rebuild, `report-only` just regenerates the wiki pages. |
| `promote` | `true` | Publish to Docker Hub and GHCR. Disable to stop after the staging build, tests and comparison. |
| `update-wiki` | `true` | Push the regenerated pages to the wiki. |

### What a run does

1. Scans the published production and debug images with Trivy.
2. Rebuilds all Linux and Windows images into the staging registry with fresh base images and no
   layer cache, then runs the usual image tests.
3. Scans the rebuilt images and publishes them only when they have fewer fixable findings than the
   published ones and no partial multi-arch manifest (`always` also accepts an equal count).
4. Before the version tags move for the first time, gives every image of the original release a
   dated tag so that build stays listed and pullable.
5. On every publication attempt, checks all dated Linux and Windows tags for the planned build
   in both registries against the verified digests. It keeps matching tags, fills in missing
   tags, and stops if a tag has a different digest or a newer build exists for that version.
   Once the dated tags are complete, it updates the version tags. Publication shares a
   concurrency group with the normal release workflow and checks current Git release tags
   before updating `<major>.<minor>` and `latest`. A retry only moves aliases the selected
   version is still eligible for. The workflow signs the Linux production and debug references
   in Docker Hub and GHCR.
6. Regenerates two wiki pages from the registry. This step runs even when nothing was rebuilt.

### Tags and builds

One version can have several builds. All images of one build share a build id, `YYYYMMDD`, or
`YYYYMMDD.N` for a further build on the same day:

| Tag | Example | Behavior |
|---|---|---|
| Version tag | `5.2.0`, `5.2.0-debug`, `windows-2022-5.2.0` | Moves to the newest build |
| Dated tag | `5.2.0-20261117`, `5.2.0-20261117-debug`, `windows-2022-5.2.0-20261117` | Names one build and never moves |
| Digest | `fluent/fluent-bit@sha256:...` | Identifies one image exactly |

Dated tags are never removed: the index is generated from them.

### Wiki pages

| Page | Content |
|---|---|
| [Container images](https://github.com/fluent/fluent-bit/wiki/Container-Images) | Index of every build of every release in the three most recent series: version tag, dated tag, short digest, build date, whether it is the release or a rebuild, and whether it is current or superseded. The full digest of every image, including debug and Windows, is listed per version. This is the page to send users to. |
| [Container image security status](https://github.com/fluent/fluent-bit/wiki/Container-Image-Security-Status) | Trivy findings of the current image of the newest patch of each of those series, split into fixable by a rebuild and not fixed upstream yet. |

Both pages are overwritten on every run and need no manual edits. The wiki history keeps the
previous versions.

### Failed jobs

A rebuild runs many jobs on shared runners and one of them occasionally fails for a reason that
a new runner solves, such as a download timing out in a Windows build or an ARM64 runner that
cannot execute 32-bit ARM binaries. [release-rebuild-images-retry](./release-rebuild-images-retry.yaml)
re-runs only the failed jobs of a failed rebuild, at most twice, so this needs no action. A run
that is still red after the third attempt has a real problem.

A missing architecture never gets published: the comparison job refuses a manifest that does not
provide `amd64`, `arm64` and `arm/v7`.

Only the images the release originally published are rebuilt, so older series with fewer Windows
images are handled without changes.

### Testing from a branch

Publishing jobs use the `release` environment, so they need its approval and only run from a
protected branch. From any other branch run with `promote=false` to exercise the build, tests,
comparison and wiki pages without publishing anything:

```shell
gh workflow run release-rebuild-images.yaml --ref my-branch -f promote=false -f update-wiki=false
```

The rendered pages are always attached to the run as the `container-image-pages` artifact and
shown in the run summary. A run that ends without publishing is expected when the
rebuild does not reduce the fixable findings; use `mode=always` to publish it regardless.

The planning, gating and page rendering live in
[release_image_rebuild.py](../scripts/release_image_rebuild.py) and are covered by
`.github/scripts/tests/test_release_image_rebuild.py`.
