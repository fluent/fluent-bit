# Available workflows

| Workflow file                                         | Description               | Run event                                         |
| :---------------------------------------------------- | ------------------------  | ------------------------------------------------- |
| [master-integration-test](./master-integration-test.yaml)     | Runs the integration testing suite on master | on new commit/push on master|
| [staging-build](./staging-build.yaml)            | Builds the distro packages and docker images from a tagged release into staging (S3 and GHCR) | on new release/tag |
| [staging-test](./staging-test.yaml)            | Test the staging distro packages and docker images| manually or when `staging-build` completes successfully |
| [staging-release](./staging-release.yaml)        | Publishes the docker images/manifest on hub.docker.io/fluent/ and the distro packages | manual approval |
| [pr-closed-docker](./pr-closed-docker.yaml)      | Removes docker images for PR on hub.docker.io/fluentbitdev/| on pr closed|
| [pr-compile-check](./pr-compile-check.yaml)      | Runs some compilation sanity checks on a PR |
| [pr-integration-test](./pr-integration-test.yaml)     | Runs the integration testing suite on a PR branch | pr opened / label created 'ok-to-test' / on new commit/push on PR(s) |
| [pr-stale](./pr-stale.yaml)                      | Closes stale PR(s) with no activity in 30 days | scheduled daily 01:30 AM UTC|
| [unit-tests](./unit-tests.yaml)     | Runs the unit tests suite on master push or new PR | PR opened, merge in master branch |

## Available labels

| Label name | Description |
| :----------|-------------|
| docs-required| default tag used to request documentation, has to be removed before merge |
| ok-container-test | run all image tests |
| ci/container-test-ok | image tests pass |
| ok-to-test | run all integration tests |
| ok-to-merge | run mergebot and merge (rebase) current PR |
| ci/integration-docker-ok | integration test is able to build docker image |
| ci/integration-gcp-ok | integration test is able to run on GCP |
| long-term | long running pull request, don't close |
| exempt-stale | prevent stale checks running |

## Required secrets

* AWS_ACCESS_KEY_ID
* AWS_SECRET_ACCESS_KEY
* AWS_S3_BUCKET_STAGING
* AWS_S3_BUCKET_RELEASE
* GPG_PRIVATE_KEY
* GPG_PRIVATE_KEY_PASSPHRASE

These are only required for Cosign of the container images, will be skipped if not present:
* COSIGN_PUBLIC_KEY
* COSIGN_PRIVATE_KEY
* COSIGN_PRIVATE_KEY_PASSWORD - if set otherwise not required

## Environments

Two environments are used:
* `staging` for all staging builds
* `release` for running the promotion of staging to release, this can have additional approvals added

If an environment is not present then it will be created but this may not have the appropriate permissions then.
## Pushing to Github Container Registry

Github actions require specific permissions to push to packages, see: https://github.community/t/403-error-on-container-registry-push-from-github-action/173071/39
For some reason this is not automatically done via permission inheritance or similar.

1. Verify you can push with a simple test, e.g. `docker pull alpine && docker tag alpine:latest ghcr.io/<repo>/fluent-bit:latest && docker push ghcr.io/<repo>/fluent-bit:latest`
2. Once this is working locally, you should then be able to set up action permissions for the repository. If you already have a package no need to push a test one.
3. Go to `https://github.com/users/USER/packages/container/fluent-bit/settings` and ensure the repository has access to `Write`.
