### Available workflows


| Workflow file                                         | Description               | Run event                                         |
| :---------------------------------------------------- | ------------------------  | ------------------------------------------------- |
| [build-release](./build-release.yaml)            | Builds the distro packages and docker images from a tagged release| on new release/tag|
| [publish-release](./publish-release.yaml)        | Publishes the docker images/manifest on hub.docker.io/fluent/ and the distro packages | on new release/tag on build-release completes|
| [pr-closed-docker](./pr-closed-docker.yaml)      | Removes docker images for PR on hub.docker.io/fluentbitdev/| on pr closed|
| [pr-stale](./pr-stale.yaml)                      | Closes stale PR(s) with no activity in 30 days | scheduled daily 01:30 AM UTC|
| [integration-build-master](./integration-build-master.yaml)     | Builds a docker image to be used in integration testing (master branch) | on new commit/push on master|
| [integration-build-pr](./integration-build-pr.yaml)     | Builds a docker image to be used in integration testing (pr branch) | on new commit/push on PR(s) |
| [integration-run-master](./integration-run-master.yaml)     | Runs the integration testing suite on master | on new image built|
| [integration-run-pr](./integration-run-pr.yaml)     | Runs the integration testing suite on a PR branch | pr opened / label created 'ok-to-test' |

