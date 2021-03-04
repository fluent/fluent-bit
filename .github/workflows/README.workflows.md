### Available workflows


| Workflow file                                         | Description               | Run event                                         |
| :---------------------------------------------------- | ------------------------  | ------------------------------------------------- |
| [build-release](./build-release.yaml)            | Builds the distro packages and docker images from a tagged release| on new release/tag|
| [publish-release](./publish-release.yaml)        | Publishes the docker images/manifest on hub.docker.io/fluent/ and the distro packages | on new release/tag on build-release completes|
| [pr-closed-docker](./pr-closed-docker.yaml)      | Removes docker images for PR on hub.docker.io/fluentbitdev/| on pr closed|
| [pr-stale](./pr-stale.yaml)                      | Closes stale PR(s) with no activity in 30 days | scheduled daily 01:30 AM UTC|
| [test-integration-master-microk8s](./test-integration-master-microk8s.yaml)            | Runs [fluent-bit-ci](https://github.com/calyptia/fluent-bit-ci/) integration tests on microk8s/x86| on new commit/push on master|
| [test-integration-pr-microk8s](./test-integration-master-microk8s.yaml)            | Runs [fluent-bit-ci](https://github.com/calyptia/fluent-bit-ci/) integration tests on microk8s/x86| on new pr with the 'ok-to-test' label against master|

