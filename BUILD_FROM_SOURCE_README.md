## Build Instructions

The upstream tag this release is branched from is `v2.0.11`

### Create Environment Variables

```
export DOCKER_REPO=<Docker Repository>
export DOCKER_NAMESPACE=<Docker Namespace>
export DOCKER_TAG=<Docker Tag>
```

### Build and Push Images

From the root of the repo, run the following command
```
docker build -t ${DOCKER_REPO}/${DOCKER_NAMESPACE}/fluent-bit:${DOCKER_TAG} -f dockerfiles/Dockerfile.oracle .
```

Once the build completes successfully, push the image:
```
docker push ${DOCKER_REPO}/${DOCKER_NAMESPACE}/fluent-bit:${DOCKER_TAG}
```
