# Build with Docker

To have a quicker start, a Docker container of the Zephyr setup can be generated.

## Build Docker container

``` Bash
docker build --build-arg DOCKER_UID=$(id -u) . -t wamr-zephyr
```

## Run Docker container to build images

Enter the docker container (maps the toplevel wasm-micro-runtime repo as volume):

``` Bash
docker run -ti -v $PWD/../../../..:/home/wamr/source --device=/dev/ttyUSB0 wamr-zephyr
```

Adopt the device or remove if not needed.

And then in the docker container:

``` Bash
./build_and_run.sh esp32c3
```