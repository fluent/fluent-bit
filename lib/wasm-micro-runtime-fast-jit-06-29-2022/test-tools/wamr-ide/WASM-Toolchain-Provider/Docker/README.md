# WASM Toolchain Provider Introduction

## Files on HOST

#### Dockerfile

-   ubuntu : 20.04
-   set up the necessary toolchains
    -   WASI-SDK (version: 12.0)
    -   WAMR-SDK
        -   repo: bytecode-alliance/wasm-micro-runtime
        -   branch: main
    -   LLVM (latest repo build)
    -   CMake (version: 3.21.1)

#### build_docker_image.sh

-   the script to build docker image for Linux platform
-   tag: 1.0

#### build_docker_image.bat

-   the script to build docker image for windows platform
-   tag: 1.0

#### run_container.sh

-   the script to start and run the docker container for Linux platform
-   mount `host directory` and `container directory`
    -   temporally using `$(pwd)/host_mnt_test` in **host** and `/mnt` in **container**
-   set docker container name with `--name`
    -   temporally set to _wasm-toolchain-ctr_

#### run_container.bat

-   the script to start and run the docker container for windows platform

## Files inside docker

### `wamrc`

### `wasi-sdk`

# Build Docker Image

-   Linux

```shell
chmod +x resource/*
./build_docker_image.sh
```

-   Windows

```shell
./build_docker_image.bat
```

# Run Docker Container

-   Linux

```shell
./run_container.sh
```

-   Windows

```shell
./run_container.bat
```
