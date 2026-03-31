# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#!/bin/bash

# 1. verify the environment: vscode & docker
#     1.1 if docker is installed, config docker command execution without sudo, promp if not installed and exit.
#     1.2 if vscode is not installed, promp and exit.
# 2. build wasm-toolchain & wasm-debug-server docker image

DIR_ROOT=$(pwd)/..

echo "=== Verify the vscode status ==="
if [ "$(code --version)" ]; then
    echo "VSCode is ready."
else
    echo "VSCode is not installed, please install firstly."
    exit 1
fi

echo "=== Verify the docker status ==="
if [ "$(docker --version)" ]; then
    echo "Docker is ready."
else
    echo "Docker is not installed, please install firstly."
    exit 1
fi

# setup docker command execution without sudo permission
sudo groupadd docker
sudo gpasswd -a ${USER} docker
sudo service docker restart

# create new group and execute the rest commands
newgrp - docker << REST

# 2. build wasm-debug-server docker image
cd ${DIR_ROOT}/WASM-Debug-Server/Docker
docker build -t wasm-debug-server:1.0 .

# 3. build wasm-toolchain docker image
cd ${DIR_ROOT}/WASM-Toolchain/Docker
docker pull ubuntu:20.04
docker build -t wasm-toolchain:1.0 .

REST