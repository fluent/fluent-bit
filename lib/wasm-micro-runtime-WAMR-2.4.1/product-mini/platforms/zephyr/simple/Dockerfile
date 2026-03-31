# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# Refer to https://docs.zephyrproject.org/3.7.0/develop/getting_started/index.html
# for more information on how to set up the Zephyr development environment.

# https://docs.zephyrproject.org/latest/develop/application/index.html#zephyr-workspace-application
# zephyrproject/       --> CI ROOT
# ├─── .west/
# │    └─── config
# ├─── bootloader/
# ├─── zephyr/         --> Zephyr source code
# ├─── zephyr-sdk/
# ├─── modules/
# │    |─── wasm-micro-runtime   --> WAMR source code
# ├─── tools/
# ├─── vendor/
# └─── application/    --> DUMMY. keep west_lite.yml here

# If you modify this file, you may need to sync the modifications to the
# .github/actions/setup-zephyr/action.yml
FROM ghcr.io/zephyrproject-rtos/ci-base:v0.26-branch

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Asian/Shanghai
ARG ZEPHYR_SDK_VERSION=0.16.9
# In west_lite.yml, the Zephyr version is set to v3.7.0
#ARG ZEPHYR_VERSION=3.7.0

# Install the Zephyr Software Development Kit (SDK)
WORKDIR /root/zephyrproject/zephyr-sdk
# hadolint ignore=DL4006
RUN wget --progress=dot:giga https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v${ZEPHYR_SDK_VERSION}/zephyr-sdk-${ZEPHYR_SDK_VERSION}_linux-x86_64.tar.xz \
    && wget --progress=dot:giga -O - https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v${ZEPHYR_SDK_VERSION}/sha256.sum | shasum --check --ignore-missing \
    && tar --strip-components=1 -xf zephyr-sdk-${ZEPHYR_SDK_VERSION}_linux-x86_64.tar.xz && rm zephyr-sdk-${ZEPHYR_SDK_VERSION}_linux-x86_64.tar.xz
# hadolint ignore=DL4006
# Install host tools and Register Zephyr SDK CMake package
RUN ./setup.sh -h -c

# Install west
# hadolint ignore=DL3013,DL3059
RUN pip3 install --no-cache-dir west

# Setup a T2(Star topology) workspace
WORKDIR /root/zephyrproject/application
COPY ./west_lite.yml ./west_lite.yml

# init the west workspace with a minimal manifest
RUN west init -l --mf west_lite.yml .

WORKDIR /root/zephyrproject
RUN west update --stats

# Git clone wamr
WORKDIR /root/zephyrproject/modules/
RUN git clone https://github.com/bytecodealliance/wasm-micro-runtime.git wasm-micro-runtime
WORKDIR /root/zephyrproject/modules/wasm-micro-runtime/product-mini/platforms/zephyr
