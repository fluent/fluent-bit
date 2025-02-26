# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Asian/Shanghai

# Install dependencies for Zephyr
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends git cmake ninja-build gperf \
    ccache dfu-util device-tree-compiler wget \
    python3-dev python3-pip python3-setuptools python3-tk python3-wheel xz-utils file \
    make gcc gcc-multilib g++-multilib libsdl2-dev libmagic1 \ 
    && apt-get clean -y && rm -rf /var/lib/apt/lists/*

# Install the Zephyr Software Development Kit (SDK)
WORKDIR /opt
# hadolint ignore=DL4006
RUN wget --progress=dot:giga https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v0.16.3/zephyr-sdk-0.16.3_linux-x86_64.tar.xz \
    && wget --progress=dot:giga -O - https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v0.16.3/sha256.sum | shasum --check --ignore-missing \
    && tar xvf zephyr-sdk-0.16.3_linux-x86_64.tar.xz && rm zephyr-sdk-0.16.3_linux-x86_64.tar.xz

WORKDIR /opt/zephyr-sdk-0.16.3
# hadolint ignore=DL4006
RUN yes | ./setup.sh

# Get Zephyr 
# hadolint ignore=DL3013
RUN pip3 install --no-cache-dir west && west init -m https://github.com/zephyrproject-rtos/zephyr --mr v3.5.0 /root/zephyrproject

WORKDIR /root/zephyrproject
RUN west update 

WORKDIR /root/zephyrproject/zephyr
RUN west zephyr-export && pip install --no-cache-dir -r ~/zephyrproject/zephyr/scripts/requirements.txt

# Git clone wamr
WORKDIR /root
RUN git clone https://github.com/bytecodealliance/wasm-micro-runtime.git

WORKDIR /root/wasm-micro-runtime/product-mini/platforms/zephyr/simple

ENV ZEPHYR_BASE="/root/zephyrproject/zephyr"
