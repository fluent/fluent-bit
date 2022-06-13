# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

FROM ubuntu:20.04

ARG DOCKER_UID=1000

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get -qq update && apt-get -qq dist-upgrade && apt install -qq -y python3-pip git wget ninja-build

WORKDIR /tmp

RUN mkdir /opt/cmake && wget -q https://github.com/Kitware/CMake/releases/download/v3.22.1/cmake-3.22.1-linux-x86_64.sh && sh cmake-3.22.1-linux-x86_64.sh --skip-license --prefix=/opt/cmake && rm cmake-3.22.1-linux-x86_64.sh

ENV PATH="/opt/cmake/bin:$PATH"

RUN useradd -m wamr -u ${DOCKER_UID} -G dialout

USER wamr

ENV PATH="/home/wamr/.local/bin:$PATH"

RUN pip3 install --user west

RUN west init ~/zephyrproject && cd ~/zephyrproject && west update && west zephyr-export

RUN pip3 install --user -r ~/zephyrproject/zephyr/scripts/requirements.txt

WORKDIR /home/wamr/zephyrproject

RUN west espressif install

ENV ZEPHYR_BASE=/home/wamr/zephyrproject/zephyr
ENV ESPRESSIF_TOOLCHAIN_PATH=/home/wamr/.espressif/tools/zephyr

WORKDIR /home/wamr/source/product-mini/platforms/zephyr/simple
