# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    cmake build-essential git wget python3.10 python3-pip

RUN wget -q https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-14/wasi-sdk-14.0-linux.tar.gz && \
    tar xf wasi-sdk-*-linux.tar.gz -C /opt && rm -f wasi-sdk-*-linux.tar.gz && \
    mv /opt/wasi-sdk-14.0 /opt/wasi-sdk

WORKDIR /home/wamr

COPY core core
COPY build-scripts build-scripts
COPY product-mini product-mini

RUN pip3 install -r core/iwasm/libraries/wasi-nn/test/requirements.txt

WORKDIR /home/wamr/core/iwasm/libraries/wasi-nn/test/build

RUN cmake -DWAMR_BUILD_WASI_NN=1 ..
RUN make -j $(grep -c ^processor /proc/cpuinfo)

WORKDIR /home/wamr/core/iwasm/libraries/wasi-nn/test

RUN ./build.sh

ENTRYPOINT [ "./build/iwasm",  "--dir=.", "test_tensorflow.wasm" ]
