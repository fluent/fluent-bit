# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

##  Build docker image that consists of gcc, cmake, wasi-sdk & zephyr sdk
FROM gcc:12.2.0 AS BASE

## set work directory
WORKDIR /root/

COPY resource /root/

#  - download cmake with wget and set up
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get -y install ccache ninja-build make cmake python3-pip --no-install-recommends

#  set compilation environment for wamrc
#    - wamr repo
#    - cmake
#    - wasi-sdk
#    - wamr-sdk

#  - download wasi-sdk with wget and set up to /opt/wasi-sdk
RUN wget --progress=dot:giga https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-19/wasi-sdk-19.0-linux.tar.gz \
    && tar -zxf wasi-sdk-*-linux.tar.gz \
    && mv wasi-sdk-19.0 /opt/wasi-sdk/ \
    && rm -f wasi-sdk-*-linux.tar.gz

##  - clone wamr repo
RUN git clone -b main --depth=1 https://github.com/bytecodealliance/wasm-micro-runtime.git

WORKDIR /root/wasm-micro-runtime/build-scripts
RUN pip3 install --no-cache-dir --user -r requirements.txt

WORKDIR /root/wasm-micro-runtime/wamr-compiler
RUN ./build_llvm.sh \
    && mkdir build

WORKDIR /root/wasm-micro-runtime/wamr-compiler/build
RUN cmake .. \
    && make \
    #  - copy the wamrc to /root
    && cp /root/wasm-micro-runtime/wamr-compiler/build/wamrc /root/wamrc \
    && mkdir -p /opt/wamr-sdk \
    && cp -r /root/wasm-micro-runtime/wamr-sdk/app /opt/wamr-sdk/ \
    && mv /root/wamr_toolchain.cmake /opt/wamr-sdk/app \
    #  - remove the wamr repo to save the size
    && rm -fr /root/wasm-micro-runtime

# ## STAGE 2
FROM ubuntu:22.04
ENV HOME_DIR=/home/wasm-toolchain

RUN mkdir -p /opt/wasi-sdk \
    && mkdir -p /opt/wamr-sdk/app \
    && mkdir -p /home/wasm-toolchain

# COPY files from BASE image
COPY --from=BASE /opt/wamr-sdk/app/ /opt/wamr-sdk/app/
COPY --from=BASE /opt/wasi-sdk /opt/wasi-sdk/
COPY --from=BASE /root/wamrc ${HOME_DIR}
COPY --from=BASE /root/build_wasm.sh ${HOME_DIR}

RUN ln -s ${HOME_DIR}/wamrc /usr/bin/wamrc

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y cmake make --no-install-recommends \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

WORKDIR ${HOME_DIR}
