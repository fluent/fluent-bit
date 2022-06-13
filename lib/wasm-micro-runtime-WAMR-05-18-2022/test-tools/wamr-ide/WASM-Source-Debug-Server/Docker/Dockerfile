# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

FROM gcc:9.3.0 AS BASE

## set work directory
WORKDIR /root/
COPY resource /root/

##  - download cmake with wget and set up
RUN wget https://github.com/Kitware/CMake/releases/download/v3.21.1/cmake-3.21.1-linux-x86_64.tar.gz \
    && tar -zxvf cmake-3.21.1-linux-x86_64.tar.gz \
    && rm -f cmake-3.21.1-linux-x86_64.tar.gz \
    && mv cmake-3.21.1-linux-x86_64 /opt/cmake \
    && ln -s /opt/cmake/bin/cmake /bin/cmake \
    && apt-get install make

##  -clone wamr-repo and build iwasm
RUN git clone -b main --depth=1 https://github.com/bytecodealliance/wasm-micro-runtime.git \
    && cd /root/wasm-micro-runtime/product-mini/platforms/linux \
    && mkdir build && cd build \
    && cmake .. -DWAMR_BUILD_DEBUG_INTERP=1 && make \
    && cp /root/wasm-micro-runtime/product-mini/platforms/linux/build/iwasm /root/iwasm \
    && rm -fr /root/wasm-micro-runtime

FROM ubuntu:20.04
# COPY files from BASE image
COPY --from=BASE /root/iwasm /root
COPY --from=BASE /root/debug.sh /root
COPY --from=BASE /root/run.sh /root

WORKDIR /root/