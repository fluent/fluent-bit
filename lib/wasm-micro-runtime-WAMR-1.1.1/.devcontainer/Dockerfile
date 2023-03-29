# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.195.0/containers/cpp/.devcontainer/base.Dockerfile
# [Choice] Debian / Ubuntu version (use Debian 11/9, Ubuntu 18.04/21.04 on local arm64/Apple Silicon): debian-11, debian-10, debian-9, ubuntu-21.04, ubuntu-20.04, ubuntu-18.04
ARG VARIANT=ubuntu-20.04
FROM mcr.microsoft.com/vscode/devcontainers/cpp:0-${VARIANT}

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Asian/Shanghai

# hadolint ignore=DL3008
RUN apt-get update \
  && apt-get install -y apt-transport-https apt-utils build-essential \
  ca-certificates curl g++-multilib git gnupg \
  libgcc-9-dev lib32gcc-9-dev lsb-release \
  ninja-build ocaml ocamlbuild python2.7 \
  software-properties-common tree tzdata \
  unzip valgrind vim wget zip --no-install-recommends \
  && apt-get clean -y \
  && rm -rf /var/lib/apt/lists/*

#
# CMAKE (https://apt.kitware.com/)
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
# hadolint ignore=DL3008
RUN wget --progress=dot:giga -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - | tee /usr/share/keyrings/kitware-archive-keyring.gpg > /dev/null \
  && echo 'deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ bionic main' | tee /etc/apt/sources.list.d/kitware.list >/dev/null \
  && apt-get update \
  && rm /usr/share/keyrings/kitware-archive-keyring.gpg \
  && apt-get install -y kitware-archive-keyring --no-install-recommends \
  && apt-get install -y cmake --no-install-recommends \
  && apt-get clean -y \
  && rm -rf /var/lib/apt/lists/* 

#
# install emsdk
WORKDIR /opt
RUN git clone https://github.com/emscripten-core/emsdk.git

WORKDIR /opt/emsdk
RUN  git pull \
  && ./emsdk install 2.0.26 \
  && ./emsdk activate 2.0.26 \
  && echo "source /opt/emsdk/emsdk_env.sh" >> /root/.bashrc

#
# install wasi-sdk
ARG WASI_SDK_VER=16
RUN wget -c --progress=dot:giga https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_SDK_VER}/wasi-sdk-${WASI_SDK_VER}.0-linux.tar.gz -P /opt \
  && tar xf /opt/wasi-sdk-${WASI_SDK_VER}.0-linux.tar.gz -C /opt \
  && ln -fs /opt/wasi-sdk-${WASI_SDK_VER}.0 /opt/wasi-sdk \
  && rm /opt/wasi-sdk-${WASI_SDK_VER}.0-linux.tar.gz

#
#install wabt
ARG WABT_VER=1.0.29
RUN wget -c --progress=dot:giga https://github.com/WebAssembly/wabt/releases/download/${WABT_VER}/wabt-${WABT_VER}-ubuntu.tar.gz -P /opt \
  && tar xf /opt/wabt-${WABT_VER}-ubuntu.tar.gz -C /opt \
  && ln -fs /opt/wabt-${WABT_VER} /opt/wabt \
  && rm /opt/wabt-${WABT_VER}-ubuntu.tar.gz

#
# install bazelisk
ARG BAZELISK_VER=1.12.0
RUN mkdir /opt/bazelisk \ 
  && wget -c --progress=dot:giga https://github.com/bazelbuild/bazelisk/releases/download/v${BAZELISK_VER}/bazelisk-linux-amd64 -P /opt/bazelisk \
  && chmod a+x /opt/bazelisk/bazelisk-linux-amd64 \
  && ln -fs /opt/bazelisk/bazelisk-linux-amd64 /opt/bazelisk/bazel

#
# install clang+llvm
WORKDIR /etc/apt/apt.conf.d
RUN touch 99verfiy-peer.conf \
  && echo "Acquire { https::Verify-Peer false }" > 99verfiy-peer.conf

WORKDIR /tmp 
RUN wget --progress=dot:giga https://apt.llvm.org/llvm.sh \
  && chmod a+x ./llvm.sh \
  && /tmp/llvm.sh 12 all \ 
  && ln -sf /usr/bin/clang-format-12 /usr/bin/clang-format \
  && rm -rf /tmp/*

#
# [Optional]

#
# Install pip
# hadolint ignore=DL3008
RUN apt-get update \
  && apt-get install -y --reinstall python3-venv python3-pip --no-install-recommends \
  && apt-get clean -y \
  && rm -rf /var/lib/apt/lists/*

#
# Install required python packages
# hadolint ignore=DL3013
RUN python3 -m pip install --no-cache-dir --upgrade pip \
  && pip3 install --no-cache-dir --user black nose pycparser pylint

# set path, PS and clean up
ENV PATH "/opt/bazelisk:/opt/clang-llvm/bin:${PATH}"
RUN echo "export PATH=/opt/bazelisk:/opt/clang-llvm/bin:${PATH}" >> /root/.bashrc \
  && printf "%s\n" "PS1='\n[ \u@wamr-dev-docker \W ]\n$ '" >> /root/.bashrc \
  && apt-get autoremove -y \
  && apt-get clean -y \
  && rm -rf /var/lib/apt/lists/* \
  && rm -rf /tmp/*

# set workdir when container run
VOLUME /workspace
WORKDIR /workspace