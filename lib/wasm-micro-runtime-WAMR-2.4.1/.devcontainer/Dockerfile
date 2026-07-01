# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.245.2/containers/cpp/.devcontainer/base.Dockerfile
# [Choice] Debian / Ubuntu version (use Debian 12/11/9, Ubuntu 18.04/21.04 on local arm64/Apple Silicon): debian-12, debian-11, debian-10, debian-9, ubuntu-21.04, ubuntu-20.04, ubuntu-18.04
ARG VARIANT=debian-12
FROM mcr.microsoft.com/vscode/devcontainers/cpp:${VARIANT}

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Asian/Shanghai

# hadolint ignore=DL3008
RUN apt-get update \
  && apt-get upgrade -y \
  && apt-get install -y apt-transport-https apt-utils build-essential \
  ca-certificates ccache cmake curl g++-multilib git gnupg \
  libgcc-12-dev lib32gcc-12-dev lsb-release \
  ninja-build ocaml ocamlbuild \
  software-properties-common tree tzdata \
  unzip valgrind vim wget zip --no-install-recommends \
  && apt-get clean -y \
  && rm -rf /var/lib/apt/lists/*

#
# binaryen
ARG BINARYEN_VER=114
WORKDIR /opt
RUN wget -c --progress=dot:giga https://github.com/WebAssembly/binaryen/releases/download/version_${BINARYEN_VER}/binaryen-version_${BINARYEN_VER}-x86_64-linux.tar.gz \
  && tar xf binaryen-version_${BINARYEN_VER}-x86_64-linux.tar.gz \
  && ln -sf /opt/binaryen-version_${BINARYEN_VER} /opt/binaryen \
  && rm binaryen-version_${BINARYEN_VER}-x86_64-linux.tar.gz

#
# CMAKE (https://apt.kitware.com/)
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
# hadolint ignore=DL3008
ARG CMAKE_VER=3.27.0
RUN wget https://github.com/Kitware/CMake/releases/download/v${CMAKE_VER}/cmake-${CMAKE_VER}-Linux-x86_64.sh \
      -q -O /tmp/cmake-install.sh \
      && chmod u+x /tmp/cmake-install.sh \
      && mkdir /opt/cmake-${CMAKE_VER} \
      && /tmp/cmake-install.sh --skip-license --prefix=/opt/cmake-${CMAKE_VER} \
      && rm /tmp/cmake-install.sh \
      && ln -s /opt/cmake-${CMAKE_VER}/bin/* /usr/local/bin

#
# install emsdk
WORKDIR /opt
RUN git clone https://github.com/emscripten-core/emsdk.git

ARG EMSDK_VER=3.1.43
WORKDIR /opt/emsdk
RUN  git pull \
  && ./emsdk install ${EMSDK_VER} \
  && ./emsdk activate ${EMSDK_VER} \
  && echo "source /opt/emsdk/emsdk_env.sh" >> /root/.bashrc

#
# install wasi-sdk
ARG WASI_SDK_VER=20
RUN wget -c --progress=dot:giga https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_SDK_VER}/wasi-sdk-${WASI_SDK_VER}.0-linux.tar.gz -P /opt \
  && tar xf /opt/wasi-sdk-${WASI_SDK_VER}.0-linux.tar.gz -C /opt \
  && ln -sf /opt/wasi-sdk-${WASI_SDK_VER}.0 /opt/wasi-sdk \
  && rm /opt/wasi-sdk-${WASI_SDK_VER}.0-linux.tar.gz

#
#install wabt
ARG WABT_VER=1.0.33
RUN wget -c --progress=dot:giga https://github.com/WebAssembly/wabt/releases/download/${WABT_VER}/wabt-${WABT_VER}-ubuntu.tar.gz -P /opt \
  && tar xf /opt/wabt-${WABT_VER}-ubuntu.tar.gz -C /opt \
  && ln -sf /opt/wabt-${WABT_VER} /opt/wabt \
  && rm /opt/wabt-${WABT_VER}-ubuntu.tar.gz

#
# install bazelisk
ARG BAZELISK_VER=1.17.0
RUN mkdir /opt/bazelisk \
  && wget -c --progress=dot:giga https://github.com/bazelbuild/bazelisk/releases/download/v${BAZELISK_VER}/bazelisk-linux-amd64 -P /opt/bazelisk \
  && chmod a+x /opt/bazelisk/bazelisk-linux-amd64 \
  && ln -fs /opt/bazelisk/bazelisk-linux-amd64 /opt/bazelisk/bazel

#
# install clang+llvm
ARG LLVM_VER=16
RUN apt-get purge -y clang-14 llvm-14 && apt-get autoremove -y
WORKDIR /etc/apt/apt.conf.d
RUN touch 99verfiy-peer.conf \
  && echo "Acquire { https::Verify-Peer false }" > 99verfiy-peer.conf

WORKDIR /tmp
#RUN wget --progress=dot:giga https://apt.llvm.org/llvm.sh \
#  && chmod a+x ./llvm.sh \
#  && ./llvm.sh ${LLVM_VER} all

# Workaround due to https://github.com/llvm/llvm-project/issues/62475
# hadolint ignore=DL3008
RUN set -ex \
    && echo "deb http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-${LLVM_VER} main" > /etc/apt/sources.list.d/apt.llvm.org.list \
    && wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc \
    && apt-get update \
    && apt-get install -y \
    clang-${LLVM_VER} lldb-${LLVM_VER} lld-${LLVM_VER} clangd-${LLVM_VER} clang-tidy-${LLVM_VER} clang-format-${LLVM_VER} clang-tools-${LLVM_VER} \
    llvm-${LLVM_VER}-dev lld-${LLVM_VER} lldb-${LLVM_VER} llvm-${LLVM_VER}-tools libomp-${LLVM_VER}-dev libc++-${LLVM_VER}-dev libc++abi-${LLVM_VER}-dev \
    libclang-common-${LLVM_VER}-dev libclang-${LLVM_VER}-dev libclang-cpp${LLVM_VER}-dev libunwind-${LLVM_VER}-dev \
    libclang-rt-${LLVM_VER}-dev libpolly-${LLVM_VER}-dev --no-install-recommends \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

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
RUN python3 -m pip install --no-cache-dir --break-system-packages --upgrade pip \
  && pip3 install --no-cache-dir --break-system-packages black nose pycparser pylint

#
# Install github-cli. It doens't work as a feature of devcontainer.json
ARG GH_CLI_VER=2.32.0
WORKDIR /tmp
RUN wget -q https://github.com/cli/cli/releases/download/v${GH_CLI_VER}/gh_${GH_CLI_VER}_linux_amd64.deb \
  && dpkg -i gh_${GH_CLI_VER}_linux_amd64.deb

#
# Install NodeJS
RUN wget -qO- https://deb.nodesource.com/setup_20.x | bash -
# hadolint ignore=DL3008
RUN apt-get install -y nodejs --no-install-recommends

# set path
ENV PATH="/opt/bazelisk:/usr/lib/llvm-${LLVM_VER}/bin:${PATH}"
ENV CC=/usr/lib/llvm-${LLVM_VER}/bin/clang CXX=/usr/lib/llvm-${LLVM_VER}/bin/clang++
RUN printf "%s\n" "PS1='\n[ \u@wamr-dev-docker \W ]\n$ '" >> /root/.bashrc \
  && apt-get autoremove -y \
  && apt-get clean -y \
  && rm -rf /var/lib/apt/lists/* \
  && rm -rf /tmp/*

# set workdir when container run
VOLUME /workspaces
WORKDIR /workspaces
