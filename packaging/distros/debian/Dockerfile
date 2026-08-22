# Special Dockerfile to build all Debian targets, the only difference is
# the packages in the base image.
# Set this to the base image to use in each case, so if we want to build for debian/bullseye
# we would set BASE_BUILDER=debian-bullseye-base.
ARG BASE_BUILDER
# Lookup the name to use below but should follow the '<distro>-base' convention with slashes replaced.
# Use buildkit to skip unused base images: DOCKER_BUILDKIT=1

# Multiarch support
FROM multiarch/qemu-user-static:x86_64-aarch64 AS multiarch-aarch64

# debian/buster base image
FROM debian:buster-slim AS debian-buster-base
ENV DEBIAN_FRONTEND="noninteractive" \
    CMAKE_HOME="/opt/cmake"

ARG CMAKE_VERSION="3.31.6"
ARG CMAKE_URL="https://github.com/Kitware/CMake/releases/download"

# Patch to archive.debian.org
# https://lists.debian.org/debian-devel-announce/2025/06/msg00001.html
RUN sed -i s/deb.debian.org/archive.debian.org/g /etc/apt/sources.list && \
    sed -i s/security.debian.org/archive.debian.org/g /etc/apt/sources.list

# hadolint ignore=DL3008,DL3015
RUN apt-get -qq update && \
    apt-get install -y curl ca-certificates build-essential \
    make bash sudo wget unzip dh-make \
    libsystemd-dev zlib1g-dev flex bison \
    libssl1.1 libssl-dev libpq-dev postgresql-server-dev-all \
    libsasl2-2 libsasl2-dev libyaml-dev libsnmp-dev libcurl4-openssl-dev pkg-config \
    tar gzip && \
    apt-get install -y --reinstall lsb-base lsb-release && \
    mkdir -p "${CMAKE_HOME}" && \
    cmake_download_url="${CMAKE_URL}/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-$(uname -m).tar.gz" && \
    echo "Downloading CMake ${CMAKE_VERSION}: ${cmake_download_url} -> ${CMAKE_HOME}" && \
    curl -jksSL "${cmake_download_url}" | tar -xzf - -C "${CMAKE_HOME}" --strip-components 1

ENV PATH="${CMAKE_HOME}/bin:${PATH}"

# debian/buster.arm64v8 base image
FROM arm64v8/debian:buster-slim AS debian-buster.arm64v8-base
ENV DEBIAN_FRONTEND="noninteractive" \
    CMAKE_HOME="/opt/cmake"

COPY --from=multiarch-aarch64 /usr/bin/qemu-aarch64-static /usr/bin/qemu-aarch64-static

ARG CMAKE_VERSION="3.31.6"
ARG CMAKE_URL="https://github.com/Kitware/CMake/releases/download"

# Patch to archive.debian.org
# https://lists.debian.org/debian-devel-announce/2025/06/msg00001.html
RUN sed -i s/deb.debian.org/archive.debian.org/g /etc/apt/sources.list && \
    sed -i s/security.debian.org/archive.debian.org/g /etc/apt/sources.list

# hadolint ignore=DL3008,DL3015
RUN apt-get -qq update && \
    apt-get install -y curl ca-certificates build-essential \
    make bash sudo wget unzip dh-make \
    libsystemd-dev zlib1g-dev flex bison \
    libssl1.1 libssl-dev libpq-dev postgresql-server-dev-all \
    libsasl2-2 libsasl2-dev libyaml-dev libsnmp-dev libcurl4-openssl-dev pkg-config \
    tar gzip && \
    apt-get install -y --reinstall lsb-base lsb-release && \
    mkdir -p "${CMAKE_HOME}" && \
    cmake_download_url="${CMAKE_URL}/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-$(uname -m).tar.gz" && \
    echo "Downloading CMake ${CMAKE_VERSION}: ${cmake_download_url} -> ${CMAKE_HOME}" && \
    curl -jksSL "${cmake_download_url}" | tar -xzf - -C "${CMAKE_HOME}" --strip-components 1

ENV PATH="${CMAKE_HOME}/bin:${PATH}"

# debian/bullseye base image
FROM debian:bullseye-slim AS debian-bullseye-base
ENV DEBIAN_FRONTEND="noninteractive" \
    CMAKE_HOME="/opt/cmake"

ARG CMAKE_VERSION="3.31.6"
ARG CMAKE_URL="https://github.com/Kitware/CMake/releases/download"

# hadolint ignore=DL3008,DL3015
RUN apt-get -qq update && \
    apt-get install -y curl ca-certificates build-essential \
    make bash sudo wget unzip dh-make \
    libsystemd-dev zlib1g-dev flex bison \
    libssl1.1 libssl-dev libpq-dev postgresql-server-dev-all \
    libsasl2-2 libsasl2-dev libyaml-dev libsnmp-dev libcurl4-openssl-dev pkg-config \
    tar gzip && \
    apt-get install -y --reinstall lsb-base lsb-release && \
    mkdir -p "${CMAKE_HOME}" && \
    cmake_download_url="${CMAKE_URL}/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-$(uname -m).tar.gz" && \
    echo "Downloading CMake ${CMAKE_VERSION}: ${cmake_download_url} -> ${CMAKE_HOME}" && \
    curl -jksSL "${cmake_download_url}" | tar -xzf - -C "${CMAKE_HOME}" --strip-components 1

ENV PATH="${CMAKE_HOME}/bin:${PATH}"

# debian/bullseye.arm64v8 base image
FROM arm64v8/debian:bullseye-slim AS debian-bullseye.arm64v8-base
ENV DEBIAN_FRONTEND="noninteractive" \
    CMAKE_HOME="/opt/cmake"

COPY --from=multiarch-aarch64 /usr/bin/qemu-aarch64-static /usr/bin/qemu-aarch64-static

ARG CMAKE_VERSION="3.31.6"
ARG CMAKE_URL="https://github.com/Kitware/CMake/releases/download"

# hadolint ignore=DL3008,DL3015
RUN apt-get -qq update && \
    apt-get install -y curl ca-certificates build-essential \
    make bash sudo wget unzip dh-make \
    libsystemd-dev zlib1g-dev flex bison \
    libssl1.1 libssl-dev libpq-dev postgresql-server-dev-all \
    libsasl2-2 libsasl2-dev libyaml-dev libsnmp-dev libcurl4-openssl-dev pkg-config \
    tar gzip && \
    apt-get install -y --reinstall lsb-base lsb-release && \
    mkdir -p "${CMAKE_HOME}" && \
    cmake_download_url="${CMAKE_URL}/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-$(uname -m).tar.gz" && \
    echo "Downloading CMake ${CMAKE_VERSION}: ${cmake_download_url} -> ${CMAKE_HOME}" && \
    curl -jksSL "${cmake_download_url}" | tar -xzf - -C "${CMAKE_HOME}" --strip-components 1

ENV PATH="${CMAKE_HOME}/bin:${PATH}"

# debian/bookworm base image
FROM debian:bookworm-slim AS debian-bookworm-base
ENV DEBIAN_FRONTEND="noninteractive" \
    CMAKE_HOME="/opt/cmake"

ARG CMAKE_VERSION="3.31.6"
ARG CMAKE_URL="https://github.com/Kitware/CMake/releases/download"

# hadolint ignore=DL3008,DL3015
RUN apt-get -qq update && \
    apt-get install -y curl ca-certificates build-essential \
    make bash sudo wget unzip dh-make \
    libsystemd-dev zlib1g-dev flex bison \
    libssl3 libssl-dev libpq-dev postgresql-server-dev-all \
    libsasl2-2 libsasl2-dev libyaml-dev libsnmp-dev libcurl4-openssl-dev pkg-config \
    tar gzip && \
    apt-get install -y --reinstall lsb-base lsb-release && \
    mkdir -p "${CMAKE_HOME}" && \
    cmake_download_url="${CMAKE_URL}/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-$(uname -m).tar.gz" && \
    echo "Downloading CMake ${CMAKE_VERSION}: ${cmake_download_url} -> ${CMAKE_HOME}" && \
    curl -jksSL "${cmake_download_url}" | tar -xzf - -C "${CMAKE_HOME}" --strip-components 1

ENV PATH="${CMAKE_HOME}/bin:${PATH}"

# debian/bookworm.arm64v8 base image
FROM arm64v8/debian:bookworm-slim AS debian-bookworm.arm64v8-base
ENV DEBIAN_FRONTEND="noninteractive" \
    CMAKE_HOME="/opt/cmake"

COPY --from=multiarch-aarch64 /usr/bin/qemu-aarch64-static /usr/bin/qemu-aarch64-static

ARG CMAKE_VERSION="3.31.6"
ARG CMAKE_URL="https://github.com/Kitware/CMake/releases/download"

# hadolint ignore=DL3008,DL3015
RUN apt-get -qq update && \
    apt-get install -y curl ca-certificates build-essential \
    make bash sudo wget unzip dh-make \
    libsystemd-dev zlib1g-dev flex bison \
    libssl3 libssl-dev libpq-dev postgresql-server-dev-all \
    libsasl2-2 libsasl2-dev libyaml-dev libsnmp-dev libcurl4-openssl-dev pkg-config \
    tar gzip && \
    apt-get install -y --reinstall lsb-base lsb-release && \
    mkdir -p "${CMAKE_HOME}" && \
    cmake_download_url="${CMAKE_URL}/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-$(uname -m).tar.gz" && \
    echo "Downloading CMake ${CMAKE_VERSION}: ${cmake_download_url} -> ${CMAKE_HOME}" && \
    curl -jksSL "${cmake_download_url}" | tar -xzf - -C "${CMAKE_HOME}" --strip-components 1

ENV PATH="${CMAKE_HOME}/bin:${PATH}"

# debian/trixie base image
FROM debian:trixie-slim AS debian-trixie-base
ENV DEBIAN_FRONTEND="noninteractive" \
    CMAKE_HOME="/opt/cmake"

ARG CMAKE_VERSION="3.31.6"
ARG CMAKE_URL="https://github.com/Kitware/CMake/releases/download"

# hadolint ignore=DL3008,DL3015
RUN apt-get -qq update && \
    apt-get install -y curl ca-certificates build-essential \
    make bash sudo wget unzip dh-make \
    libsystemd-dev zlib1g-dev flex bison \
    libssl3 libssl-dev libpq-dev postgresql-server-dev-all \
    libsasl2-2 libsasl2-dev libyaml-dev libsnmp-dev libcurl4-openssl-dev pkg-config \
    tar gzip && \
    apt-get install -y --reinstall lsb-base lsb-release && \
    mkdir -p "${CMAKE_HOME}" && \
    cmake_download_url="${CMAKE_URL}/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-$(uname -m).tar.gz" && \
    echo "Downloading CMake ${CMAKE_VERSION}: ${cmake_download_url} -> ${CMAKE_HOME}" && \
    curl -jksSL "${cmake_download_url}" | tar -xzf - -C "${CMAKE_HOME}" --strip-components 1

ENV PATH="${CMAKE_HOME}/bin:${PATH}"

# debian/trixie.arm64v8 base image
FROM arm64v8/debian:trixie-slim AS debian-trixie.arm64v8-base
ENV DEBIAN_FRONTEND="noninteractive" \
    CMAKE_HOME="/opt/cmake"

COPY --from=multiarch-aarch64 /usr/bin/qemu-aarch64-static /usr/bin/qemu-aarch64-static

ARG CMAKE_VERSION="3.31.6"
ARG CMAKE_URL="https://github.com/Kitware/CMake/releases/download"

# hadolint ignore=DL3008,DL3015
RUN apt-get -qq update && \
    apt-get install -y curl ca-certificates build-essential \
    make bash sudo wget unzip dh-make \
    libsystemd-dev zlib1g-dev flex bison \
    libssl3 libssl-dev libpq-dev postgresql-server-dev-all \
    libsasl2-2 libsasl2-dev libyaml-dev libsnmp-dev libcurl4-openssl-dev pkg-config \
    tar gzip && \
    apt-get install -y --reinstall lsb-base lsb-release && \
    mkdir -p "${CMAKE_HOME}" && \
    cmake_download_url="${CMAKE_URL}/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-$(uname -m).tar.gz" && \
    echo "Downloading CMake ${CMAKE_VERSION}: ${cmake_download_url} -> ${CMAKE_HOME}" && \
    curl -jksSL "${cmake_download_url}" | tar -xzf - -C "${CMAKE_HOME}" --strip-components 1

ENV PATH="${CMAKE_HOME}/bin:${PATH}"

# Common build for all distributions now
# hadolint ignore=DL3006
FROM $BASE_BUILDER AS builder

ARG FLB_NIGHTLY_BUILD
ENV FLB_NIGHTLY_BUILD=$FLB_NIGHTLY_BUILD

# Docker context must be the base of the repo
WORKDIR /tmp/fluent-bit/
COPY . ./

WORKDIR /tmp/fluent-bit/build/
# CMake configuration variables
ARG CFLAGS="-std=gnu99"
ARG CMAKE_INSTALL_PREFIX=/opt/fluent-bit/
ARG CMAKE_INSTALL_SYSCONFDIR=/etc/
ARG FLB_SIMD=On
ARG FLB_RELEASE=On
ARG FLB_TRACE=On
ARG FLB_SQLDB=On
ARG FLB_HTTP_SERVER=On
ARG FLB_OUT_KAFKA=On
ARG FLB_OUT_PGSQL=On
ARG FLB_JEMALLOC=On
ARG FLB_CHUNK_TRACE=On

ENV CFLAGS=$CFLAGS
RUN cmake -DCMAKE_INSTALL_PREFIX="$CMAKE_INSTALL_PREFIX" \
    -DCMAKE_INSTALL_SYSCONFDIR="$CMAKE_INSTALL_SYSCONFDIR" \
    -DFLB_SIMD="$FLB_SIMD" \
    -DFLB_RELEASE="$FLB_RELEASE" \
    -DFLB_TRACE="$FLB_TRACE" \
    -DFLB_SQLDB="$FLB_SQLDB" \
    -DFLB_HTTP_SERVER="$FLB_HTTP_SERVER" \
    -DFLB_OUT_KAFKA="$FLB_OUT_KAFKA" \
    -DFLB_OUT_PGSQL="$FLB_OUT_PGSQL" \
    -DFLB_NIGHTLY_BUILD="$FLB_NIGHTLY_BUILD" \
    -DFLB_JEMALLOC="${FLB_JEMALLOC}" \
    -DFLB_CHUNK_TRACE="${FLB_CHUNK_TRACE}" \
    ../

VOLUME [ "/output" ]
CMD [ "/bin/bash", "-c", "make -j 4 && cpack -G DEB && cp *.deb /output/" ]
