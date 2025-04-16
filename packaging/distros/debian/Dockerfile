# hadolint ignore=DL3006
ARG BASE_BUILDER

# Multiarch support
FROM multiarch/qemu-user-static:x86_64-aarch64 AS multiarch-aarch64

# CMake 3.20.0 builder for Debian Buster
FROM debian:buster-slim AS cmake-3.20-installer-buster
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -qq update && \
    apt-get install -y curl build-essential libssl-dev zlib1g-dev && \
    curl -LO https://github.com/Kitware/CMake/releases/download/v3.20.0/cmake-3.20.0.tar.gz && \
    tar -xzf cmake-3.20.0.tar.gz && cd cmake-3.20.0 && \
    ./bootstrap -- -DCMAKE_USE_OPENSSL=OFF && \
    make -j"$(nproc)" && make install && \
    cmake --version

# debian/buster base image
FROM debian:buster-slim AS debian-buster-base
ENV DEBIAN_FRONTEND=noninteractive
COPY --from=cmake-3.20-installer-buster /usr/local /usr/local
RUN apt-get -qq update && \
    apt-get install -y curl ca-certificates build-essential \
    make bash sudo wget unzip dh-make \
    libsystemd-dev zlib1g-dev flex bison \
    libssl1.1 libssl-dev libpq-dev postgresql-server-dev-all \
    libsasl2-2 libsasl2-dev libyaml-dev libcurl4-openssl-dev pkg-config && \
    apt-get install -y --reinstall lsb-base lsb-release


# CMake 3.20.0 builder for Debian Buster Arm64
FROM debian:buster-slim AS cmake-3.20-installer-buster-arm64
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -qq update && \
    apt-get install -y curl build-essential libssl-dev zlib1g-dev && \
    curl -LO https://github.com/Kitware/CMake/releases/download/v3.20.0/cmake-3.20.0.tar.gz && \
    tar -xzf cmake-3.20.0.tar.gz && cd cmake-3.20.0 && \
    ./bootstrap -- -DCMAKE_USE_OPENSSL=OFF && \
    make -j"$(nproc)" && make install && \
    cmake --version

# debian/buster.arm64v8 base image
FROM --platform=linux/arm64 arm64v8/debian:buster-slim AS debian-buster.arm64v8-base
ENV DEBIAN_FRONTEND=noninteractive
COPY --from=multiarch-aarch64 /usr/bin/qemu-aarch64-static /usr/bin/qemu-aarch64-static
COPY --from=cmake-3.20-installer-buster-arm64 /usr/local /usr/local
RUN apt-get -qq update && \
    apt-get install -y curl ca-certificates build-essential \
    make bash sudo wget unzip dh-make \
    libsystemd-dev zlib1g-dev flex bison \
    libssl1.1 libssl-dev libpq-dev postgresql-server-dev-all \
    libsasl2-2 libsasl2-dev libyaml-dev libcurl4-openssl-dev pkg-config && \
    apt-get install -y --reinstall lsb-base lsb-release


# CMake 3.20.0 builder for Debian Bullseye
FROM debian:bullseye-slim AS cmake-3.20-installer-bullseye
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -qq update && \
    apt-get install -y curl build-essential libssl-dev zlib1g-dev && \
    curl -LO https://github.com/Kitware/CMake/releases/download/v3.20.0/cmake-3.20.0.tar.gz && \
    tar -xzf cmake-3.20.0.tar.gz && cd cmake-3.20.0 && \
    ./bootstrap -- -DCMAKE_USE_OPENSSL=OFF && \
    make -j"$(nproc)" && make install && \
    cmake --version

# debian/bullseye base image
FROM debian:bullseye-slim AS debian-bullseye-base
ENV DEBIAN_FRONTEND=noninteractive
COPY --from=cmake-3.20-installer-bullseye /usr/local /usr/local
RUN apt-get -qq update && \
    apt-get install -y curl ca-certificates build-essential \
    make bash sudo wget unzip dh-make \
    libsystemd-dev zlib1g-dev flex bison \
    libssl1.1 libssl-dev libpq-dev postgresql-server-dev-all \
    libsasl2-2 libsasl2-dev libyaml-dev libcurl4-openssl-dev pkg-config && \
    apt-get install -y --reinstall lsb-base lsb-release

# CMake 3.20.0 builder for Debian Bullseye Arm64
FROM --platform=linux/arm64 arm64v8/debian:bullseye-slim AS cmake-3.20-installer-bullseye-arm64
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -qq update && \
    apt-get install -y curl build-essential libssl-dev zlib1g-dev && \
    curl -LO https://github.com/Kitware/CMake/releases/download/v3.20.0/cmake-3.20.0.tar.gz && \
    tar -xzf cmake-3.20.0.tar.gz && cd cmake-3.20.0 && \
    ./bootstrap -- -DCMAKE_USE_OPENSSL=OFF && \
    make -j"$(nproc)" && make install && \
    cmake --version

# debian/bullseye.arm64v8 base image
FROM arm64v8/debian:bullseye-slim AS debian-bullseye.arm64v8-base
ENV DEBIAN_FRONTEND=noninteractive
COPY --from=multiarch-aarch64 /usr/bin/qemu-aarch64-static /usr/bin/qemu-aarch64-static
COPY --from=cmake-3.20-installer-bullseye-arm64 /usr/local /usr/local
RUN apt-get -qq update && \
    apt-get install -y curl ca-certificates build-essential \
    make bash sudo wget unzip dh-make \
    libsystemd-dev zlib1g-dev flex bison \
    libssl1.1 libssl-dev libpq-dev postgresql-server-dev-all \
    libsasl2-2 libsasl2-dev libyaml-dev libcurl4-openssl-dev pkg-config && \
    apt-get install -y --reinstall lsb-base lsb-release


# CMake 3.20.0 builder for Debian Bookworm
FROM debian:bookworm-slim AS cmake-3.20-installer-bookworm
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -qq update && \
    apt-get install -y curl build-essential libssl-dev zlib1g-dev && \
    curl -LO https://github.com/Kitware/CMake/releases/download/v3.20.0/cmake-3.20.0.tar.gz && \
    tar -xzf cmake-3.20.0.tar.gz && cd cmake-3.20.0 && \
    ./bootstrap -- -DCMAKE_USE_OPENSSL=OFF && \
    make -j"$(nproc)" && make install && \
    cmake --version

# debian/bookworm base image
FROM debian:bookworm-slim AS debian-bookworm-base
ENV DEBIAN_FRONTEND=noninteractive
COPY --from=cmake-3.20-installer-bookworm /usr/local /usr/local
RUN apt-get -qq update && \
    apt-get install -y curl ca-certificates build-essential \
    make bash sudo wget unzip dh-make \
    libsystemd-dev zlib1g-dev flex bison \
    libssl3 libssl-dev libpq-dev postgresql-server-dev-all \
    libsasl2-2 libsasl2-dev libyaml-dev libcurl4-openssl-dev pkg-config && \
    apt-get install -y --reinstall lsb-base lsb-release

# CMake 3.20.0 builder for Debian Bookworm Arm64
FROM --platform=linux/arm64 arm64v8/debian:bookworm-slim AS cmake-3.20-installer-bookworm-arm64
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -qq update && \
    apt-get install -y curl build-essential libssl-dev zlib1g-dev && \
    curl -LO https://github.com/Kitware/CMake/releases/download/v3.20.0/cmake-3.20.0.tar.gz && \
    tar -xzf cmake-3.20.0.tar.gz && cd cmake-3.20.0 && \
    ./bootstrap -- -DCMAKE_USE_OPENSSL=OFF && \
    make -j"$(nproc)" && make install && \
    cmake --version

# debian/bookworm.arm64v8 base image
FROM arm64v8/debian:bookworm-slim AS debian-bookworm.arm64v8-base
ENV DEBIAN_FRONTEND=noninteractive
COPY --from=multiarch-aarch64 /usr/bin/qemu-aarch64-static /usr/bin/qemu-aarch64-static
COPY --from=cmake-3.20-installer-bookworm-arm64 /usr/local /usr/local
RUN apt-get -qq update && \
    apt-get install -y curl ca-certificates build-essential \
    make bash sudo wget unzip dh-make \
    libsystemd-dev zlib1g-dev flex bison \
    libssl3 libssl-dev libpq-dev postgresql-server-dev-all \
    libsasl2-2 libsasl2-dev libyaml-dev libcurl4-openssl-dev pkg-config && \
    apt-get install -y --reinstall lsb-base lsb-release

# Final builder
FROM ${BASE_BUILDER} AS builder

ARG FLB_NIGHTLY_BUILD
ENV FLB_NIGHTLY_BUILD=$FLB_NIGHTLY_BUILD

WORKDIR /tmp/fluent-bit/
COPY . ./

WORKDIR /tmp/fluent-bit/build/
ARG CFLAGS="-std=gnu99"
ARG CMAKE_INSTALL_PREFIX=/opt/fluent-bit/
ARG CMAKE_INSTALL_SYSCONFDIR=/etc/
ARG FLB_RELEASE=On
ARG FLB_TRACE=On
ARG FLB_SQLDB=On
ARG FLB_HTTP_SERVER=On
ARG FLB_OUT_KAFKA=On
ARG FLB_OUT_PGSQL=On
ARG FLB_JEMALLOC=On
ARG FLB_CHUNK_TRACE=On

ENV CFLAGS=$CFLAGS

RUN  cmake --version && \
     cmake -DCMAKE_INSTALL_PREFIX="$CMAKE_INSTALL_PREFIX" \
    -DCMAKE_INSTALL_SYSCONFDIR="$CMAKE_INSTALL_SYSCONFDIR" \
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
CMD [ "/bin/bash", "-c", "make -j$(nproc) && cpack -G DEB && cp *.deb /output/" ]
