# Special Dockerfile to build all Ubuntu targets, the only difference is
# the packages in the base image.
# Set this to the base image to use in each case, so if we want to build for ubuntu/20.04
# we would set BASE_BUILDER=ubuntu-20.04-base.
ARG BASE_BUILDER
# Lookup the name to use below but should follow the '<distro>-base' convention with slashes replaced.
# Use buildkit to skip unused base images: DOCKER_BUILDKIT=1

FROM balenalib/rpi-raspbian:buster AS raspbian-buster-base
ENV DEBIAN_FRONTEND noninteractive

# Builder image so dependencies can be latest, recommended and no need to wipe
# We pin cmake to a working version (latest 3.16 triggers cmake failures for GNU C compiler detection)
# hadolint ignore=DL3008,DL3015
RUN apt-get update && \
    apt-get install -y cmake=3.13.4-1 cmake-data=3.13.4-1 \
    curl ca-certificates build-essential \
    make bash sudo wget unzip dh-make \
    libsystemd-dev zlib1g-dev flex bison \
    libssl1.1 libssl-dev libpq-dev postgresql-server-dev-all \
    libsasl2-2 libsasl2-dev libyaml-dev libcurl4-openssl-dev pkg-config && \
    apt-get install -y --reinstall lsb-base lsb-release

# raspbian/bullseye base image
FROM balenalib/rpi-raspbian:bullseye AS raspbian-bullseye-base
ENV DEBIAN_FRONTEND noninteractive

# hadolint ignore=DL3008,DL3015
RUN apt-get update && \
    apt-get install -y curl ca-certificates build-essential \
    cmake make bash sudo wget unzip dh-make \
    libsystemd-dev zlib1g-dev flex bison \
    libssl1.1 libssl-dev libpq-dev postgresql-server-dev-all \
    libsasl2-2 libsasl2-dev libyaml-dev libcurl4-openssl-dev pkg-config && \
    apt-get install -y --reinstall lsb-base lsb-release

# raspbian/bookworm base image
FROM balenalib/rpi-raspbian:bookworm AS raspbian-bookworm-base
ENV DEBIAN_FRONTEND noninteractive

# hadolint ignore=DL3008,DL3015
RUN apt-get update && \
    apt-get install -y curl ca-certificates build-essential \
    cmake make bash sudo wget unzip dh-make \
    libsystemd-dev zlib1g-dev flex bison \
    libssl3 libssl-dev libpq-dev postgresql-server-dev-all \
    libsasl2-2 libsasl2-dev libyaml-dev libcurl4-openssl-dev pkg-config && \
    apt-get install -y --reinstall lsb-base lsb-release

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
ARG FLB_RELEASE=On
ARG FLB_TRACE=On
ARG FLB_SQLDB=On
ARG FLB_HTTP_SERVER=On
ARG FLB_OUT_KAFKA=On
ARG FLB_OUT_PGSQL=On
ARG FLB_JEMALLOC=On
ARG FLB_CHUNK_TRACE=On
#Tell raspbian packages should be using armv7.
ARG WAMR_BUILD_TARGET=ARMV7A

ENV CFLAGS=$CFLAGS
RUN cmake -DCMAKE_INSTALL_PREFIX="$CMAKE_INSTALL_PREFIX" \
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
    -DWAMR_BUILD_TARGET="${WAMR_BUILD_TARGET}" \
    ../

VOLUME [ "/output" ]
CMD [ "/bin/bash", "-c", "make -j 4 && cpack -G DEB && cp *.deb /output/" ]
