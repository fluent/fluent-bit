# Dockerfile to build latest opensuse leap
# Set this to the base image to use in each case, so if we want to build for opensuse/leap
# we would set BASE_BUILDER=opensuse-leap-base.
ARG BASE_BUILDER
# Lookup the name to use below but should follow the '<distro>-base' convention with slashes replaced.
# Use buildkit to skip unused base images: DOCKER_BUILDKIT=1

# Multiarch support
FROM multiarch/qemu-user-static:x86_64-aarch64 AS multiarch-aarch64

# opensuse/leap base image
# hadolint ignore=DL3006
FROM opensuse/leap AS opensuse-leap-base

# hadolint ignore=DL3037,DL3033
RUN zypper up -y && \
    zypper install -y --no-recommends \
        rpm-build \
        curl ca-certificates wget unzip flex bison \
        gcc gcc-c++ \
        cmake-full \
        make \
        bash \
        systemd-devel \
        postgresql postgresql-devel postgresql-server \
        cyrus-sasl cyrus-sasl-devel \
        libopenssl3 libopenssl-devel \
        libyaml-devel && \
    zypper clean -a && rm -rf /var/cache/zypp/*

# opensuse/leap base image
FROM opensuse/leap:15.6 AS opensuse-15.6-base 

# hadolint ignore=DL3037,DL3033
RUN zypper up -y && \
    zypper install -y --no-recommends \
        rpm-build \
        curl ca-certificates wget unzip flex bison \
        gcc gcc-c++ \
        cmake-full \
        make \
        bash \
        systemd-devel \
        postgresql postgresql-devel postgresql-server \
        cyrus-sasl cyrus-sasl-devel \
        libopenssl3 libopenssl-devel \
        libyaml-devel && \
    zypper clean -a && rm -rf /var/cache/zypp/*

# opensuse/leap.arm64v8 base image
# hadolint ignore=DL3037,DL3029
FROM --platform=arm64 opensuse/leap:15.6 AS opensuse-15.6.arm64v8-base

COPY --from=multiarch-aarch64 /usr/bin/qemu-aarch64-static /usr/bin/qemu-aarch64-static

# hadolint ignore=DL3033,DL3037
RUN zypper up -y && \
    zypper install -y --no-recommends \
        rpm-build \
        curl ca-certificates wget unzip flex bison \
        gcc gcc-c++ \
        cmake-full \
        make \
        bash \
        systemd-devel \
        postgresql postgresql-devel postgresql-server \
        cyrus-sasl cyrus-sasl-devel \
        libopenssl3 libopenssl-devel \
        libyaml-devel && \
    zypper clean -a && rm -rf /var/cache/zypp/*

# Need larger page size
ARG FLB_JEMALLOC_OPTIONS="--with-lg-page=16 --with-lg-quantum=3"
ENV FLB_JEMALLOC_OPTIONS=$FLB_JEMALLOC_OPTIONS

# Common build for all distributions now
# hadolint ignore=DL3006
FROM $BASE_BUILDER AS builder
#

ARG FLB_NIGHTLY_BUILD
ENV FLB_NIGHTLY_BUILD=$FLB_NIGHTLY_BUILD

# Docker context must be the base of the repo
WORKDIR /source/fluent-bit/
COPY . ./

WORKDIR /source/fluent-bit/build/
# CMake configuration variables
# Unused
ARG CFLAGS
ARG CMAKE_INSTALL_PREFIX=/opt/fluent-bit/
ARG CMAKE_INSTALL_SYSCONFDIR=/etc/
ARG FLB_SIMD=On
ARG FLB_RELEASE=On
ARG FLB_TRACE=On
ARG FLB_SQLDB=On
ARG FLB_HTTP_SERVER=On
ARG FLB_OUT_KAFKA=On
ARG FLB_JEMALLOC=On
ARG FLB_CHUNK_TRACE=On
ARG FLB_UNICODE_ENCODER=On
ARG FLB_KAFKA=On
ARG FLB_OUT_PGSQL=On
ARG SYSTEMD_UNITDIR=/usr/lib/systemd/system

RUN cmake -DCMAKE_INSTALL_PREFIX="$CMAKE_INSTALL_PREFIX" \
    -DCMAKE_INSTALL_SYSCONFDIR="$CMAKE_INSTALL_SYSCONFDIR" \
    -DFLB_SIMD="$FLB_SIMD" \
    -DFLB_RELEASE="$FLB_RELEASE" \
    -DFLB_TRACE="$FLB_TRACE" \
    -DFLB_SQLDB="$FLB_SQLDB" \
    -DFLB_HTTP_SERVER="$FLB_HTTP_SERVER" \
    -DFLB_KAFKA="$FLB_KAFKA" \
    -DFLB_OUT_PGSQL="$FLB_OUT_PGSQL" \
    -DFLB_NIGHTLY_BUILD="$FLB_NIGHTLY_BUILD" \
    -DFLB_JEMALLOC_OPTIONS="$FLB_JEMALLOC_OPTIONS" \
    -DFLB_JEMALLOC="${FLB_JEMALLOC}" \
    -DFLB_CHUNK_TRACE="${FLB_CHUNK_TRACE}" \
    -DFLB_UNICODE_ENCODER="${FLB_UNICODE_ENCODER}" \
    -DSYSTEMD_UNITDIR="$SYSTEMD_UNITDIR" \
    ../

VOLUME [ "/output" ]
CMD [ "/bin/bash", "-c", "make --no-print-directory -j 4 && cpack -G RPM && cp *.rpm /output/" ]
