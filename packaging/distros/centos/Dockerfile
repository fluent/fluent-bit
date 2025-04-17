# Special Dockerfile to build all CentOS targets, the only difference is
# the packages in the base image.
# Set this to the base image to use in each case, so if we want to build for centos/7
# we would set BASE_BUILDER=centos-7-base.
ARG BASE_BUILDER
# Lookup the name to use below but should follow the '<distro>-base' convention with slashes replaced.
# Use buildkit to skip unused base images: DOCKER_BUILDKIT=1

# Multiarch support
FROM multiarch/qemu-user-static:x86_64-aarch64 AS multiarch-aarch64

# centos/7 base image
FROM centos:7 AS centos-7-base

ENV CMAKE_HOME="/opt/cmake"
ARG CMAKE_VERSION="3.31.6"
ARG CMAKE_URL="https://github.com/Kitware/CMake/releases/download"

# hadolint ignore=DL3033
RUN sed -i -e "s/^mirrorlist=http:\/\/mirrorlist.centos.org/#mirrorlist=http:\/\/mirrorlist.centos.org/g" /etc/yum.repos.d/CentOS-Base.repo && \
    sed -i -e "s/^#baseurl=http:\/\/mirror.centos.org/baseurl=http:\/\/vault.centos.org/g" /etc/yum.repos.d/CentOS-Base.repo && \
    yum -y update && \
    yum install -y rpm-build curl ca-certificates gcc gcc-c++ make bash \
    wget unzip systemd-devel wget flex bison \
    cyrus-sasl-lib cyrus-sasl-devel openssl openssl-libs openssl-devel libcurl-devel \
    postgresql-libs postgresql-devel postgresql-server postgresql libyaml-devel \
    tar gzip && \
    yum install -y epel-release && \
    yum install -y cmake3 && \
    yum clean all && \
    mkdir -p "${CMAKE_HOME}" && \
    cmake_download_url="${CMAKE_URL}/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-$(uname -m).tar.gz" && \
    echo "Downloading CMake ${CMAKE_VERSION}: ${cmake_download_url} -> ${CMAKE_HOME}" && \
    curl -jksSL "${cmake_download_url}" | tar -xzf - -C "${CMAKE_HOME}" --strip-components 1

ENV PATH="${CMAKE_HOME}/bin:${PATH}"

ARG FLB_OUT_PGSQL=On
ENV FLB_OUT_PGSQL=$FLB_OUT_PGSQL
ARG FLB_UNICODE_ENCODER=Off
ENV FLB_UNICODE_ENCODER=$FLB_UNICODE_ENCODER
ARG FLB_KAFKA=Off
ENV FLB_KAFKA=$FLB_KAFKA

# centos/7.arm64v8 base image
FROM arm64v8/centos:7 AS centos-7.arm64v8-base

COPY --from=multiarch-aarch64 /usr/bin/qemu-aarch64-static /usr/bin/qemu-aarch64-static

ENV CMAKE_HOME="/opt/cmake"
ARG CMAKE_VERSION="3.31.6"
ARG CMAKE_URL="https://github.com/Kitware/CMake/releases/download"

# hadolint ignore=DL3033
RUN sed -i -e "s/^mirrorlist=http:\/\/mirrorlist.centos.org/#mirrorlist=http:\/\/mirrorlist.centos.org/g" /etc/yum.repos.d/CentOS-Base.repo && \
    sed -i -e "s/^#baseurl=http:\/\/mirror.centos.org/baseurl=http:\/\/vault.centos.org/g" /etc/yum.repos.d/CentOS-Base.repo && \
    yum -y update && \
    yum install -y rpm-build curl ca-certificates gcc gcc-c++ make bash \
    wget unzip systemd-devel wget flex bison \
    cyrus-sasl-lib cyrus-sasl-devel openssl openssl-libs openssl-devel libcurl-devel \
    postgresql-libs postgresql-devel postgresql-server postgresql libyaml-devel \
    tar gzip && \
    yum install -y epel-release && \
    yum install -y cmake3 && \
    yum clean all && \
    mkdir -p "${CMAKE_HOME}" && \
    cmake_download_url="${CMAKE_URL}/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-$(uname -m).tar.gz" && \
    echo "Downloading CMake ${CMAKE_VERSION}: ${cmake_download_url} -> ${CMAKE_HOME}" && \
    curl -jksSL "${cmake_download_url}" | tar -xzf - -C "${CMAKE_HOME}" --strip-components 1

ENV PATH="${CMAKE_HOME}/bin:${PATH}"

# There are no postgresql libraries available for this target
ARG FLB_OUT_PGSQL=Off
ENV FLB_OUT_PGSQL=$FLB_OUT_PGSQL
ARG FLB_UNICODE_ENCODER=Off
ENV FLB_UNICODE_ENCODER=$FLB_UNICODE_ENCODER
ARG FLB_KAFKA=Off
ENV FLB_KAFKA=$FLB_KAFKA

# Need larger page size
ARG FLB_JEMALLOC_OPTIONS="--with-lg-page=16 --with-lg-quantum=3"
ENV FLB_JEMALLOC_OPTIONS=$FLB_JEMALLOC_OPTIONS

# centos/8 base image
FROM centos:8 AS centos-8-base

# CentOS is now EOL so have to use the vault repos
RUN sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-* && \
    sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*

# Add for the YAML development libraries
RUN sed -i 's/enabled=0/enabled=1/g' /etc/yum.repos.d/CentOS-Linux-PowerTools.repo

ENV CMAKE_HOME="/opt/cmake"
ARG CMAKE_VERSION="3.31.6"
ARG CMAKE_URL="https://github.com/Kitware/CMake/releases/download"

# hadolint ignore=DL3033
RUN yum -y update && \
    yum install -y rpm-build curl ca-certificates gcc gcc-c++ make bash \
    wget unzip systemd-devel wget flex bison \
    postgresql-libs postgresql-devel postgresql-server postgresql \
    cyrus-sasl-lib cyrus-sasl-devel openssl openssl-libs openssl-devel libcurl-devel \
    libyaml-devel zlib-devel \
    tar gzip && \
    yum clean all && \
    mkdir -p "${CMAKE_HOME}" && \
    cmake_download_url="${CMAKE_URL}/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-$(uname -m).tar.gz" && \
    echo "Downloading CMake ${CMAKE_VERSION}: ${cmake_download_url} -> ${CMAKE_HOME}" && \
    curl -jksSL "${cmake_download_url}" | tar -xzf - -C "${CMAKE_HOME}" --strip-components 1

ENV PATH="${CMAKE_HOME}/bin:${PATH}"

ARG FLB_OUT_PGSQL=On
ENV FLB_OUT_PGSQL=$FLB_OUT_PGSQL
ARG FLB_UNICODE_ENCODER=On
ENV FLB_UNICODE_ENCODER=$FLB_UNICODE_ENCODER
ARG FLB_KAFKA=On
ENV FLB_KAFKA=$FLB_KAFKA

# centos/8.arm64v8 base image
FROM arm64v8/centos:8 AS centos-8.arm64v8-base

COPY --from=multiarch-aarch64 /usr/bin/qemu-aarch64-static /usr/bin/qemu-aarch64-static

# CentOS is now EOL so have to use the vault repos
RUN sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-* && \
    sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*

# Add for the YAML development libraries
RUN sed -i 's/enabled=0/enabled=1/g' /etc/yum.repos.d/CentOS-Linux-PowerTools.repo

ENV CMAKE_HOME="/opt/cmake"
ARG CMAKE_VERSION="3.31.6"
ARG CMAKE_URL="https://github.com/Kitware/CMake/releases/download"

# hadolint ignore=DL3033
RUN yum -y update && \
    yum install -y rpm-build curl ca-certificates gcc gcc-c++ make bash \
    wget unzip systemd-devel wget flex bison \
    postgresql-libs postgresql-devel postgresql-server postgresql \
    cyrus-sasl-lib cyrus-sasl-devel openssl openssl-libs openssl-devel libcurl-devel \
    libyaml-devel zlib-devel \
    tar gzip && \
    yum clean all && \
    mkdir -p "${CMAKE_HOME}" && \
    cmake_download_url="${CMAKE_URL}/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-$(uname -m).tar.gz" && \
    echo "Downloading CMake ${CMAKE_VERSION}: ${cmake_download_url} -> ${CMAKE_HOME}" && \
    curl -jksSL "${cmake_download_url}" | tar -xzf - -C "${CMAKE_HOME}" --strip-components 1

ENV PATH="${CMAKE_HOME}/bin:${PATH}"

ARG FLB_OUT_PGSQL=On
ENV FLB_OUT_PGSQL=$FLB_OUT_PGSQL
ARG FLB_UNICODE_ENCODER=On
ENV FLB_UNICODE_ENCODER=$FLB_UNICODE_ENCODER
ARG FLB_KAFKA=On
ENV FLB_KAFKA=$FLB_KAFKA

# Need larger page size
ARG FLB_JEMALLOC_OPTIONS="--with-lg-page=16 --with-lg-quantum=3"
ENV FLB_JEMALLOC_OPTIONS=$FLB_JEMALLOC_OPTIONS

FROM quay.io/centos/centos:stream9 AS centos-9-base

ENV CMAKE_HOME="/opt/cmake"
ARG CMAKE_VERSION="3.31.6"
ARG CMAKE_URL="https://github.com/Kitware/CMake/releases/download"

# Add for the YAML development libraries
# hadolint ignore=DL3033,DL3041
RUN dnf -y install 'dnf-command(config-manager)' && dnf -y config-manager --set-enabled crb && \
    dnf -y install rpm-build ca-certificates gcc gcc-c++ make bash \
    wget unzip systemd-devel wget flex bison \
    postgresql-libs postgresql-devel postgresql-server postgresql \
    cyrus-sasl-lib cyrus-sasl-devel openssl openssl-libs openssl-devel libcurl-devel \
    libyaml-devel zlib-devel \
    tar gzip && \
    dnf clean all && \
    mkdir -p "${CMAKE_HOME}" && \
    cmake_download_url="${CMAKE_URL}/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-$(uname -m).tar.gz" && \
    echo "Downloading CMake ${CMAKE_VERSION}: ${cmake_download_url} -> ${CMAKE_HOME}" && \
    curl -jksSL "${cmake_download_url}" | tar -xzf - -C "${CMAKE_HOME}" --strip-components 1

ENV PATH="${CMAKE_HOME}/bin:${PATH}"

ARG FLB_OUT_PGSQL=On
ENV FLB_OUT_PGSQL=$FLB_OUT_PGSQL

# hadolint ignore=DL3029
FROM --platform=arm64 quay.io/centos/centos:stream9 AS centos-9.arm64v8-base

COPY --from=multiarch-aarch64 /usr/bin/qemu-aarch64-static /usr/bin/qemu-aarch64-static

ENV CMAKE_HOME="/opt/cmake"
ARG CMAKE_VERSION="3.31.6"
ARG CMAKE_URL="https://github.com/Kitware/CMake/releases/download"

# Add for the YAML development libraries
# hadolint ignore=DL3033,DL3041
RUN dnf -y install 'dnf-command(config-manager)' && dnf -y config-manager --set-enabled crb && \
    dnf -y install rpm-build ca-certificates gcc gcc-c++ make bash \
    wget unzip systemd-devel wget flex bison \
    postgresql-libs postgresql-devel postgresql-server postgresql \
    cyrus-sasl-lib cyrus-sasl-devel openssl openssl-libs openssl-devel libcurl-devel \
    libyaml-devel zlib-devel \
    tar gzip && \
    dnf clean all && \
    mkdir -p "${CMAKE_HOME}" && \
    cmake_download_url="${CMAKE_URL}/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-$(uname -m).tar.gz" && \
    echo "Downloading CMake ${CMAKE_VERSION}: ${cmake_download_url} -> ${CMAKE_HOME}" && \
    curl -jksSL "${cmake_download_url}" | tar -xzf - -C "${CMAKE_HOME}" --strip-components 1

ENV PATH="${CMAKE_HOME}/bin:${PATH}"

ARG FLB_OUT_PGSQL=On
ENV FLB_OUT_PGSQL=$FLB_OUT_PGSQL
ARG FLB_UNICODE_ENCODER=On
ENV FLB_UNICODE_ENCODER=$FLB_UNICODE_ENCODER
ARG FLB_KAFKA=On
ENV FLB_KAFKA=$FLB_KAFKA

# Need larger page size
ARG FLB_JEMALLOC_OPTIONS="--with-lg-page=16 --with-lg-quantum=3"
ENV FLB_JEMALLOC_OPTIONS=$FLB_JEMALLOC_OPTIONS

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
    ../

VOLUME [ "/output" ]
CMD [ "/bin/bash", "-c", "make -j 4 && cpack -G RPM && cp *.rpm /output/" ]
