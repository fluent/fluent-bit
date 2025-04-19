ARG BASE_BUILDER=amazonlinux-2-base
FROM multiarch/qemu-user-static:x86_64-aarch64 AS multiarch-aarch64

####################################################
## Amazon Linux 2 x86_64: amazonlinux-2.base
####################################################

# CMake 3.20 Amazon Linux 2
FROM amazonlinux:2 AS cmake-3.20-installer-al2
WORKDIR /tmp
RUN yum install -y gcc gcc-c++ make curl tar gzip openssl11 openssl11-devel && \
    curl -LO https://github.com/Kitware/CMake/releases/download/v3.20.0/cmake-3.20.0.tar.gz && \
    tar -xzf cmake-3.20.0.tar.gz && cd cmake-3.20.0 && \
    ./bootstrap -- -DCMAKE_USE_OPENSSL=OFF && \
    make -j 4 && make install && cmake --version

# Amazon Linux 2 x86_64 base
FROM amazonlinux:2 AS amazonlinux-2-base
COPY --from=cmake-3.20-installer-al2 /usr/local /usr/local
RUN yum -y update && yum install -y rpm-build curl gcc gcc-c++ make bash wget unzip \
    systemd-devel flex bison cyrus-sasl-devel openssl11-devel postgresql-devel \
    libyaml-devel zlib-devel libcurl-devel


#######################################################
## Amazon Linux 2 ARM64: amazonlinux-2.arm64v8-base
#######################################################

# CMake 3.20 Amazon Linux 2 ARM64
FROM --platform=linux/arm64 arm64v8/amazonlinux:2 AS cmake-3.20-installer-al2-arm64
WORKDIR /tmp
COPY --from=multiarch-aarch64 /usr/bin/qemu-aarch64-static /usr/bin/
RUN yum install -y tar gzip openssl11 openssl11-devel && \
    curl -LO https://github.com/Kitware/CMake/releases/download/v3.20.0/cmake-3.20.0-linux-aarch64.tar.gz && \
    tar -xzf cmake-3.20.0-linux-aarch64.tar.gz && \
    cp -r cmake-3.20.0-linux-aarch64/* /usr/local/ && \
    cmake --version

# Amazon Linux 2 ARM64 base
FROM --platform=linux/arm64 arm64v8/amazonlinux:2 AS amazonlinux-2.arm64v8-base
COPY --from=multiarch-aarch64 /usr/bin/qemu-aarch64-static /usr/bin/qemu-aarch64-static
COPY --from=cmake-3.20-installer-al2-arm64 /usr/local /usr/local
RUN yum -y update && yum install -y rpm-build gcc gcc-c++ make bash wget unzip \
    systemd-devel flex bison cyrus-sasl-devel openssl11-devel postgresql-devel \
    libyaml-devel zlib-devel glibc-devel

#######################################################
## Amazon Linux 2023 x86_64: amazonlinux-2023.base
#######################################################

# CMake 3.20 Amazon Linux 2023 x86_64
FROM amazonlinux:2023 AS cmake-3.20-installer-al2023-x86
WORKDIR /tmp
RUN yum -y update && \
    yum install -y gcc gcc-c++ make tar gzip bzip2 xz ncurses-devel python3 && \
    curl -LO https://github.com/Kitware/CMake/releases/download/v3.20.0/cmake-3.20.0.tar.gz && \
    tar -xzf cmake-3.20.0.tar.gz && cd cmake-3.20.0 && \
    ./bootstrap -- -DCMAKE_USE_OPENSSL=OFF && \
    make -j 4 && make install && cmake --version

# Amazon Linux 2023 x86_64 base
FROM amazonlinux:2023 AS amazonlinux-2023-base
COPY --from=cmake-3.20-installer-al2023-x86 /usr/local /usr/local
RUN yum -y update && \
    yum install -y rpm-build gcc gcc-c++ make bash wget unzip \
    systemd-devel flex bison cyrus-sasl-devel openssl-devel postgresql-devel \
    libyaml-devel zlib-devel && yum clean all

###########################################################
## Amazon Linux 2023 ARM64: amazonlinux-2023.arm64v8-base
###########################################################

# CMake 3.20 Amazon Linux 2023 ARM64
FROM --platform=linux/arm64 arm64v8/amazonlinux:2023 AS cmake-3.20-installer-al2023-arm64
WORKDIR /tmp
RUN yum -y update && yum install -y gcc gcc-c++ make tar gzip bzip2 xz ncurses-devel python3 && \
    curl -LO https://github.com/Kitware/CMake/releases/download/v3.20.0/cmake-3.20.0.tar.gz && \
    tar -xzf cmake-3.20.0.tar.gz && cd cmake-3.20.0 && \
    ./bootstrap -- -DCMAKE_USE_OPENSSL=OFF && \
    make -j 4 && make install && cmake --version

# Amazon Linux 2023 ARM64 base
FROM --platform=linux/arm64 arm64v8/amazonlinux:2023 AS amazonlinux-2023.arm64v8-base
COPY --from=multiarch-aarch64 /usr/bin/qemu-aarch64-static /usr/bin/qemu-aarch64-static
COPY --from=cmake-3.20-installer-al2023-arm64 /usr/local /usr/local
RUN yum -y update && yum install -y rpm-build gcc gcc-c++ make bash wget unzip \
    systemd-devel flex bison cyrus-sasl-devel openssl-devel postgresql-devel \
    libyaml-devel zlib-devel && yum clean all

# Common build for all distributions now
# hadolint ignore=DL3006
FROM $BASE_BUILDER as builder

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
ARG FLB_RELEASE=On
ARG FLB_TRACE=On
ARG FLB_SQLDB=On
ARG FLB_HTTP_SERVER=On
ARG FLB_OUT_KAFKA=On
ARG FLB_OUT_PGSQL=On
ARG FLB_JEMALLOC=On
ARG FLB_CHUNK_TRACE=On

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
    ../

VOLUME [ "/output" ]
CMD [ "/bin/bash", "-c", "make -j 16 && cpack -G RPM && cp *.rpm /output/" ]


# target to validate all the base images
FROM scratch as validate-all
COPY --from=amazonlinux-2.arm64v8-base /etc/os-release /dev/null
COPY --from=amazonlinux-2-base /etc/os-release /dev/null
COPY --from=amazonlinux-2023-base /etc/os-release /dev/null
COPY --from=amazonlinux-2023.arm64v8-base /etc/os-release /dev/null
