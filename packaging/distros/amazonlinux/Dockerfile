ARG BASE_BUILDER=amazonlinux-2-base
FROM ${BASE_BUILDER} as builder

FROM multiarch/qemu-user-static:x86_64-aarch64 as multiarch-aarch64

# Shared layer: Build CMake 3.20 with OpenSSL 1.1 headers/libs
FROM amazonlinux:2 as cmake-3.20-installer
WORKDIR /tmp

# hadolint ignore=DL3033
RUN yum install -y gcc gcc-c++ make curl tar gzip \
    openssl11 openssl11-devel && \
    ln -sf /usr/include/openssl11 /usr/include/openssl && \
    curl -LO https://github.com/Kitware/CMake/releases/download/v3.20.0/cmake-3.20.0.tar.gz && \
    tar -xzf cmake-3.20.0.tar.gz && \
    cd cmake-3.20.0 && \
    ./bootstrap -- -DCMAKE_USE_OPENSSL=ON && \
    make -j$(nproc) && \
    make install && \
    cmake --version

# Amazon Linux 2 x86_64
FROM amazonlinux:2 as amazonlinux-2-base
COPY --from=cmake-3.20-installer /usr/local /usr/local

# hadolint ignore=DL3033
RUN yum -y update && \
    yum install -y rpm-build curl ca-certificates gcc gcc-c++ make bash \
    wget unzip systemd-devel flex bison \
    cyrus-sasl-lib cyrus-sasl-devel openssl11 openssl11-devel \
    postgresql-devel postgresql-libs \
    libyaml-devel zlib-devel libcurl-devel && \
    ln -sf /usr/include/openssl11 /usr/include/openssl && \
    echo "/usr/lib64/openssl11" > /etc/ld.so.conf.d/openssl11.conf && \
    ldconfig && \
    yum clean all

# Amazon Linux 2 ARM64
FROM arm64v8/amazonlinux:2 as amazonlinux-2.arm64v8-base
COPY --from=multiarch-aarch64 /usr/bin/qemu-aarch64-static /usr/bin/qemu-aarch64-static
COPY --from=cmake-3.20-installer /usr/local /usr/local
RUN yum -y update && \
    yum install -y rpm-build ca-certificates gcc gcc-c++ make bash \
    wget unzip systemd-devel flex bison \
    cyrus-sasl-lib cyrus-sasl-devel openssl11 openssl11-devel \
    postgresql-devel postgresql-libs \
    libyaml-devel zlib-devel libcurl-devel && \
    ln -sf /usr/include/openssl11 /usr/include/openssl && \
    echo "/usr/lib64/openssl11" > /etc/ld.so.conf.d/openssl11.conf && \
    ldconfig && \
    yum clean all

# Amazon Linux 2023 is not used with OpenSSL 1.1 (for now) — skip to avoid mismatches

# Fluent Bit Build Phase
FROM $BASE_BUILDER as builder

ARG FLB_NIGHTLY_BUILD
ENV FLB_NIGHTLY_BUILD=$FLB_NIGHTLY_BUILD

WORKDIR /tmp/fluent-bit/
COPY . ./

WORKDIR /tmp/fluent-bit/build/
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
CMD [ "/bin/bash", "-c", "make -j 4 && cpack -G RPM && cp *.rpm /output/" ]
