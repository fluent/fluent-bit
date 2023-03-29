# Special Dockerfile to build all CentOS targets, the only difference is
# the packages in the base image.
# Set this to the base image to use in each case, so if we want to build for centos/7
# we would set BASE_BUILDER=centos-7-base.
ARG BASE_BUILDER
# Lookup the name to use below but should follow the '<distro>-base' convention with slashes replaced.
# Use buildkit to skip unused base images: DOCKER_BUILDKIT=1

# Multiarch support
FROM multiarch/qemu-user-static:x86_64-aarch64 as multiarch-aarch64

# centos/7 base image
FROM centos:7 as centos-7-base

# hadolint ignore=DL3033
RUN yum -y update && \
    yum install -y rpm-build curl ca-certificates gcc gcc-c++ cmake make bash \
    wget unzip systemd-devel wget flex bison \
    cyrus-sasl-lib cyrus-sasl-devel openssl openss-libs openssl-devel \
    postgresql-libs postgresql-devel postgresql-server postgresql libyaml-devel && \
    wget -q http://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm && \
    rpm -ivh epel-release-latest-7.noarch.rpm && \
    yum install -y cmake3 && \
    yum clean all

ARG FLB_OUT_PGSQL=On
ENV FLB_OUT_PGSQL=$FLB_OUT_PGSQL

# centos/7.arm64v8 base image
FROM arm64v8/centos:7 as centos-7.arm64v8-base

COPY --from=multiarch-aarch64 /usr/bin/qemu-aarch64-static /usr/bin/qemu-aarch64-static

# hadolint ignore=DL3033
RUN yum -y update && \
    yum install -y rpm-build curl ca-certificates gcc gcc-c++ cmake make bash \
    wget unzip systemd-devel wget flex bison \
    cyrus-sasl-lib cyrus-sasl-devel openssl openss-libs openssl-devel \
    postgresql-libs postgresql-devel postgresql-server postgresql libyaml-devel && \
    wget -q http://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm && \
    rpm -ivh epel-release-latest-7.noarch.rpm && \
    yum install -y cmake3 && \
    yum clean all

# There are no postgresql libraries available for this target
ARG FLB_OUT_PGSQL=Off
ENV FLB_OUT_PGSQL=$FLB_OUT_PGSQL

# Need larger page size
ARG FLB_JEMALLOC_OPTIONS="--with-lg-page=16 --with-lg-quantum=3"
ENV FLB_JEMALLOC_OPTIONS=$FLB_JEMALLOC_OPTIONS

# centos/8 base image
FROM centos:8 as centos-8-base

# CentOS is now EOL so have to use the vault repos
RUN sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-* && \
    sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*

# Add for the YAML development libraries
RUN sed -i 's/enabled=0/enabled=1/g' /etc/yum.repos.d/CentOS-Linux-PowerTools.repo

# hadolint ignore=DL3033
RUN yum -y update && \
    yum install -y rpm-build curl ca-certificates gcc gcc-c++ cmake make bash \
    wget unzip systemd-devel wget flex bison \
    postgresql-libs postgresql-devel postgresql-server postgresql \
    cyrus-sasl-lib cyrus-sasl-devel openssl openssl-libs openssl-devel \
    libyaml-devel zlib-devel && \
    yum clean all

ARG FLB_OUT_PGSQL=On
ENV FLB_OUT_PGSQL=$FLB_OUT_PGSQL

# centos/8.arm64v8 base image
FROM arm64v8/centos:8 as centos-8.arm64v8-base

COPY --from=multiarch-aarch64 /usr/bin/qemu-aarch64-static /usr/bin/qemu-aarch64-static

# CentOS is now EOL so have to use the vault repos
RUN sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-* && \
    sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*

# Add for the YAML development libraries
RUN sed -i 's/enabled=0/enabled=1/g' /etc/yum.repos.d/CentOS-Linux-PowerTools.repo

# hadolint ignore=DL3033
RUN yum -y update && \
    yum install -y rpm-build curl ca-certificates gcc gcc-c++ cmake make bash \
    wget unzip systemd-devel wget flex bison \
    postgresql-libs postgresql-devel postgresql-server postgresql \
    cyrus-sasl-lib cyrus-sasl-devel openssl openssl-libs openssl-devel \
    libyaml-devel zlib-devel && \
    yum clean all

ARG FLB_OUT_PGSQL=On
ENV FLB_OUT_PGSQL=$FLB_OUT_PGSQL

# Need larger page size
ARG FLB_JEMALLOC_OPTIONS="--with-lg-page=16 --with-lg-quantum=3"
ENV FLB_JEMALLOC_OPTIONS=$FLB_JEMALLOC_OPTIONS

FROM quay.io/centos/centos:stream9 as centos-9-base

# Add for the YAML development libraries
# hadolint ignore=DL3033,DL3041
RUN dnf -y install 'dnf-command(config-manager)' && dnf -y config-manager --set-enabled crb && \
    dnf -y install rpm-build ca-certificates gcc gcc-c++ cmake make bash \
    wget unzip systemd-devel wget flex bison \
    postgresql-libs postgresql-devel postgresql-server postgresql \
    cyrus-sasl-lib cyrus-sasl-devel openssl openssl-libs openssl-devel \
    libyaml-devel zlib-devel && \
    dnf clean all

ARG FLB_OUT_PGSQL=On
ENV FLB_OUT_PGSQL=$FLB_OUT_PGSQL

# hadolint ignore=DL3029
FROM --platform=arm64 quay.io/centos/centos:stream9 as centos-9.arm64v8-base

COPY --from=multiarch-aarch64 /usr/bin/qemu-aarch64-static /usr/bin/qemu-aarch64-static

# Add for the YAML development libraries
# hadolint ignore=DL3033,DL3041
RUN dnf -y install 'dnf-command(config-manager)' && dnf -y config-manager --set-enabled crb && \
    dnf -y install rpm-build ca-certificates gcc gcc-c++ cmake make bash \
    wget unzip systemd-devel wget flex bison \
    postgresql-libs postgresql-devel postgresql-server postgresql \
    cyrus-sasl-lib cyrus-sasl-devel openssl openssl-libs openssl-devel  \
    libyaml-devel zlib-devel && \
    dnf clean all

ARG FLB_OUT_PGSQL=On
ENV FLB_OUT_PGSQL=$FLB_OUT_PGSQL

# Need larger page size
ARG FLB_JEMALLOC_OPTIONS="--with-lg-page=16 --with-lg-quantum=3"
ENV FLB_JEMALLOC_OPTIONS=$FLB_JEMALLOC_OPTIONS

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
ARG FLB_JEMALLOC=On
ARG FLB_CHUNK_TRACE=On

# cmake3 exists in every image - cmake references the older cmake2 in centos 7
RUN cmake3 -DCMAKE_INSTALL_PREFIX="$CMAKE_INSTALL_PREFIX" \
    -DCMAKE_INSTALL_SYSCONFDIR="$CMAKE_INSTALL_SYSCONFDIR" \
    -DFLB_RELEASE="$FLB_RELEASE" \
    -DFLB_TRACE="$FLB_TRACE" \
    -DFLB_SQLDB="$FLB_SQLDB" \
    -DFLB_HTTP_SERVER="$FLB_HTTP_SERVER" \
    -DFLB_OUT_KAFKA="$FLB_OUT_KAFKA" \
    -DFLB_OUT_PGSQL="$FLB_OUT_PGSQL" \
    -DFLB_NIGHTLY_BUILD="$FLB_NIGHTLY_BUILD" \
    -DFLB_JEMALLOC_OPTIONS="$FLB_JEMALLOC_OPTIONS" \
    -DFLB_JEMALLOC="${FLB_JEMALLOC}" \
    -DFLB_CHUNK_TRACE="${FLB_CHUNK_TRACE}" \
    ../

VOLUME [ "/output" ]
CMD [ "/bin/bash", "-c", "make -j 4 && cpack3 -G RPM && cp *.rpm /output/" ]
