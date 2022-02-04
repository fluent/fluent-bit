# Special Dockerfile to build all Debian targets, the only difference is
# the packages in the base image.
# Set this to the base image to use in each case, so if we want to build for debian/bullseye
# we would set BASE_BUILDER=debian-bullseye-base.
ARG BASE_BUILDER
# Lookup the name to use below but should follow the '<distro>-base' convention with slashes replaced.
# Use buildkit to skip unused base images: DOCKER_BUILDKIT=1

# Multiarch support
FROM multiarch/qemu-user-static:x86_64-aarch64 as multiarch-aarch64

# debian/stretch base image
FROM debian:stretch-slim as debian-stretch-base
ENV DEBIAN_FRONTEND noninteractive

# hadolint ignore=DL3008,DL3015
RUN apt-get -qq update && \
    apt-get install -y -qq curl ca-certificates build-essential \
                           cmake make bash sudo wget unzip dh-make \
                           libsystemd-dev zlib1g-dev flex bison \
                           libssl1.1 libssl-dev libpq-dev postgresql-server-dev-all \
                           libsasl2-2 libsasl2-dev && \
    apt-get install -y -qq --reinstall lsb-base lsb-release

# debian/stretch.arm64v8 base image
FROM arm64v8/debian:stretch as debian-stretch.arm64v8-base
ENV DEBIAN_FRONTEND noninteractive

COPY --from=multiarch-aarch64 /usr/bin/qemu-aarch64-static /usr/bin/qemu-aarch64-static

# hadolint ignore=DL3008,DL3015
RUN apt-get -qq update && \
    apt-get install -y -qq curl ca-certificates build-essential \
                           cmake make bash sudo wget unzip dh-make \
                           libsystemd-dev zlib1g-dev flex bison \
                           libssl1.1 libssl-dev libpq-dev postgresql-server-dev-all \
                           libsasl2-2 libsasl2-dev && \
    apt-get install -y -qq --reinstall lsb-base lsb-release

# debian/buster base image
FROM debian:buster-slim as debian-buster-base
ENV DEBIAN_FRONTEND noninteractive

# hadolint ignore=DL3008,DL3015
RUN apt-get -qq update && \
    apt-get install -y -qq curl ca-certificates build-essential \
                           cmake make bash sudo wget unzip dh-make \
                           libsystemd-dev zlib1g-dev flex bison \
                           libssl1.1 libssl-dev libpq-dev postgresql-server-dev-all \
                           libsasl2-2 libsasl2-dev && \
    apt-get install -y -qq --reinstall lsb-base lsb-release

# debian/buster.arm64v8 base image
FROM arm64v8/debian:buster-slim as debian-buster.arm64v8-base
ENV DEBIAN_FRONTEND noninteractive

COPY --from=multiarch-aarch64 /usr/bin/qemu-aarch64-static /usr/bin/qemu-aarch64-static

# hadolint ignore=DL3008,DL3015
RUN apt-get -qq update && \
    apt-get install -y -qq curl ca-certificates build-essential \
                           cmake make bash sudo wget unzip dh-make \
                           libsystemd-dev zlib1g-dev flex bison \
                           libssl1.1 libssl-dev libpq-dev postgresql-server-dev-all \
                           libsasl2-2 libsasl2-dev && \
    apt-get install -y -qq --reinstall lsb-base lsb-release

# debian/bullseye base image
FROM debian:bullseye-slim as debian-bullseye-base
ENV DEBIAN_FRONTEND noninteractive

# hadolint ignore=DL3008,DL3015
RUN apt-get -qq update && \
    apt-get install -y -qq curl ca-certificates build-essential \
                           cmake make bash sudo wget unzip dh-make \
                           libsystemd-dev zlib1g-dev flex bison \
                           libssl1.1 libssl-dev libpq-dev postgresql-server-dev-all \
                           libsasl2-2 libsasl2-dev && \
    apt-get install -y -qq --reinstall lsb-base lsb-release

# debian/bullseye.arm64v8 base image
FROM arm64v8/debian:bullseye-slim as debian-bullseye.arm64v8-base
ENV DEBIAN_FRONTEND noninteractive

COPY --from=multiarch-aarch64 /usr/bin/qemu-aarch64-static /usr/bin/qemu-aarch64-static

# hadolint ignore=DL3008,DL3015
RUN apt-get -qq update && \
    apt-get install -y -qq curl ca-certificates build-essential \
                           cmake make bash sudo wget unzip dh-make \
                           libsystemd-dev zlib1g-dev flex bison \
                           libssl1.1 libssl-dev libpq-dev postgresql-server-dev-all \
                           libsasl2-2 libsasl2-dev && \
    apt-get install -y -qq --reinstall lsb-base lsb-release

# Common build for all distributions now
# hadolint ignore=DL3006
FROM $BASE_BUILDER as builder

ARG FLB_PREFIX
ARG FLB_VERSION
ARG FLB_SRC

ENV FLB_PREFIX=$FLB_PREFIX
ENV FLB_VERSION=$FLB_VERSION
ENV FLB_SRC=$FLB_SRC

ENV FLB_TARBALL http://github.com/fluent/fluent-bit/archive/$FLB_PREFIX$FLB_VERSION.zip
COPY sources/$FLB_SRC /

WORKDIR /tmp
RUN if [ -z "$FLB_SRC" ] ; then wget -q -O "/tmp/fluent-bit-${FLB_VERSION}.zip" ${FLB_TARBALL} && unzip "fluent-bit-$FLB_VERSION.zip" ; else tar zxfv "/$FLB_SRC" ; fi

# CMake configuration variables
ARG CFLAGS="-std=gnu99"
ARG CMAKE_INSTALL_PREFIX=/opt/td-agent-bit/
ARG CMAKE_INSTALL_SYSCONFDIR=/etc/
ARG FLB_TD=On
ARG FLB_RELEASE=On
ARG FLB_TRACE=On
ARG FLB_SQLDB=On
ARG FLB_HTTP_SERVER=On
ARG FLB_OUT_KAFKA=On
ARG FLB_OUT_PGSQL=On

WORKDIR /tmp/fluent-bit-$FLB_VERSION/build/
ENV CFLAGS=$CFLAGS
RUN cmake -DCMAKE_INSTALL_PREFIX="$CMAKE_INSTALL_PREFIX" \
          -DCMAKE_INSTALL_SYSCONFDIR="$CMAKE_INSTALL_SYSCONFDIR" \
          -DFLB_RELEASE="$FLB_RELEASE" \
          -DFLB_TRACE="$FLB_TRACE" \
          -DFLB_TD="$FLB_TD" \
          -DFLB_SQLDB="$FLB_SQLDB" \
          -DFLB_HTTP_SERVER="$FLB_HTTP_SERVER" \
          -DFLB_OUT_KAFKA="$FLB_OUT_KAFKA" \
          -DFLB_OUT_PGSQL="$FLB_OUT_PGSQL" \
          ../

VOLUME [ "/output" ]
CMD [ "/bin/bash", "-c", "make -j 4 && cpack -G DEB && cp *.deb /output/" ]
