# Special Dockerfile to build all Ubuntu targets, the only difference is
# the packages in the base image.
# Set this to the base image to use.
ARG BASE_BUILDER
# Use buildkit to skip unused base images: DOCKER_BUILDKIT=1

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

FROM ubuntu:16.04 as ubuntu-16.04-base
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get -qq update && \
    apt-get install -y -qq curl ca-certificates build-essential libsystemd-dev cmake \
    make bash sudo wget unzip nano vim valgrind dh-make flex bison \
    libpq-dev postgresql-server-dev-all software-properties-common \
    apt-transport-https ca-certificates && \
    wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | \
         gpg --dearmor - | sudo tee /etc/apt/trusted.gpg.d/kitware.gpg >/dev/null && \
         apt-add-repository 'deb https://apt.kitware.com/ubuntu/ xenial main' && \
    apt-get -qq update && \
    apt-get install -y -qq --reinstall lsb-base lsb-release cmake

FROM ubuntu:18.04 as ubuntu-18.04-base
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get -qq update && \
    apt-get install -y -qq curl ca-certificates build-essential libsystemd-dev \
    cmake make bash sudo wget unzip nano vim valgrind dh-make flex bison \
    libpq-dev postgresql-server-dev-all \
    libsasl2-2 libsasl2-dev openssl libssl-dev libssl1.1 && \
    apt-get install -y -qq --reinstall lsb-base lsb-release

FROM arm64v8/ubuntu:18.04 as ubuntu-18.04.arm64v8-base
ENV DEBIAN_FRONTEND noninteractive

COPY --from=multiarch/qemu-user-static:x86_64-aarch64 /usr/bin/qemu-aarch64-static /usr/bin/qemu-aarch64-static

RUN apt-get -qq update && \
    apt-get install -y -qq curl ca-certificates build-essential libsystemd-dev \
    cmake make bash sudo wget unzip nano vim valgrind dh-make flex bison \
    libpq-dev postgresql-server-dev-all \
    libsasl2-2 libsasl2-dev openssl libssl-dev libssl1.1 && \
    apt-get install -y -qq --reinstall lsb-base lsb-release

FROM ubuntu:20.04 as ubuntu-20.04-base
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get -qq update && \
    apt-get install -y -qq curl ca-certificates build-essential libsystemd-dev \
    cmake make bash sudo wget unzip nano vim valgrind dh-make flex bison \
    libpq-dev postgresql-server-dev-all \
    libsasl2-2 libsasl2-dev openssl libssl-dev libssl1.1 && \
    apt-get install -y -qq --reinstall lsb-base lsb-release

FROM arm64v8/ubuntu:20.04 as ubuntu-20.04.arm64v8-base
ENV DEBIAN_FRONTEND noninteractive

COPY --from=multiarch/qemu-user-static:x86_64-aarch64 /usr/bin/qemu-aarch64-static /usr/bin/qemu-aarch64-static

RUN apt-get -qq update && \
    apt-get install -y -qq curl ca-certificates build-essential libsystemd-dev \
    cmake make bash sudo wget unzip nano vim valgrind dh-make flex bison \
    libpq-dev postgresql-server-dev-all \
    libsasl2-2 libsasl2-dev openssl libssl-dev libssl1.1 && \
    apt-get install -y -qq --reinstall lsb-base lsb-release

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
RUN if [ "x$FLB_SRC" = "x" ] ; then wget -O "/tmp/fluent-bit-${FLB_VERSION}.zip" ${FLB_TARBALL} && unzip "fluent-bit-$FLB_VERSION.zip" ; else tar zxfv "/$FLB_SRC" ; fi

WORKDIR /tmp/"fluent-bit-$FLB_VERSION/build/"
ENV CFLAGS=$CFLAGS
RUN cmake -DCMAKE_INSTALL_PREFIX=$CMAKE_INSTALL_PREFIX \
          -DCMAKE_INSTALL_SYSCONFDIR=$CMAKE_INSTALL_SYSCONFDIR \
          -DFLB_RELEASE=$FLB_RELEASE \
          -DFLB_TRACE=$FLB_TRACE \
          -DFLB_TD=$FLB_TD \
          -DFLB_SQLDB=$FLB_SQLDB \
          -DFLB_HTTP_SERVER=$FLB_HTTP_SERVER \
          -DFLB_OUT_KAFKA=$FLB_OUT_KAFKA \
          -DFLB_OUT_PGSQL=$FLB_OUT_PGSQL \
          ../

WORKDIR "/tmp/fluent-bit-${FLB_VERSION}/build/"
VOLUME [ "/output" ]
CMD make -j 4 && cpack -G DEB && cp *.deb /output
