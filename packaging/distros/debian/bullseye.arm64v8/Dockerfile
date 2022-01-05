FROM arm64v8/debian:bullseye-slim as builder
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get -qq update && \
    apt-get install -y -qq curl ca-certificates build-essential \
                           cmake make bash sudo wget unzip dh-make \
                           libsystemd-dev zlib1g-dev flex bison \
                           libssl1.1 libssl-dev libpq-dev postgresql-server-dev-all \
                           libsasl2-2 libsasl2-dev && \
    apt-get install -y -qq --reinstall lsb-base lsb-release

ARG FLB_PREFIX
ARG FLB_VERSION
ARG FLB_SRC

ENV FLB_PREFIX=$FLB_PREFIX
ENV FLB_VERSION=$FLB_VERSION
ENV FLB_SRC=$FLB_SRC

# Source set up
ENV FLB_TARBALL http://github.com/fluent/fluent-bit/archive/$FLB_PREFIX$FLB_VERSION.zip
COPY sources/$FLB_SRC /

# Get source tarball or use local source
WORKDIR /tmp
RUN if [ "x$FLB_SRC" = "x" ] ; then wget -O "/tmp/fluent-bit-${FLB_VERSION}.zip" ${FLB_TARBALL} && unzip "fluent-bit-$FLB_VERSION.zip" ; else tar zxfv "/$FLB_SRC" ; fi

# CMake configuration
WORKDIR /tmp/fluent-bit-$FLB_VERSION/build/
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

# Actual build is not carried out until the container is run
WORKDIR "/tmp/fluent-bit-${FLB_VERSION}/build/"
VOLUME [ "/output" ]
CMD make && cpack -G DEB && cp *.deb /output
