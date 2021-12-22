# Use deprecated image as it pins dependencies to working ones.
# Current balenalib/rpi-raspbian:buster triggers cmake failures for GNU C compiler detection
FROM resin/rpi-raspbian:buster
ENV DEBIAN_FRONTEND noninteractive

# Builder image so dependencies can be latest, recommended and no need to wipe
# hadolint ignore=DL3008,DL3015,DL3009
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

ENV FLB_TARBALL http://github.com/fluent/fluent-bit/archive/$FLB_PREFIX$FLB_VERSION.zip
COPY sources/$FLB_SRC /

RUN cd /tmp && \
    if [ "x$FLB_SRC" = "x" ] ; then wget -O "/tmp/fluent-bit-${FLB_VERSION}.zip" ${FLB_TARBALL} && unzip "fluent-bit-$FLB_VERSION.zip" ; else tar zxfv "/$FLB_SRC" ; fi && \
    cd "fluent-bit-$FLB_VERSION/build/" && \
    export CFLAGS="$CFLAGS -std=gnu99" && \
    cmake  -DCMAKE_INSTALL_PREFIX=/opt/td-agent-bit/ -DCMAKE_INSTALL_SYSCONFDIR=/etc/ \
           -DFLB_RELEASE=On -DFLB_TRACE=On -DFLB_TD=On \
           -DFLB_SQLDB=On -DFLB_HTTP_SERVER=On \
           -DFLB_OUT_KAFKA=On \
           -DFLB_OUT_PGSQL=On ../

CMD cd "/tmp/fluent-bit-${FLB_VERSION}/build/" && make -j 2 && cpack -G DEB && cp *.deb /output
