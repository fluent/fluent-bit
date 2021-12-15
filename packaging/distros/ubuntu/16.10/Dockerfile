FROM ubuntu:16.10
ENV DEBIAN_FRONTEND noninteractive

ARG FLB_PREFIX
ARG FLB_VERSION

ENV FLB_TARBALL http://github.com/fluent/fluent-bit/archive/$FLB_PREFIX$FLB_VERSION.zip

RUN apt-get -qq update && \
    apt-get install -y -qq curl ca-certificates build-essential cmake make bash sudo wget unzip nano vim valgrind dh-make && \
    apt-get install -y -qq --reinstall lsb-base lsb-release && \
    wget -O "/tmp/fluent-bit-${FLB_VERSION}.zip" ${FLB_TARBALL} && \
    cd /tmp && unzip "fluent-bit-$FLB_VERSION.zip"

CMD cd "/tmp/fluent-bit-${FLB_VERSION}/" && ./debian.sh && cp ../*.deb /output
