FROM registry.access.redhat.com/ubi8/ubi:8.5 as builder
# hadolint ignore=DL3041
RUN dnf update -y && dnf install -y cmake3 curl diffutils gcc gcc-c++ libpq-devel m4 make openssl-devel systemd-devel tar unzip && dnf clean all

# Provide the dependencies for record accessor built from source
ARG BISON_VER=3.7
ARG BISON_URL=http://ftp.gnu.org/gnu/bison
ARG FLEX_VER=2.6.4
ARG FLEX_URL=https://github.com/westes/flex/files/981163
ADD ${BISON_URL}/bison-${BISON_VER}.tar.gz /bison/
ADD ${FLEX_URL}/flex-${FLEX_VER}.tar.gz /flex/
RUN tar -xzvf /bison/bison-${BISON_VER}.tar.gz -C /bison/ && tar -xzvf /flex/flex-${FLEX_VER}.tar.gz -C /flex/

# Flex needs Bison so do first
WORKDIR /bison/bison-${BISON_VER}/
RUN ./configure && make && make install
WORKDIR /flex/flex-${FLEX_VER}/
RUN ./configure && make && make install

# Fluent Bit version
ENV FLB_MAJOR 1
ENV FLB_MINOR 8
ENV FLB_PATCH 11
ENV FLB_VERSION 1.8.11

# Note we use the upstream source directly here
ARG FLB_TARBALL=https://github.com/fluent/fluent-bit/archive/v$FLB_VERSION.tar.gz
ENV FLB_SOURCE $FLB_TARBALL
RUN mkdir -p /fluent-bit/bin /fluent-bit/etc /fluent-bit/log /tmp/fluent-bit-master/

RUN curl -L -o "/tmp/fluent-bit.tar.gz" ${FLB_SOURCE} \
    && mkdir -p /tmp/fluent-bit \
    && tar zxfv /tmp/fluent-bit.tar.gz -C /tmp/fluent-bit --strip-components=1 \
    && rm -rf /tmp/fluent-bit/build/*

WORKDIR /tmp/fluent-bit/build/
# IPv6 tests dependent on docker configuration and support so disable
RUN sed -i '/{ "ipv6_client_server", test_ipv6_client_server},/d' ../tests/internal/network.c
# TODO check if we need to disable the TD output plugin & Process input plugin as unit test fails
RUN cmake -DFLB_RELEASE=On \
          -DFLB_TRACE=Off \
          -DFLB_JEMALLOC=On \
          -DFLB_TLS=On \
          -DFLB_SHARED_LIB=Off \
          -DFLB_EXAMPLES=Off \
          -DFLB_HTTP_SERVER=On \
          -DFLB_IN_SYSTEMD=On \
          -DFLB_OUT_KAFKA=On \
          -DFLB_OUT_PGSQL=On \
          -DFLB_TESTS_INTERNAL=On \
          -DFLB_TESTS_RUNTIME=On \
          ..

RUN make -j $(getconf _NPROCESSORS_ONLN)
RUN install bin/fluent-bit /fluent-bit/bin/

# Configuration files
RUN cp -f /tmp/fluent-bit/conf/fluent-bit.conf \
    /tmp/fluent-bit/conf/parsers.conf \
    /tmp/fluent-bit/conf/parsers_ambassador.conf \
    /tmp/fluent-bit/conf/parsers_java.conf \
    /tmp/fluent-bit/conf/parsers_extra.conf \
    /tmp/fluent-bit/conf/parsers_openstack.conf \
    /tmp/fluent-bit/conf/parsers_cinder.conf \
    /tmp/fluent-bit/conf/plugins.conf \
    /fluent-bit/etc/

FROM builder as test
WORKDIR /tmp/fluent-bit/build/
RUN make test

FROM registry.access.redhat.com/ubi8/ubi-minimal:8.5 as production
RUN microdnf update && microdnf install -y openssl libpq systemd-libs shadow-utils && microdnf clean all

ARG FLUENT_BIT_VER=1.8.11
ENV FLUENTBIT_VERSION=$FLUENT_BIT_VER

ARG PROD_VERSION
ENV PROD_VERSION=$PROD_VERSION

# https://redhat-connect.gitbook.io/partner-guide-for-red-hat-openshift-and-container/program-on-boarding/technical-prerequisites#dockerfile-requirements
# The following labels must exist: name, maintainer, vendor, version, release, summary & description.
LABEL name="calyptia/fluent-bit" \
      vendor="calyptia" \
      maintainer="Patrick Stephens <pat@calyptia.com>" \
      version="ubi8-${FLUENT_BIT_VER}" \
      release="${FLUENT_BIT_VER}" \
      summary="Calyptia Fluent Bit ${PROD_VERSION}" \
      description="Calyptia Fluent Bit ${PROD_VERSION} based on upstream Fluent Bit"

EXPOSE 2020

ENTRYPOINT [ "/fluent-bit/bin/fluent-bit" ]
CMD [ "/fluent-bit/bin/fluent-bit", "-c", "/fluent-bit/etc/fluent-bit.conf" ]

# Ensure we add licensing and help information for certification requirements
COPY licenses/* /licenses/
COPY README.md /help.1

COPY --from=builder /fluent-bit /fluent-bit

# Run as non-root user - pick a random one
RUN useradd -u 9876 -m -s /bin/false fluent-bit
USER 9876
