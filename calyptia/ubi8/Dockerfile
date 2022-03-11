ARG FLUENT_BIT_VER=1.9.0

FROM registry.access.redhat.com/ubi8/ubi:8.5 as builder
# hadolint ignore=DL3041
RUN dnf update -y && dnf install -y cmake3 curl diffutils gcc gcc-c++ git libpq-devel m4 make openssl-devel systemd-devel tar unzip && dnf clean all

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
ENV FLUENTBIT_VERSION=$FLUENT_BIT_VER

# Note we use the upstream source directly here
WORKDIR /source
RUN git clone -b "$FLUENT_BIT_VER" https://github.com/fluent/fluent-bit.git

# Copy any local source files as needed
COPY calyptia/ubi8/patches/ /source/fluent-bit/

WORKDIR /source/fluent-bit/build/
# IPv6 tests dependent on docker configuration and support so disable
RUN sed -i '/{ "ipv6_client_server", test_ipv6_client_server},/d' ../tests/internal/network.c
# Separate layers now for configure and build to allow local caching
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
# Build
RUN make -j "$(getconf _NPROCESSORS_ONLN)"
# Install and create all necessary directories
RUN mkdir -p /fluent-bit/bin /fluent-bit/etc /fluent-bit/log && \
    install bin/fluent-bit /fluent-bit/bin/

WORKDIR /source/fluent-bit/
# Configuration files
RUN cp -f conf/fluent-bit.conf \
    conf/parsers.conf \
    conf/parsers_ambassador.conf \
    conf/parsers_java.conf \
    conf/parsers_extra.conf \
    conf/parsers_openstack.conf \
    conf/parsers_cinder.conf \
    conf/plugins.conf \
    /fluent-bit/etc/

# Primarily to capture test output rather than verify
FROM builder as test
WORKDIR /source/build/
RUN make test || true

# The release image now
FROM registry.access.redhat.com/ubi8/ubi-minimal:8.5 as production
RUN microdnf update && microdnf install -y openssl libpq systemd-libs shadow-utils && microdnf clean all

ENV FLUENTBIT_VERSION=$FLUENT_BIT_VER

# https://redhat-connect.gitbook.io/partner-guide-for-red-hat-openshift-and-container/program-on-boarding/technical-prerequisites#dockerfile-requirements
# The following labels must exist: name, maintainer, vendor, version, release, summary & description.
LABEL name="calyptia/fluent-bit" \
      vendor="calyptia" \
      maintainer="Patrick Stephens <pat@calyptia.com>" \
      version="ubi8-${FLUENT_BIT_VER}" \
      release="${FLUENT_BIT_VER}" \
      summary="Calyptia Fluent Bit ${FLUENT_BIT_VER}" \
      description="Calyptia Fluent Bit based on upstream Fluent Bit ${FLUENT_BIT_VER}"

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
