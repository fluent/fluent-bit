
# To use this container you may need to do the following:
# https://askubuntu.com/a/1369504
# sudo add-apt-repository ppa:jacob/virtualisation #(for Ubuntu 20.04)
# sudo apt-get update && sudo apt-get install qemu qemu-user qemu-user-static
# https://stackoverflow.com/a/60667468
# docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
# docker buildx rm builder
# docker buildx create --name builder --use
# docker buildx inspect --bootstrap
# docker buildx build --platform "linux/amd64,linux/arm64,linux/arm/v7" -f ./dockerfiles/Dockerfile.multiarch --build-arg FLB_TARBALL=https://github.com/fluent/fluent-bit/archive/v1.8.11.tar.gz ./dockerfiles/

# Set this to the current release version: it gets done so as part of the release.
ARG RELEASE_VERSION=2.1.6

# For multi-arch builds - assumption is running on an AMD64 host
FROM multiarch/qemu-user-static:x86_64-arm as qemu-arm32
FROM multiarch/qemu-user-static:x86_64-aarch64 as qemu-arm64

FROM debian:bullseye-slim as builder-base

COPY --from=qemu-arm32 /usr/bin/qemu-arm-static /usr/bin/
COPY --from=qemu-arm64 /usr/bin/qemu-aarch64-static /usr/bin/

ARG FLB_NIGHTLY_BUILD
ENV FLB_NIGHTLY_BUILD=$FLB_NIGHTLY_BUILD

ARG FLB_CHUNK_TRACE=On
ENV FLB_CHUNK_TRACE=${FLB_CHUNK_TRACE}

RUN mkdir -p /fluent-bit/bin /fluent-bit/etc /fluent-bit/log

ENV DEBIAN_FRONTEND noninteractive

# hadolint ignore=DL3008
RUN echo "deb http://deb.debian.org/debian bullseye-backports main" >> /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    ca-certificates \
    cmake \
    git \
    make \
    tar \
    libssl-dev \
    libsasl2-dev \
    pkg-config \
    libsystemd-dev/bullseye-backports \
    zlib1g-dev \
    libpq-dev \
    postgresql-server-dev-all \
    flex \
    bison \
    libyaml-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Must be run from root of repo
WORKDIR /src/fluent-bit/
COPY . ./

# We split the builder setup out so people can target it or use as a base image without doing a full build.
FROM builder-base as builder
WORKDIR /src/fluent-bit/build/
RUN cmake -DFLB_RELEASE=On \
    -DFLB_JEMALLOC=On \
    -DFLB_TLS=On \
    -DFLB_SHARED_LIB=Off \
    -DFLB_EXAMPLES=Off \
    -DFLB_HTTP_SERVER=On \
    -DFLB_IN_EXEC=On \
    -DFLB_IN_SYSTEMD=On \
    -DFLB_OUT_KAFKA=On \
    -DFLB_OUT_PGSQL=On \
    -DFLB_NIGHTLY_BUILD="$FLB_NIGHTLY_BUILD" \
    -DFLB_LOG_NO_CONTROL_CHARS=On \
    -DFLB_CHUNK_TRACE="$FLB_CHUNK_TRACE" \
    ..

RUN make -j "$(getconf _NPROCESSORS_ONLN)"
RUN install bin/fluent-bit /fluent-bit/bin/

# Configuration files
COPY conf/fluent-bit.conf \
    conf/parsers.conf \
    conf/parsers_ambassador.conf \
    conf/parsers_java.conf \
    conf/parsers_extra.conf \
    conf/parsers_openstack.conf \
    conf/parsers_cinder.conf \
    conf/plugins.conf \
    /fluent-bit/etc/

# Generate schema and include as part of the container image
RUN /fluent-bit/bin/fluent-bit -J > /fluent-bit/etc/schema.json

FROM debian:bullseye-slim as debug
ARG RELEASE_VERSION
ENV FLUENT_BIT_VERSION=${RELEASE_VERSION}
LABEL description="Fluent Bit multi-architecture debug container image" \
    vendor="Fluent Organization" \
    version="${RELEASE_VERSION}-debug" \
    author="Eduardo Silva <eduardo@calyptia.com>" \
    org.opencontainers.image.description="Fluent Bit debug container image" \
    org.opencontainers.image.title="Fluent Bit Debug" \
    org.opencontainers.image.licenses="Apache-2.0" \
    org.opencontainers.image.vendor="Fluent Organization" \
    org.opencontainers.image.version="${RELEASE_VERSION}-debug" \
    org.opencontainers.image.source="https://github.com/fluent/fluent-bit" \
    org.opencontainers.image.documentation="https://docs.fluentbit.io/" \
    org.opencontainers.image.authors="Eduardo Silva <eduardo@calyptia.com>"

COPY --from=qemu-arm32 /usr/bin/qemu-arm-static /usr/bin/
COPY --from=qemu-arm64 /usr/bin/qemu-aarch64-static /usr/bin/
ENV DEBIAN_FRONTEND noninteractive

# hadolint ignore=DL3008
RUN echo "deb http://deb.debian.org/debian bullseye-backports main" >> /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    auditd  \
    libssl1.1 \
    libsasl2-2 \
    pkg-config \
    libpq5 \
    libsystemd0/bullseye-backports \
    zlib1g \
    ca-certificates \
    libatomic1 \
    libgcrypt20 \
    libyaml-0-2 \
    bash gdb valgrind build-essential  \
    git bash-completion vim tmux jq \
    dnsutils iputils-ping iputils-arping iputils-tracepath iputils-clockdiff \
    tcpdump curl nmap tcpflow iftop \
    net-tools mtr netcat-openbsd bridge-utils iperf ngrep \
    openssl \
    htop atop strace iotop sysstat ncdu logrotate hdparm pciutils psmisc tree pv \
    cmake make tar flex bison \
    libssl-dev libsasl2-dev libsystemd-dev/bullseye-backports zlib1g-dev libpq-dev libyaml-dev postgresql-server-dev-all \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN rm -f /usr/bin/qemu-*-static
COPY --from=builder /fluent-bit /fluent-bit

## Copy AWS plugins
COPY --from=amazon/aws-for-fluent-bit:latest /fluent-bit/kinesis.so /fluent-bit/kinesis.so
COPY --from=amazon/aws-for-fluent-bit:latest /fluent-bit/firehose.so /fluent-bit/firehose.so
COPY --from=amazon/aws-for-fluent-bit:latest /fluent-bit/cloudwatch.so /fluent-bit/cloudwatch.so

EXPOSE 2020

# No entry point so we can just shell in
CMD ["/fluent-bit/bin/fluent-bit", "-e", "/fluent-bit/firehose.so", "-e", "/fluent-bit/cloudwatch.so", "-e", "/fluent-bit/kinesis.so", "-c", "/fluent-bit/etc/fluent-bit.conf"]
