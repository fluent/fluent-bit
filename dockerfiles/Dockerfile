# syntax=docker/dockerfile:1
# check=skip=InvalidBaseImagePlatform

# To use this container you may need to do the following:
# https://askubuntu.com/a/1369504
# sudo add-apt-repository ppa:jacob/virtualisation #(for Ubuntu 20.04)
# sudo apt-get update && sudo apt-get install qemu qemu-user qemu-user-static
# https://stackoverflow.com/a/60667468
# docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
# docker buildx rm builder
# docker buildx create --name builder --use
# docker buildx inspect --bootstrap
# docker buildx build --platform "linux/amd64,linux/arm64,linux/arm/v7,linux/s390x" -f ./dockerfiles/Dockerfile.multiarch --build-arg FLB_TARBALL=https://github.com/fluent/fluent-bit/archive/v1.8.11.tar.gz ./dockerfiles/

# Set this to the current release version: it gets done so as part of the release.
ARG RELEASE_VERSION=4.2.1

# For multi-arch builds - assumption is running on an AMD64 host
FROM multiarch/qemu-user-static:x86_64-arm AS qemu-arm32
FROM multiarch/qemu-user-static:x86_64-aarch64 AS qemu-arm64

FROM debian:bookworm-slim AS builder-base

COPY --from=qemu-arm32 /usr/bin/qemu-arm-static /usr/bin/
COPY --from=qemu-arm64 /usr/bin/qemu-aarch64-static /usr/bin/

ARG FLB_NIGHTLY_BUILD
ENV FLB_NIGHTLY_BUILD=$FLB_NIGHTLY_BUILD

ARG FLB_CHUNK_TRACE=On
ENV FLB_CHUNK_TRACE=${FLB_CHUNK_TRACE}

RUN mkdir -p /fluent-bit/bin /fluent-bit/etc /fluent-bit/log

ENV DEBIAN_FRONTEND=noninteractive

# hadolint ignore=DL3008
RUN echo "deb http://deb.debian.org/debian bookworm-backports main" >> /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    ca-certificates \
    git \
    make \
    tar \
    libssl-dev \
    libcurl4-openssl-dev \
    libsasl2-dev \
    pkg-config \
    libsystemd-dev/bookworm-backports \
    zlib1g-dev \
    libpq-dev \
    postgresql-server-dev-all \
    flex \
    bison \
    libyaml-dev \
    && apt-get satisfy -y cmake "cmake (<< 4.0)" \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Must be run from root of repo
WORKDIR /src/fluent-bit/
COPY . ./

# We split the builder setup out so people can target it or use as a base image without doing a full build.
FROM builder-base AS builder
WORKDIR /src/fluent-bit/build/

# Required to be set to ARMV7 for that target
ARG WAMR_BUILD_TARGET
ARG EXTRA_CMAKE_FLAGS
ENV EXTRA_CMAKE_FLAGS=${EXTRA_CMAKE_FLAGS}

# Optional: jemalloc configure flags (e.g., page size). Leave unset to keep defaults.
ARG FLB_JEMALLOC_OPTIONS
ENV FLB_JEMALLOC_OPTIONS=${FLB_JEMALLOC_OPTIONS}

# We do not want word splitting for EXTRA_CMAKE_FLAGS in case multiple are defined
# hadolint ignore=SC2086
RUN [ -n "${WAMR_BUILD_TARGET:-}" ] && EXTRA_CMAKE_FLAGS="$EXTRA_CMAKE_FLAGS -DWAMR_BUILD_TARGET=$WAMR_BUILD_TARGET"; \
    cmake -DFLB_SIMD=On \
    -DFLB_RELEASE=On \
    -DFLB_JEMALLOC=On \
    -DFLB_TLS=On \
    -DFLB_SHARED_LIB=Off \
    -DFLB_EXAMPLES=Off \
    -DFLB_HTTP_SERVER=On \
    -DFLB_IN_EXEC=Off \
    -DFLB_IN_SYSTEMD=On \
    -DFLB_OUT_KAFKA=On \
    -DFLB_OUT_PGSQL=On \
    -DFLB_NIGHTLY_BUILD="$FLB_NIGHTLY_BUILD" \
    -DFLB_LOG_NO_CONTROL_CHARS=On \
    -DFLB_CHUNK_TRACE="$FLB_CHUNK_TRACE" \
    -DFLB_JEMALLOC_OPTIONS="$FLB_JEMALLOC_OPTIONS" \
    $EXTRA_CMAKE_FLAGS \
    ..

ARG CFLAGS="-v"
ENV CFLAGS=${CFLAGS}

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

# Simple example of how to properly extract packages for reuse in distroless
# Taken from: https://github.com/GoogleContainerTools/distroless/issues/863
FROM debian:bookworm-slim AS deb-extractor
COPY --from=qemu-arm32 /usr/bin/qemu-arm-static /usr/bin/
COPY --from=qemu-arm64 /usr/bin/qemu-aarch64-static /usr/bin/

# We download all debs locally then extract them into a directory we can use as the root for distroless.
# We also include some extra handling for the status files that some tooling uses for scanning, etc.
WORKDIR /tmp
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN echo "deb http://deb.debian.org/debian bookworm-backports main" >> /etc/apt/sources.list && \
    apt-get update && \
    apt-get download \
    libssl3 \
    libcurl4 \
    libnghttp2-14 \
    librtmp1 \
    libssh2-1 \
    libpsl5 \
    libbrotli1 \
    libsasl2-2 \
    pkg-config \
    libpq5 \
    libsystemd0/bookworm-backports \
    zlib1g \
    ca-certificates \
    libatomic1 \
    libgcrypt20 \
    libzstd1 \
    liblz4-1 \
    libgssapi-krb5-2 \
    libldap-2.5 \
    libgpg-error0 \
    libkrb5-3 \
    libk5crypto3 \
    libcom-err2 \
    libkrb5support0 \
    libgnutls30 \
    libkeyutils1 \
    libp11-kit0 \
    libidn2-0 \
    libunistring2 \
    libtasn1-6 \
    libnettle8 \
    libhogweed6 \
    libgmp10 \
    libffi8 \
    liblzma5 \
    libyaml-0-2 \
    libcap2 \
    && \
    mkdir -p /dpkg/var/lib/dpkg/status.d/ && \
    for deb in *.deb; do \
    package_name=$(dpkg-deb -I "${deb}" | awk '/^ Package: .*$/ {print $2}'); \
    echo "Processing: ${package_name}"; \
    dpkg --ctrl-tarfile "$deb" | tar -Oxf - ./control > "/dpkg/var/lib/dpkg/status.d/${package_name}"; \
    dpkg --extract "$deb" /dpkg || exit 10; \
    done

# Remove unnecessary files extracted from deb packages like man pages and docs etc.
RUN find /dpkg/ -type d -empty -delete && \
    rm -r /dpkg/usr/share/doc/

# We want latest at time of build
# hadolint ignore=DL3006
FROM gcr.io/distroless/cc-debian12 AS production
ARG RELEASE_VERSION
ENV FLUENT_BIT_VERSION=${RELEASE_VERSION}
LABEL description="Fluent Bit multi-architecture container image" \
    vendor="Fluent Organization" \
    version="${RELEASE_VERSION}" \
    author="Eduardo Silva <eduardo.silva@chronosphere.io>" \
    org.opencontainers.image.description="Fluent Bit container image" \
    org.opencontainers.image.title="Fluent Bit" \
    org.opencontainers.image.licenses="Apache-2.0" \
    org.opencontainers.image.vendor="Fluent Organization" \
    org.opencontainers.image.version="${RELEASE_VERSION}" \
    org.opencontainers.image.source="https://github.com/fluent/fluent-bit" \
    org.opencontainers.image.documentation="https://docs.fluentbit.io/" \
    org.opencontainers.image.authors="Eduardo Silva <eduardo.silva@chronosphere.io>"

# Copy the libraries from the extractor stage into root
COPY --from=deb-extractor /dpkg /

# Copy certificates
COPY --from=builder /etc/ssl/certs /etc/ssl/certs

# Finally the binaries as most likely to change
COPY --from=builder /fluent-bit /fluent-bit

EXPOSE 2020

# Entry point
ENTRYPOINT [ "/fluent-bit/bin/fluent-bit" ]
CMD ["/fluent-bit/bin/fluent-bit", "-c", "/fluent-bit/etc/fluent-bit.conf"]

FROM debian:bookworm-slim AS debug
ARG RELEASE_VERSION
ENV FLUENT_BIT_VERSION=${RELEASE_VERSION}
LABEL description="Fluent Bit multi-architecture debug container image" \
    vendor="Fluent Organization" \
    version="${RELEASE_VERSION}-debug" \
    author="Eduardo Silva <eduardo.silva@chronosphere.io>" \
    org.opencontainers.image.description="Fluent Bit debug container image" \
    org.opencontainers.image.title="Fluent Bit Debug" \
    org.opencontainers.image.licenses="Apache-2.0" \
    org.opencontainers.image.vendor="Fluent Organization" \
    org.opencontainers.image.version="${RELEASE_VERSION}-debug" \
    org.opencontainers.image.source="https://github.com/fluent/fluent-bit" \
    org.opencontainers.image.documentation="https://docs.fluentbit.io/" \
    org.opencontainers.image.authors="Eduardo Silva <eduardo.silva@chronosphere.io>"

COPY --from=qemu-arm32 /usr/bin/qemu-arm-static /usr/bin/
COPY --from=qemu-arm64 /usr/bin/qemu-aarch64-static /usr/bin/
ENV DEBIAN_FRONTEND=noninteractive

# hadolint ignore=DL3008
RUN echo "deb http://deb.debian.org/debian bookworm-backports main" >> /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    libssl3 \
    libcurl4 \
    libnghttp2-14 \
    librtmp1 \
    libssh2-1 \
    libpsl5 \
    libbrotli1 \
    libsasl2-2 \
    pkg-config \
    libpq5 \
    libsystemd0/bookworm-backports \
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
    make tar flex bison \
    libssl-dev libsasl2-dev libsystemd-dev/bookworm-backports zlib1g-dev libpq-dev libyaml-dev postgresql-server-dev-all \
    && apt-get satisfy -y cmake "cmake (<< 4.0)" \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN rm -f /usr/bin/qemu-*-static
COPY --from=builder /fluent-bit /fluent-bit

EXPOSE 2020

# No entry point so we can just shell in
CMD ["/fluent-bit/bin/fluent-bit", "-c", "/fluent-bit/etc/fluent-bit.conf"]
