FROM gcr.io/google-containers/debian-base-amd64:0.3 as builder

# Fluent Bit version
ENV FLB_MAJOR 0
ENV FLB_MINOR 12
ENV FLB_PATCH 10
ENV FLB_VERSION 0.12.10

RUN mkdir -p /fluent-bit/bin /fluent-bit/etc /fluent-bit/log /tmp/src/

COPY . /tmp/src/
RUN rm -rf /tmp/src/build/*

RUN apt-get update && apt-get install -y build-essential cmake make wget unzip libsystemd-dev
WORKDIR /tmp/src/build/
RUN cmake -DFLB_DEBUG=Off -DFLB_TRACE=Off -DFLB_JEMALLOC=On -DFLB_BUFFERING=On -DFLB_TLS=On -DFLB_WITHOUT_SHARED_LIB=On -DFLB_WITHOUT_EXAMPLES=On ..
RUN make 
RUN install bin/fluent-bit /fluent-bit/bin/
# Configuration files
COPY conf/fluent-bit.conf conf/parsers.conf conf/parsers_java.conf /fluent-bit/etc/

FROM gcr.io/google-containers/debian-base-amd64:0.3
MAINTAINER Eduardo Silva <eduardo@treasure-data.com>
LABEL Description="Fluent Bit docker image" Vendor="Fluent Organization" Version="1.1"

RUN apt-get update \
    && apt-get dist-upgrade -y \
    && apt-get install --no-install-recommends ca-certificates -y \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get autoclean
COPY --from=builder /fluent-bit /fluent-bit

# Entry point
CMD ["/fluent-bit/bin/fluent-bit", "-c", "/fluent-bit/etc/fluent-bit.conf"]
