FROM debian:bullseye-slim as builder
ENV DEBIAN_FRONTEND noninteractive
ENV KAFKA_URL https://downloads.apache.org/kafka/3.4.1/kafka_2.13-3.4.1.tgz
ENV KAFKA_SHA256 a76f17a52b8f2cd31de11571ff366a714820b6e4e02893b0159d09db0edaf998

# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    ca-certificates \
    cmake \
    pkg-config \
    libsasl2-dev \
    libssl-dev \
    flex \
    openjdk-11-jre-headless \
    bison \
    netcat-openbsd \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Download kafka to access "kafka-topics" script
WORKDIR /kafka
RUN bash -c 'curl -L $KAFKA_URL | tee kafka.tgz | sha256sum -c <(echo "$KAFKA_SHA256 -")' \
    && tar --strip-components=1 -xf kafka.tgz \
    && mv /kafka/bin/kafka-topics.sh /kafka/bin/kafka-topics
ENV PATH="${PATH}:/kafka/bin"

WORKDIR /build/
COPY . /source
RUN cmake -DFLB_DEV=On \
          -DFLB_IN_KAFKA=On \
          -DFLB_OUT_KAFKA=On \
          -DFLB_CONFIG_YAML=Off \
          /source && \
    cmake --build . --parallel

FROM builder as runner
COPY --from=builder /build/bin/fluent-bit /usr/local/bin/fluent-bit
COPY examples/kafka_filter/kafka.conf /etc/kafka.conf
COPY examples/kafka_filter/kafka.lua /etc/kafka.lua
CMD ["/usr/local/bin/fluent-bit", "-c", "/etc/kafka.conf"]
