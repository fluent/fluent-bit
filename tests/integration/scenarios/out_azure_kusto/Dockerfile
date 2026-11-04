FROM python:3.12-bookworm AS tools

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake build-essential flex bison libssl-dev libyaml-dev \
    ca-certificates valgrind \
    && rm -rf /var/lib/apt/lists/*

FROM tools AS build
COPY . /src
WORKDIR /src
ARG TEST_TARGETS=flb-rt-out_azure_kusto
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug \
    -DFLB_MINIMAL=On -DFLB_IN_DUMMY=On -DFLB_IN_LIB=On \
    -DFLB_OUT_AZURE_KUSTO=On -DFLB_OUT_NULL=On -DFLB_OUT_LIB=On \
    -DFLB_TLS=On -DFLB_JEMALLOC=Off -DFLB_SHARED_LIB=Off \
    -DFLB_TESTS_RUNTIME=On -DFLB_TESTS_INTERNAL=On \
    -DFLB_EXAMPLES=Off -DFLB_WASM=Off -DFLB_BACKTRACE=Off -DFLB_LUAJIT=Off \
    -DFLB_UNICODE_ENCODER=Off -DFLB_KAFKA=Off -DFLB_VALGRIND=On \
    && cmake --build build --target fluent-bit-bin ${TEST_TARGETS} -j8
RUN mkdir -p /fluent-bit/bin && cp build/bin/fluent-bit /fluent-bit/bin/
ENTRYPOINT ["/fluent-bit/bin/fluent-bit"]
