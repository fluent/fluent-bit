FROM ubuntu:20.04
WORKDIR /wamr-test/tests/fuzz/wasm-mutator-fuzz/server
COPY ./tests/fuzz/wasm-mutator-fuzz/server/requirements.txt /requirements.txt

ARG proxy=""

RUN if [ "$proxy" != "" ]; \
    then export http_proxy="$proxy" && export https_proxy="$proxy"; \
    else echo Do not set proxy; \
    fi

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Asian/Shanghai

# hadolint ignore=DL3008
RUN apt-get -o Acquire::http::proxy="$proxy" update \
    && apt-get -o Acquire::http::proxy="$proxy" install \
    curl clang rustc cargo python3 python3-pip git \
    gcc build-essential cmake g++-multilib libunwind-dev \
    wget -y --no-install-recommends && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir -U -r /requirements.txt --proxy=$proxy
COPY ./tests/fuzz /wamr-test/tests/fuzz

RUN if [ "$proxy" != "" ]; \
    then git config --global http.proxy $proxy && git config --global https.proxy $proxy; \
    else echo Do not set proxy for git; \
    fi

WORKDIR /wamr-test/tests/fuzz/wasm-mutator-fuzz

RUN wget --progress=dot:giga -e "https_proxy=$proxy" \
    https://github.com/bytecodealliance/wasm-tools/releases/download/v1.201.0/wasm-tools-1.201.0-x86_64-linux.tar.gz \
    && tar -xzf wasm-tools-1.201.0-x86_64-linux.tar.gz && mv wasm-tools-1.201.0-x86_64-linux wasm-tools
ENV PATH="/wamr-test/tests/fuzz/wasm-mutator-fuzz/wasm-tools:$PATH"

WORKDIR /wamr-test/tests/fuzz/wasm-mutator-fuzz/server/app

# hadolint ignore=DL3025
CMD nohup sh -c 'python3 main.py'
