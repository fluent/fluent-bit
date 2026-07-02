FROM ubuntu:24.04

ARG UID

RUN NEEDRESTART_MODE=a apt-get update && apt-get install -y \
    wget curl python3 git openjdk-21-jdk-headless python3-venv \
    python3-setuptools build-essential libssl-dev libcurl4-openssl-dev \
    zlib1g-dev libsasl2-dev libzstd-dev clang-format-18 doxygen graphviz

RUN wget -O rapidjson-dev.deb https://launchpad.net/ubuntu/+archive/primary/+files/rapidjson-dev_1.1.0+dfsg2-3_all.deb && \
    dpkg -i rapidjson-dev.deb && \
    rm rapidjson-dev.deb
    
RUN mkdir -p /home/user
WORKDIR /home/user
COPY ./tests/trivup tests/trivup
COPY ./tests/requirements.txt tests/requirements.txt
COPY ./packaging/tools/requirements.txt packaging/tools/requirements.txt
COPY ./packaging/nuget/requirements.txt packaging/nuget/requirements.txt
RUN chown -R ${UID} /home/user

USER ${UID}

USER ${UID}
RUN python3 -m venv venv && \
    . venv/bin/activate && \
    pip install -U pip && \
    (cd tests && pip install -r requirements.txt) && \
    pip install -r packaging/tools/requirements.txt && \
    pip install -r packaging/nuget/requirements.txt && \
    rm -rf tests packaging
