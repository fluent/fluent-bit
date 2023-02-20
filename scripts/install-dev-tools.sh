#!/usr/bin/env bash

apt-get update

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
    libyaml-dev
