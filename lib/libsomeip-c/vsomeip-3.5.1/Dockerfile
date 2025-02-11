FROM ubuntu:jammy
SHELL ["/bin/bash", "-xec"]
RUN export DEBIAN_FRONTEND=noninteractive;\
    apt-get update;\
    apt-get dist-upgrade --no-install-recommends --purge --yes\
        clang-12\
        cmake\
        g++\
        googletest\
        libbenchmark-dev\
        libboost-{{file,}system,thread}-dev\
        make\
        python3-pip\
        ;\
    apt-get autoremove --purge --yes;\
    apt-get clean;\
    pip3 install gcovr;\
    ln -s /usr/bin/clang-12 /usr/bin/clang;\
    ln -s /usr/bin/clang++-12 /usr/bin/clang++;\
    ln -s /usr/bin/lld-12 /usr/bin/lld;\
    ln -s /usr/bin/clang-tidy-12 /usr/bin/clang-tidy

ENV GTEST_ROOT=/usr/src/googletest

WORKDIR /home/source
VOLUME ["/home/source"]
