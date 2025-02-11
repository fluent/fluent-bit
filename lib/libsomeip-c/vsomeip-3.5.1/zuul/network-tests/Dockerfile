FROM ubuntu:jammy
SHELL ["/bin/bash", "-xec"]
RUN export DEBIAN_FRONTEND=noninteractive;\
    apt-get update;\
    apt-get dist-upgrade --purge --yes\
        bind9-dnsutils\
        cmake\
        g++-12\
        gdb\
        googletest\
        iproute2\
        jq\
        lcov\
        libboost-{log,system,thread}-dev\
        lsof\
        net-tools\
        ninja-build\
        openssh-server\
        pkg-config\
        python3-pip\
        tcpdump\
        valgrind\
        ;\
    apt-get autoremove --purge --yes;\
    apt-get clean;\
    pip3 install gcovr

# Pinned GCC version
ENV CC=gcc-12
ENV CXX=g++-12
ENV GCOV=gcov-12

# Build dlt-daemon
ADD dlt-daemon /home/source
RUN cmake -B /home/build -D DLT_IPC=UNIX_SOCKET -G Ninja -S /home/source;\
    cmake --build /home/build;\
    cmake --install /home/build --prefix /usr --strip;

# /etc configurations
RUN echo 'ECUId = M' > /etc/dlt-master.conf;\
    echo 'ECUId = S' > /etc/dlt-slave.conf;\
    echo 'SendEnv *' > /etc/ssh/ssh_config.d/vsomeip.conf;\
    echo 'AcceptEnv *' > /etc/ssh/sshd_config.d/vsomeip.conf

# SSH configurations
RUN ssh-keygen -q -b 1024 -f ~/.ssh/id_rsa -t rsa -N '';\
    install -DTm0400 ~/.ssh/id_rsa.pub ~/.ssh/authorized_keys;\
    install -DTm0400 ~/.ssh/id_rsa /commonapi_main/lxc-config/.ssh/mgc_lxc/rsa_key_file.pub

# Hard-coded path used in the tests' scripts
RUN ln -s /home/build /vsomeip_lib

# Place stuff in a known place
WORKDIR /home/source

# Declare bind-mounts
VOLUME ["/home/build", "/home/logs", "/home/source"]
