# RPM packages for librdkafka

On a system with RPM mock installed, simply run make to create RPM packages:

    $ make

Additional mock options may be specified using MOCK_OPTIONS:

    $ make MOCK_OPTIONS='--bootstrap-chroot'


## Build with Mock on docker

From the librdkafka top-level directory:

    $ packaging/rpm/mock-on-docker.sh

Wait for packages to build, they will be copied to top-level dir artifacts/

Test the packages:

    $ packaging/rpm/tests/test-on-docker.sh

