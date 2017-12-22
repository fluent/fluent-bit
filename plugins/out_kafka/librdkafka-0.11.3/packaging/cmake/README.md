# Build librdkafka with cmake

The cmake build mode is experimental and not officially supported,
the community is asked to maintain and support this mode through PRs.


Set up build environment (from top-level librdkafka directory):

    $ cmake -H. -B_cmake_build

On MacOSX and OpenSSL from Homebrew you might need to do:

    $ cmake -H. -B_cmake_build -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl


Build the library:

    $ cmake --build _cmake_build


Run (local) tests:

    $ (cd _cmake_build && ctest -VV -R RdKafkaTestBrokerLess)


Install library:

    $ cmake --build _cmake_build --target install
