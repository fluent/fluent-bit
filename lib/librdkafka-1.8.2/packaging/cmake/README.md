# Build librdkafka with cmake

The cmake build mode is experimental and not officially supported,
the community is asked to maintain and support this mode through PRs.

Set up build environment (from top-level librdkafka directory):

    $ cmake -H. -B_cmake_build

On MacOSX and OpenSSL from Homebrew you might need to do:

    $ cmake -H. -B_cmake_build -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl


Build the library:

    $ cmake --build _cmake_build

If you want to build static library:

    $ cmake --build _cmake_build -DRDKAFKA_BUILD_STATIC=1


Run (local) tests:

    $ (cd _cmake_build && ctest -VV -R RdKafkaTestBrokerLess)


Install library:

    $ cmake --build _cmake_build --target install


If you use librdkafka as submodule in cmake project and want static link of librdkafka:

      set(RDKAFKA_BUILD_STATIC ON CACHE BOOL "")
      add_subdirectory(librdkafka)
      target_link_libraries(your_library_or_executable rdkafka)
