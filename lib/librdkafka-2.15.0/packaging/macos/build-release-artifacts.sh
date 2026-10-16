./configure --install-deps --source-deps-only --enable-static --disable-lz4-ext --enable-strip
make -j all examples check
examples/rdkafka_example -X builtin.features
otool -L src/librdkafka.dylib
otool -L src-cpp/librdkafka++.dylib
make -j -C tests build
export TEST_CONSUMER_GROUP_PROTOCOL=classic
make -C tests run_local_quick
export TEST_CONSUMER_GROUP_PROTOCOL=consumer
# Skip tests needing special limits
TESTS_WITH_INCREASED_NLIMIT="0153"
export TESTS_SKIP="$TESTS_WITH_INCREASED_NLIMIT"
make -C tests run_local_quick
# Now run only those tests with different limits

# Tests needing increased number of file descriptors
PREV_N=$(ulimit -n)
ulimit -n 2048
export TESTS_SKIP=""
export TESTS="$TESTS_WITH_INCREASED_NLIMIT"
make -C tests run_local_quick
ulimit -n $PREV_N


DESTDIR="$PWD/dest" make install
(cd dest && tar cvzf ../artifacts/librdkafka.tgz .)
