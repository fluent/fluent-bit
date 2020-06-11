# librdkafka v1.4.2

v1.4.2 is a maintenance release with the following fixes and enhancements:

 * Fix produce/consume hang after partition goes away and comes back,
   such as when a topic is deleted and re-created.
 * Consumer: Reset the stored offset when partitions are un-assign()ed (fixes #2782).
    This fixes the case where a manual offset-less commit() or the auto-committer
    would commit a stored offset from a previous assignment before
    a new message was consumed by the application.
 * Probe known CA cert paths and set default `ssl.ca.location` accordingly
   if OpenSSL is statically linked or `ssl.ca.location` is set to `probe`.
 * Per-partition OffsetCommit errors were unhandled (fixes #2791)
 * Seed the PRNG (random number generator) by default, allow application to override with `enable.random.seed=false` (#2795)
 * Fix stack overwrite (of 1 byte) when SaslHandshake MechCnt is zero
 * Align bundled c11 threads (tinycthreads) constants to glibc and musl (#2681)
 * Fix return value of rd_kafka_test_fatal_error() (by @ckb42)
 * Ensure CMake sets disabled defines to zero on Windows (@benesch)
 * librdkafka's build tooling now requires Python 3.x (python3 interpreter).

*Note: there was no v1.4.1 librdkafka release*





# Older releases

See https://github.com/edenhill/librdkafka/releases
