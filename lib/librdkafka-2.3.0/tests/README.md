# Automated regression tests for librdkafka


## Supported test environments

While the standard test suite works well on OSX and Windows,
the full test suite (which must be run for PRs and releases) will
only run on recent Linux distros due to its use of ASAN, Kerberos, etc.


## Automated broker cluster setup using trivup

A local broker cluster can be set up using
[trivup](https://github.com/edenhill/trivup), which is a Python package
available on PyPi.
These self-contained clusters are used to run the librdkafka test suite
on a number of different broker versions or with specific broker configs.

trivup will download the specified Kafka version into its root directory,
the root directory is also used for cluster instances, where Kafka will
write messages, logs, etc.
The trivup root directory is by default `tmp` in the current directory but
may be specified by setting the `TRIVUP_ROOT` environment variable
to alternate directory, e.g., `TRIVUP_ROOT=$HOME/trivup make full`.

First install required Python packages (trivup with friends):

    $ python3 -m pip install -U -r requirements.txt

Bring up a Kafka cluster (with the specified version) and start an interactive
shell, when the shell is exited the cluster is brought down and deleted.

    $ python3 -m trivup.clusters.KafkaCluster 2.3.0   # Broker version
    # You can also try adding:
    #   --ssl    To enable SSL listeners
    #   --sasl <mechanism>   To enable SASL authentication
    #   --sr     To provide a Schema-Registry instance
    #  .. and so on, see --help for more.

In the trivup shell, run the test suite:

    $ make


If you'd rather use an existing cluster, you may omit trivup and
provide a `test.conf` file that specifies the brokers and possibly other
librdkafka configuration properties:

    $ cp test.conf.example test.conf
    $ $EDITOR test.conf



## Run specific tests

To run tests:

    # Run tests in parallel (quicker, but harder to troubleshoot)
    $ make

    # Run a condensed test suite (quickest)
    # This is what is run on CI builds.
    $ make quick

    # Run tests in sequence
    $ make run_seq

    # Run specific test
    $ TESTS=0004 make

    # Run test(s) with helgrind, valgrind, gdb
    $ TESTS=0009 ./run-test.sh valgrind|helgrind|gdb


All tests in the 0000-0999 series are run automatically with `make`.

Tests 1000-1999 are subject to specific non-standard setups or broker
configuration, these tests are run with `TESTS=1nnn make`.
See comments in the test's source file for specific requirements.

To insert test results into SQLite database make sure the `sqlite3` utility
is installed, then add this to `test.conf`:

    test.sql.command=sqlite3 rdktests



## Adding a new test

The simplest way to add a new test is to copy one of the recent
(higher `0nnn-..` number) tests to the next free
`0nnn-<what-is-tested>` file.

If possible and practical, try to use the C++ API in your test as that will
cover both the C and C++ APIs and thus provide better test coverage.
Do note that the C++ test framework is not as feature rich as the C one,
so if you need message verification, etc, you're better off with a C test.

After creating your test file it needs to be added in a couple of places:

 * Add to [tests/CMakeLists.txt](tests/CMakeLists.txt)
 * Add to [win32/tests/tests.vcxproj](win32/tests/tests.vcxproj)
 * Add to both locations in [tests/test.c](tests/test.c) - search for an
   existing test number to see what needs to be done.

You don't need to add the test to the Makefile, it is picked up automatically.

Some additional guidelines:
 * If your test depends on a minimum broker version, make sure to specify it
   in test.c using `TEST_BRKVER()` (see 0091 as an example).
 * If your test can run without an active cluster, flag the test
   with `TEST_F_LOCAL`.
 * If your test runs for a long time or produces/consumes a lot of messages
   it might not be suitable for running on CI (which should run quickly
   and are bound by both time and resources). In this case it is preferred
   if you modify your test to be able to run quicker and/or with less messages
   if the `test_quick` variable is true.
 * There's plenty of helper wrappers in test.c for common librdkafka functions
   that makes tests easier to write by not having to deal with errors, etc.
 * Fail fast, use `TEST_ASSERT()` et.al., the sooner an error is detected
   the better since it makes troubleshooting easier.
 * Use `TEST_SAY()` et.al. to inform the developer what your test is doing,
   making it easier to troubleshoot upon failure. But try to keep output
   down to reasonable levels. There is a `TEST_LEVEL` environment variable
   that can be used with `TEST_SAYL()` to only emit certain printouts
   if the test level is increased. The default test level is 2.
 * The test runner will automatically adjust timeouts (it knows about)
   if running under valgrind, on CI, or similar environment where the
   execution speed may be slower.
   To make sure your test remains sturdy in these type of environments, make
   sure to use the `tmout_multip(milliseconds)` macro when passing timeout
   values to non-test functions, e.g, `rd_kafka_poll(rk, tmout_multip(3000))`.
 * If your test file contains multiple separate sub-tests, use the
   `SUB_TEST()`, `SUB_TEST_QUICK()` and `SUB_TEST_PASS()` from inside
   the test functions to help differentiate test failures.


## Test scenarios

A test scenario defines the cluster configuration used by tests.
The majority of tests use the "default" scenario which matches the
Apache Kafka default broker configuration (topic auto creation enabled, etc).

If a test relies on cluster configuration that is mutually exclusive with
the default configuration an alternate scenario must be defined in
`scenarios/<scenario>.json` which is a configuration object which
is passed to [trivup](https://github.com/edenhill/trivup).

Try to reuse an existing test scenario as far as possible to speed up
test times, since each new scenario will require a new cluster incarnation.


## A guide to testing, verifying, and troubleshooting, librdkafka


### Creating a development build

The [dev-conf.sh](../dev-conf.sh) script configures and builds librdkafka and
the test suite for development use, enabling extra runtime
checks (`ENABLE_DEVEL`, `rd_dassert()`, etc), disabling optimization
(to get accurate stack traces and line numbers), enable ASAN, etc.

    # Reconfigure librdkafka for development use and rebuild.
    $ ./dev-conf.sh

**NOTE**: Performance tests and benchmarks should not use a development build.


### Controlling the test framework

A test run may be dynamically set up using a number of environment variables.
These environment variables work for all different ways of invocing the tests,
be it `make`, `run-test.sh`, `until-fail.sh`, etc.

 * `TESTS=0nnn` - only run a single test identified by its full number, e.g.
                  `TESTS=0102 make`. (Yes, the var should have been called TEST)
 * `SUBTESTS=...` - only run sub-tests (tests that are using `SUB_TEST()`)
                      that contains this string.
 * `TESTS_SKIP=...` - skip these tests.
 * `TEST_DEBUG=...` - this will automatically set the `debug` config property
                      of all instantiated clients to the value.
                      E.g.. `TEST_DEBUG=broker,protocol TESTS=0001 make`
 * `TEST_LEVEL=n` - controls the `TEST_SAY()` output level, a higher number
                      yields more test output. Default level is 2.
 * `RD_UT_TEST=name` - only run unittest containing `name`, should be used
                          with `TESTS=0000`.
                          See [../src/rdunittest.c](../src/rdunittest.c) for
                          unit test names.
 * `TESTS_SKIP_BEFORE=0nnn` - skip tests before this test. Tests are skipped
                              even if they are part of `TESTS` variable.
                              Usage: `TESTS_SKIP_BEFORE=0030`. All the tests
                              until test 0030 are skipped.


Let's say that you run the full test suite and get a failure in test 0061,
which is a consumer test. You want to quickly reproduce the issue
and figure out what is wrong, so limit the tests to just 0061, and provide
the relevant debug options (which is typically `cgrp,fetch` for consumers):

    $ TESTS=0061 TEST_DEBUG=cgrp,fetch make

If the test did not fail you've found an intermittent issue, this is where
[until-fail.sh](until-fail.sh) comes in to play, so run the test until it fails:

    # bare means to run the test without valgrind
    $ TESTS=0061 TEST_DEBUG=cgrp,fetch ./until-fail.sh bare


### How to run tests

The standard way to run the test suite is firing up a trivup cluster
in an interactive shell:

    $ ./interactive_broker_version.py 2.3.0   # Broker version


And then running the test suite in parallel:

    $ make


Run one test at a time:

    $ make run_seq


Run a single test:

    $ TESTS=0034 make


Run test suite with valgrind (see instructions below):

    $ ./run-test.sh valgrind   # memory checking

or with helgrind (the valgrind thread checker):

    $ ./run-test.sh helgrind   # thread checking


To run the tests in gdb:

**NOTE**: gdb support is flaky on OSX due to signing issues.

    $ ./run-test.sh gdb
    (gdb) run

    # wait for test to crash, or interrupt with Ctrl-C

    # backtrace of current thread
    (gdb) bt
    # move up or down a stack frame
    (gdb) up
    (gdb) down
    # select specific stack frame
    (gdb) frame 3
    # show code at location
    (gdb) list

    # print variable content
    (gdb) p rk.rk_conf.group_id
    (gdb) p *rkb

    # continue execution (if interrupted)
    (gdb) cont

    # single-step one instruction
    (gdb) step

    # restart
    (gdb) run

    # see all threads
    (gdb) info threads

    # see backtraces of all threads
    (gdb) thread apply all bt

    # exit gdb
    (gdb) exit


If a test crashes and produces a core file (make sure your shell has
`ulimit -c unlimited` set!), do:

    # On linux
    $ LD_LIBRARY_PATH=../src:../src-cpp gdb ./test-runner <core-file>
    (gdb) bt

    # On OSX
    $ DYLD_LIBRARY_PATH=../src:../src-cpp gdb ./test-runner /cores/core.<pid>
    (gdb) bt


To run all tests repeatedly until one fails, this is a good way of finding
intermittent failures, race conditions, etc:

    $ ./until-fail.sh bare  # bare is to run the test without valgrind,
                            # may also be one or more of the modes supported
                            # by run-test.sh:
                            #  bare valgrind helgrind gdb, etc..

To run a single test repeatedly with valgrind until failure:

    $ TESTS=0103 ./until-fail.sh valgrind



### Finding memory leaks, memory corruption, etc.

There are two ways to verifying there are no memory leaks, out of bound
memory accesses, use after free, etc. ASAN or valgrind.

#### ASAN - AddressSanitizer

The first option is using AddressSanitizer, this is build-time instrumentation
provided by clang and gcc to insert memory checks in the build library.

To enable AddressSanitizer (ASAN), run `./dev-conf.sh asan` from the
librdkafka root directory.
This script will rebuild librdkafka and the test suite with ASAN enabled.

Then run tests as usual. Memory access issues will be reported on stderr
in real time as they happen (and the test will fail eventually), while
memory leaks will be reported on stderr when the test run exits successfully,
i.e., no tests failed.

Test failures will typically cause the current test to exit hard without
cleaning up, in which case there will be a large number of reported memory
leaks, these shall be ignored. The memory leak report is only relevant
when the test suite passes.

**NOTE**: The OSX version of ASAN does not provide memory leak protection,
          you will need to run the test suite on Linux (native or in Docker).

**NOTE**: ASAN, TSAN and valgrind are mutually exclusive.


#### Valgrind - memory checker

Valgrind is a powerful virtual machine that intercepts all memory accesses
of an unmodified program, reporting memory access violations, use after free,
memory leaks, etc.

Valgrind provides additional checks over ASAN and is mostly useful
for troubleshooting crashes, memory issues and leaks when ASAN falls short.

To use valgrind, make sure librdkafka and the test suite is built without
ASAN or TSAN, it must be a clean build without any other instrumentation,
then simply run:

    $ ./run-test.sh valgrind

Valgrind will report to stderr, just like ASAN.


**NOTE**: Valgrind only runs on Linux.

**NOTE**: ASAN, TSAN and valgrind are mutually exclusive.


### TSAN - Thread and locking issues

librdkafka uses a number of internal threads which communicate and share state
through op queues, conditional variables, mutexes and atomics.

While the docstrings in the librdkafka source code specify what locking is
required it is very hard to manually verify that the correct locks
are acquired, and in the correct order (to avoid deadlocks).

TSAN, ThreadSanitizer, is of great help here. As with ASAN, TSAN is a
build-time option: run `./dev-conf.sh tsan` to rebuild with TSAN.

Run the test suite as usual, preferably in parallel. TSAN will output
thread errors to stderr and eventually fail the test run.

If you're having threading issues and TSAN does not provide enough information
to sort it out, you can also try running the test with helgrind, which
is valgrind's thread checker (`./run-test.sh helgrind`).


**NOTE**: ASAN, TSAN and valgrind are mutually exclusive.


### Resource usage thresholds (experimental)

**NOTE**: This is an experimental feature, some form of system-specific
          calibration will be needed.

If the `-R` option is passed to the `test-runner`, or the `make rusage`
target is used, the test framework will monitor each test's resource usage
and fail the test if the default or test-specific thresholds are exceeded.

Per-test thresholds are specified in test.c using the `_THRES()` macro.

Currently monitored resources are:
 * `utime` - User CPU time in seconds (default 1.0s)
 * `stime` - System/Kernel CPU time in seconds (default 0.5s).
 * `rss` - RSS (memory) usage (default 10.0 MB)
 * `ctxsw` - Number of voluntary context switches, e.g. syscalls (default 10000).

Upon successful test completion a log line will be emitted with a resource
usage summary, e.g.:

    Test resource usage summary: 20.161s (32.3%) User CPU time, 12.976s (20.8%) Sys CPU time, 0.000MB RSS memory increase, 4980 Voluntary context switches

The User and Sys CPU thresholds are based on observations running the
test suite on an Intel(R) Core(TM) i7-2600 CPU @ 3.40GHz (8 cores)
which define the base line system.

Since no two development environments are identical a manual CPU calibration
value can be passed as `-R<C>`, where `C` is the CPU calibration for
the local system compared to the base line system.
The CPU threshold will be multiplied by the CPU calibration value (default 1.0),
thus a value less than 1.0 means the local system is faster than the
base line system, and a value larger than 1.0 means the local system is
slower than the base line system.
I.e., if you are on an i5 system, pass `-R2.0` to allow higher CPU usages,
or `-R0.8` if your system is faster than the base line system.
The the CPU calibration value may also be set with the
`TEST_CPU_CALIBRATION=1.5` environment variable.

In an ideal future, the test suite would be able to auto-calibrate.


**NOTE**: The resource usage threshold checks will run tests in sequence,
          not parallell, to be able to effectively measure per-test usage.


# PR and release verification

Prior to pushing your PR  you must verify that your code change has not
introduced any regression or new issues, this requires running the test
suite in multiple different modes:

 * PLAINTEXT, SSL transports
 * All SASL mechanisms (PLAIN, GSSAPI, SCRAM, OAUTHBEARER)
 * Idempotence enabled for all tests
 * With memory checking
 * With thread checking
 * Compatibility with older broker versions

These tests must also be run for each release candidate that is created.

    $ make release-test

This will take approximately 30 minutes.

**NOTE**: Run this on Linux (for ASAN and Kerberos tests to work properly), not OSX.


# Test mode specifics

The following sections rely on trivup being installed.


### Compatbility tests with multiple broker versions

To ensure compatibility across all supported broker versions the entire
test suite is run in a trivup based cluster, one test run for each
relevant broker version.

    $ ./broker_version_tests.py


### SASL tests

Testing SASL requires a bit of configuration on the brokers, to automate
this the entire test suite is run on trivup based clusters.

    $ ./sasl_tests.py



### Full test suite(s) run

To run all tests, including the broker version and SASL tests, etc, use

    $ make full

**NOTE**: `make full` is a sub-set of the more complete `make release-test` target.


### Idempotent Producer tests

To run the entire test suite with `enable.idempotence=true` enabled, use
`make idempotent_seq` or `make idempotent_par` for sequencial or
parallel testing.
Some tests are skipped or slightly modified when idempotence is enabled.


## Manual testing notes

The following manual tests are currently performed manually, they should be
implemented as automatic tests.

### LZ4 interop

    $ ./interactive_broker_version.py -c ./lz4_manual_test.py 0.8.2.2 0.9.0.1 2.3.0

Check the output and follow the instructions.




## Test numbers

Automated tests: 0000-0999
Manual tests:    8000-8999
