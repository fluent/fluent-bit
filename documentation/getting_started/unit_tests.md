# Unit Tests

[Fluent Bit](http://fluentbit.io) comes with some unit test programs that uses the _library_ mode to ingest data and test the output. The tests are based on [Google Test](https://code.google.com/p/googletest/) suite and requires a C++ compiler.

## Requirements

In order to build and run the tests, your system needs a C++ compiler and an installed version of [gtest](https://code.google.com/p/googletest/). On Debian/Ubuntu systems the following commands will install the dependencies:

```bash
$ sudo apt-get install g++ libgtest-dev
```

Note that _libgtest-dev_ will __only__ install the sources of the test suite, you need to take some extra steps to make this work:

```bash
$ cd /usr/src/gtest
$ sudo cmake .
$ sudo make
$ sudo cp libg* /usr/lib/
```

## Enable Tests

By default [Fluent Bit](http://fluentbit.io) have the tests disabled, you need to append the _ENABLE_TESTS_ option to your __cmake__ line, e.g:

```bash
$ cd build/
$ cmake -DENABLE_TESTS=ON ../
```

## Running Tests

To run the tests just issue the following command:

```bash
$ make test
```
