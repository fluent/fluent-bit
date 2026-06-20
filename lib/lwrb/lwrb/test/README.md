# Testing Suite for lwrb

This directory contains an environment for writing and executing tests for the lwrb library. It supports code coverage along with different usage of sanitizers (such as ASAN and UBSAN).

## Requirements
The repository must have been built recursively for retrieval of the necessary git submodules. Further more, this testing environment requires cmake. For sanitizers you need to use a compiler which has the sanitizer dependencies availble. For coverage, you also need gcov and lcov.

## Build

```bash
mkdir build
cd build
cmake -DSANITIZE_ADDRESS=On -DSANITIZE_UNDEFINED=On -DWITH_COVERAGE=On ..
make -j
```

`-DSANITIZE_ADDRESS=On -DSANITIZE_UNDEFINED=On` are optional to pass to the cmake invocation. Including is a good idea to find more potential bugs, but if you don't have sanitizer libraries in stalled in your computer you can simply discard those optional features.

## Run tests
```bash
# From within the build directory created before
ctest
# or make test
```

## Coverage output
```bash
# From within the build directory created before
# Don't use ninja when configuring cmake if you want to run this command
make coverage
# Assuming you have google chrome installed on a linux host machine
google-chrome coverage/index.html  # To see the coverage html output
```

## Future work
Run this in a CI environment such as Travis. Pass the result and coverage output as banners in the repository.
