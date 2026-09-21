# Integration tests written in Java

The high-level idea is following:

- start a logging destination
- start a fresh Fluent-Bit process
- send log messages to Fluent-Bit
- verify that everything arrives at the logging destination

The tests defined in the IntegrationTest.java file do exactly that. The other classes implement the logging destination and the application which
sends messages to Fluent-Bit.

The implementation tries to catch all kind of errors, but it won't handle them. It fails the test.

## Implementation

This project is built with Java 11 and Maven (a popular Java build tool).

## How to run the tests

### Option 1 - you got Java 11, Maven and Docker installed

To run all the tests

```
 mvn clean test
```

To run a specific test method, replace `mvn clean test` with `mvn "-Dtest=IntegrationTest#happyPathOneMessage" clean test`.

This runs fluent-bit in docker, it uses `fluent/fluent-bit:latest`. You can change that by setting the environment variable `FLUENTBIT_DOCKER_IMAGE`,
see `Config.java` for this and other options.

### Option 2 - you build fluent-bit locally and you got Docker installed

`./run_local_build.sh`

This uses a Maven docker container, mounts your locally build fluent-bit executable from `<REPO ROOT>/build/bin/fluent-bit`
into the container and uses that.

You can set environment variable to configure the build further, see `Config.java`.

NOTE: This caches the Java libraries under `$HOME/.m2`.
