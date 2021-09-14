#!/bin/bash
set -ueo pipefail

SCRIPT_ROOT="$(cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd)"
cd "$SCRIPT_ROOT"

docker run \
 -it \
 --rm \
 -e FLUENTBIT_COMMAND="/fluent-bit -c /usr/src/mymaven/src/test/resources/fluentbit.conf" \
 -e MAVEN_CONFIG=/var/maven/.m2 \
 -u "$(id -u):$(id -g)" \
 -v "$SCRIPT_ROOT/../../../build/bin/fluent-bit":/fluent-bit \
 -v "$SCRIPT_ROOT":/usr/src/mymaven \
 -v "$HOME/.m2:/var/maven/.m2" \
 -w /usr/src/mymaven maven:3.8-jdk-11 \
 mvn -Duser.home=/var/maven clean test
