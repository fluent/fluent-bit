#!/bin/bash

set -e

cd tests
export TEST_CONSUMER_GROUP_PROTOCOL=classic
./test-runner.exe -l -Q -p1
export TEST_CONSUMER_GROUP_PROTOCOL=consumer
./test-runner.exe -l -Q -p1 
