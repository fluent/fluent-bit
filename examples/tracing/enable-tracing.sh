#!/bin/bash
set -eu

REMOTE_HOST=${REMOTE_HOST:-127.0.0.1}

if command -v http &> /dev/null ; then
    http -v "$REMOTE_HOST":2020/api/v1/trace/dummy.0 output=stdout prefix=trace. params:='{"format":"json"}'
elif command -v curl &> /dev/null ; then
    curl --header 'Content-Type: application/json' --data '{"output": "stdout", "params": { "format": "json" }, "prefix": "trace."}' "$REMOTE_HOST":2020/api/v1/trace/dummy.0
else
    echo "No curl or httpie installed"
    if command -v apt-get &> /dev/null ; then
        apt-get -qq update
        apt-get -qq install -y curl
    elif command -v yum &> /dev/null ; then
        yum install -y curl
    else
        exit 1
    fi
    curl --header 'Content-Type: application/json' --data '{"output": "stdout", "params": { "format": "json" }, "prefix": "trace."}' "$REMOTE_HOST":2020/api/v1/trace/dummy.0
fi
