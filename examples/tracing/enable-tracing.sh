#!/bin/bash
set -eu
REMOTE_HOST=${REMOTE_HOST:-127.0.0.1}
if command -v http; then
    http -v $REMOTE_HOST:2020/api/v1/trace input=dummy.0 output=stdout prefix=trace. enable:=true params:='{"format":"json"}'
elif command -v curl; then
    curl --header 'Content-Type: application/json' --data '{"enable":true, "input": "dummy.0", "output": "stdout", "params": { "format": "json" }, "prefix": "trace."}' "$REMOTE_HOST":2020/api/v1/trace
else
    echo "No curl or httpie installed"
    apt-get update
    apt-get install -y curl
    curl --header 'Content-Type: application/json' --data '{"enable":true, "input": "dummy.0", "output": "stdout", "params": { "format": "json" }, "prefix": "trace."}' "$REMOTE_HOST":2020/api/v1/trace
fi
