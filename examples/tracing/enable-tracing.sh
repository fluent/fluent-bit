#!/bin/bash
set -eu

if command -v http; then
    http -v 127.0.0.1:2020/api/v1/trace input=dummy.0 output=stdout prefix=trace. enable:=true params:='{"format":"json"}'
elif command -v curl; then
    curl --header 'Content-Type: application/json' --data '{"enable":true, "input": "dummy.0", "output": "stdout", "params": { "format": "json" }, "prefix": "trace."}' '127.0.0.1:2020/api/v1/trace'
else
    echo "No curl or httpie installed"
    exit 1
fi
