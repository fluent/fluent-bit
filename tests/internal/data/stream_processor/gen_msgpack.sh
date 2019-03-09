#!/bin/sh

echo "=== Just hit ctrl-c after 2 seconds... ==="
echo

# Delete old samples file
rm -rf samples.mp

# Generate new msgpack file using as a source samples.json
../../../../build/bin/fluent-bit -R ../../../../conf/parsers.conf \
 -i tail -p path=samples.json -p parser=json \
 -o file -p format=msgpack -p path=samples.mp -f 1

