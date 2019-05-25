#!/bin/sh

echo "=== Just hit ctrl-c after 2 seconds... ==="
echo

# Delete old samples file
rm -rf samples.mp samples-subkeys.mp

# Generate new msgpack file using as a source samples.json
../../../../build/bin/fluent-bit -R ../../../../conf/parsers.conf              \
 -i tail -t samples         -p path=samples.json          -p parser=json       \
 -i tail -t samples-subkeys -p path=samples-subkeys.json  -p parser=json       \
 -o file -m samples         -p format=msgpack  -p path=samples.mp              \
 -o file -m samples-subkeys -p format=msgpack  -p path=samples-subkeys.mp -f 1
