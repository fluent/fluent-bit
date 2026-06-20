#!/bin/sh

echo "=== Hit ctrl-c if it runs forever!... ==="
echo

# Delete old samples file
rm -rf samples.mp samples-subkeys.mp

# Generate new msgpack file using as a source samples.json
../../../../build/bin/fluent-bit -R ../../../../conf/parsers.conf              \
 -i tail -t samples         -p path=samples.json          -p parser=json       \
 -i tail -t samples-subkeys -p path=samples-subkeys.json  -p parser=json       \
 -o file -m samples         -p format=msgpack  -p file=samples.mp              \
 -o file -m samples-subkeys -p format=msgpack  -p file=samples-subkeys.mp -f 1 &
 pid=$!
 sleep 2
 kill -9 $pid

 # Generate new msgpack files for hopping window
 files=$(find "samples-hw/" -type f -name "*.mp" | sort)

 for file in $files
 do
     rm -f $file
 done

 files=$(find "samples-hw/" -type f -name "*.json" | sort)

 for file in $files
 do
     # Generate new msgpack files for hopping window
     echo ""
     echo "=== Generating MessagePack file for $file ... ==="
     ../../../../build/bin/fluent-bit -R ../../../../conf/parsers.conf   \
      -i tail -p path=$file  -p parser=json                              \
      -o file -p format=msgpack -p file=$(echo $file | sed s/json/mp/) -f 1 &
      pid=$!
      sleep 2
      kill -9 $pid
 done
