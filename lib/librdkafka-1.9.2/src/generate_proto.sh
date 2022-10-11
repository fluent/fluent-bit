#!/bin/bash
#
# librdkafka - Apache Kafka C library
#
# Copyright (c) 2020 Magnus Edenhill
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


# Generate ApiKey / protocol request defines and rd_kafka_ApiKey2str() fields.
# Cut'n'paste as needed to rdkafka_protocol.h and rdkafka_proto.h
#
#
# Usage:
#   src/generate_proto.sh /path/to/apache-kafka-source

set -e

KAFKA_DIR="$1"

if [[ ! -d $KAFKA_DIR ]]; then
    echo "Usage: $0 <path-to-kafka-source-directory>"
    exit 1
fi

cd "$KAFKA_DIR"

echo "################## Protocol defines (add to rdkafka_protocol.h) ###################"
grep apiKey clients/src/main/resources/common/message/*Request.json | \
    awk '{print $3, $1 }' | \
    sort -n | \
    sed -E -s 's/ cli.*\///' | \
    sed -E 's/\.json:$//' | \
    awk -F, '{print "#define RD_KAFKAP_" $2 " " $1}'
echo "!! Don't forget to update RD_KAFKAP__NUM !!"
echo
echo

echo "################## Protocol names (add to rdkafka_proto.h) ###################"
grep apiKey clients/src/main/resources/common/message/*Request.json | \
    awk '{print $3, $1 }' | \
    sort -n | \
    sed -E -s 's/ cli.*\///' | \
    sed -E 's/\.json:$//' | \
    awk -F, '{print "[RD_KAFKAP_" $2 "] = \"" $2 "\","}'

