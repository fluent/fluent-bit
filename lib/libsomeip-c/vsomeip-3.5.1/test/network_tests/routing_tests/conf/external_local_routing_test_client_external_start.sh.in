#!/bin/bash -ex
# Copyright (C) 2015-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

export VSOMEIP_APPLICATION_NAME=external_local_routing_test_client_external
export VSOMEIP_CONFIGURATION=external_local_routing_test_client_external.json
./local_routing_test_client &
client=$!

for _ in {1..100}
do
    find /tmp -ls
    lsof -nw -p "$client" || continue
done
wait "$client"
