#!/bin/bash
# Copyright (C) 2015-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

export VSOMEIP_CONFIGURATION=security_test_local_config.json

export VSOMEIP_APPLICATION_NAME=routingmanagerd
# start daemon
../../../examples/routingmanagerd/routingmanagerd &
PID_VSOMEIPD=$!

sleep 1

export VSOMEIP_APPLICATION_NAME=service-sample
./security_test_service --local &

sleep 1

export VSOMEIP_APPLICATION_NAME=client-sample
./security_test_client --local

kill $PID_VSOMEIPD
sleep 1
