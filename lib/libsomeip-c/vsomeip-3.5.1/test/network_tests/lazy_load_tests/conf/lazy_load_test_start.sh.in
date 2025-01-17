#!/bin/bash
# Copyright (C) 2015-2018 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Purpose: This script is needed to start the services with
# one command. This is necessary as ctest - which is used to run the
# tests - isn't able to start multiple binaries for one testcase. Therefore
# the testcase simply executes this script. This script then runs the services
# and checks that all exit successfully.

export VSOMEIP_CONFIGURATION=/vsomeip/
export VSOMEIP_APPLICATION_NAME=routingmanagerd
# start daemon
../../../examples/routingmanagerd/routingmanagerd &
PID_VSOMEIPD=$!

sleep 1

export VSOMEIP_APPLICATION_NAME=service-sample
./lazy_load_test_service &

sleep 1

export VSOMEIP_CONFIGURATION=lazy_load_test_service_config.json
export VSOMEIP_APPLICATION_NAME=client-sample_normal
./lazy_load_test_client &

sleep 2

export VSOMEIP_CONFIGURATION=/vsomeip/
export VSOMEIP_APPLICATION_NAME=client-sample-lazy
# start lazy client with linux user id 1 and group id 1 to use the 1_1 folder in extensions
setpriv --reuid=1 --regid=1 --clear-groups ./lazy_load_test_lazy_client

sleep 1

kill $PID_VSOMEIPD
wait $PID_VSOMEIPD
