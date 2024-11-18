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

if [ $# -lt 2 ]
then
    echo "Please pass a json file to this script and wether remote clients are allowed or not "
    echo "For example: $0 security_test_config_service_external_allow.json --allow"
    exit 1
fi

CLIENT_JSON_FILE=$1
ALLOW_DENY=$2

FAIL=0

export VSOMEIP_CONFIGURATION=$1
export VSOMEIP_APPLICATION_NAME=routingmanagerd
# start daemon
../../../examples/routingmanagerd/routingmanagerd &
PID_VSOMEIPD=$!

export VSOMEIP_CONFIGURATION=$1
export VSOMEIP_APPLICATION_NAME=service-sample
./security_test_service --remote $2 &
PID_SERVICE=$!

# Wait until client and service are finished
for client_pid in "${PID_SERVICE}"
do
    if [ -n "$client_pid" ]; then
        # Fail gets incremented if either client or service exit
        # with a non-zero exit code
        wait "$client_pid" || ((FAIL+=1))
    fi
done

kill $PID_VSOMEIPD
kill $PID_SERVICE

# Check if both exited successfully
if [ $FAIL -eq 0 ]
then
    exit 0
else
    exit 1
fi
