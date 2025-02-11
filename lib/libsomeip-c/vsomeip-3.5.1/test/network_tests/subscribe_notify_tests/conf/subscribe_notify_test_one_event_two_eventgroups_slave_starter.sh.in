#!/bin/bash
# Copyright (C) 2015-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Purpose: This script is needed to start the services with
# one command. This is necessary as ctest - which is used to run the
# tests - isn't able to start multiple binaries for one testcase. Therefore
# the testcase simply executes this script. This script then runs the services
# and checks that all exit successfully.

if [ $# -lt 2 ]; then
    echo "Please pass a json file and a subscription type to this script."
    echo "Valid subscription types include:"
    echo "            [UDP, TCP]"
    echo "For example: $0 UDP subscribe_notify_test_one_event_two_eventgroups_udp_slave.json"
    exit 1
fi

FAIL=0

export VSOMEIP_CONFIGURATION=$2
# start daemon
../../../examples/routingmanagerd/routingmanagerd &
PID_VSOMEIPD=$!

# Start the services
./subscribe_notify_test_one_event_two_eventgroups_service $1 &
PID_SERVICE=$!

# wait until service exits successfully
wait $PID_SERVICE || FAIL=$(($FAIL+1))


# kill daemon
kill $PID_VSOMEIPD
wait $PID_VSOMEIPD || FAIL=$(($FAIL+1))

echo ""

# Check if both exited successfully
if [ $FAIL -eq 0 ]; then
    exit 0
else
    exit 1
fi
