#!/bin/bash
# Copyright (C) 2015-2018 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

FAIL=0

if [ $# -lt 1 ]
then
    echo "Please pass a operation and communication mode to this script."
    echo "For example: $0 UDP"
    echo "Valid communication modes include [UDP, TCP]"
    exit 1
fi
COMMUNICATIONMODE=$1

if [ "$COMMUNICATIONMODE" = "TCP" ]; then
    export VSOMEIP_CONFIGURATION=event_test_slave_tcp.json
elif [ "$COMMUNICATIONMODE" = "UDP" ]; then
    export VSOMEIP_CONFIGURATION=event_test_slave_udp.json
fi

../../../examples/routingmanagerd/routingmanagerd &
PID_VSOMEIPD=$!

./event_test_service $COMMUNICATIONMODE &
PID_SERVICE=$!

# Wait until all clients and services are finished
for job in $PID_SERVICE
do
    # Fail gets incremented if a client exits with a non-zero exit code
    echo "waiting for $job"
    wait $job || FAIL=$(($FAIL+1))
done

# kill the services
kill $PID_VSOMEIPD
sleep 1

# Check if everything went well
exit $FAIL
