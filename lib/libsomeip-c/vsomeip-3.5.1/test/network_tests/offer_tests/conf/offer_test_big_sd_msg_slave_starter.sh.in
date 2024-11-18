#!/bin/bash
# Copyright (C) 2015-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

FAIL=0
# Rejecting offer for which there is already a remote offer:
# * start daemon
# * start application which offers service
# * start daemon remotely
# * start same application which offers the same service again remotely
#   -> should be rejected as there is already a service instance
#   running in the network

export VSOMEIP_CONFIGURATION=offer_test_big_sd_msg_slave.json
# start daemon
../../../examples/routingmanagerd/routingmanagerd &
PID_VSOMEIPD=$!
sleep 1
# Start the services
./offer_test_big_sd_msg_service &
PID_SERVICE_TWO=$!
sleep 1

# Wait until all clients and services are finished
for job in $PID_SERVICE_TWO
do
    # Fail gets incremented if a client exits with a non-zero exit code
    wait $job || FAIL=$(($FAIL+1))
done

# kill the services
kill $PID_VSOMEIPD
sleep 1



# Check if everything went well
if [ $FAIL -eq 0 ]
then
    exit 0
else
    exit 1
fi
