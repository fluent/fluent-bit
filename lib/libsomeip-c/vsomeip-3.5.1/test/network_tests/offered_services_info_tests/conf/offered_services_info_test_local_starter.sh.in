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

FAIL=0

cat <<End-of-message
*******************************************************************************
*******************************************************************************
** Running first test
*******************************************************************************
*******************************************************************************
End-of-message

# Rejecting offer of service instance whose hosting application is still
# alive:
# * start application which offers service
# * start two clients which continuously exchanges messages with the service
# * start application which offers the same service again -> should be
#   rejected and an error message should be printed.
# * Message exchange with client application should not be interrupted.

# Array for client pids
CLIENT_PIDS=()
export VSOMEIP_CONFIGURATION=offered_services_info_test_local.json
# Start the services (routingmanagerd as app name)
./offered_services_info_test_service 1 & #routingmanagerd as app name
PID_SERVICE_ONE=$!
./offered_services_info_test_client METHODCALL &
CLIENT_PIDS+=($!)

# Wait until all clients are finished
for job in ${CLIENT_PIDS[*]}
do
    # Fail gets incremented if a client exits with a non-zero exit code
    wait $job || FAIL=$(($FAIL+1))
done

# kill the services
kill $PID_SERVICE_ONE
sleep 1


# Check if everything went well
if [ $FAIL -eq 0 ]
then
    exit 0
else
    exit 1
fi
