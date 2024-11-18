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

export VSOMEIP_CONFIGURATION=cpu_load_test_service_slave.json
./cpu_load_test_service &

# Wait until all applications are finished
for job in $(jobs -p)
do
    # Fail gets incremented if one of the binaries exits
    # with a non-zero exit code
    wait $job || FAIL=$(($FAIL+1))
done

cat <<End-of-message
*******************************************************************************
*******************************************************************************
** Now switching roles and running client on this host (slave)
*******************************************************************************
*******************************************************************************
End-of-message

sleep 4
export VSOMEIP_CONFIGURATION=cpu_load_test_client_slave.json
./cpu_load_test_client --protocol UDP --calls 1000 &

for job in $(jobs -p)
do
    # Fail gets incremented if one of the binaries exits
    # with a non-zero exit code
    wait $job || FAIL=$(($FAIL+1))
done


# Check if both exited successfully 
if [ $FAIL -eq 0 ]
then
    exit 0
else
    exit 1
fi
