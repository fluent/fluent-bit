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

export VSOMEIP_CONFIGURATION=cpu_load_test_client_master.json
./cpu_load_test_client --protocol UDP --calls 1000 &
TEST_CLIENT_PID=$!
sleep 1

if [ ! -z "$USE_LXC_TEST" ]; then
    echo "starting cpu load test on slave LXC"
    ssh  -tt -i $SANDBOX_ROOT_DIR/commonapi_main/lxc-config/.ssh/mgc_lxc/rsa_key_file.pub -o StrictHostKeyChecking=no root@$LXC_TEST_SLAVE_IP 'bash -ci "set -m; cd \$SANDBOX_TARGET_DIR/vsomeip_lib/test/network_tests/cpu_load_tests; ./cpu_load_test_slave_starter.sh"' &
elif [ ! -z "$USE_DOCKER" ]; then
    docker exec $DOCKER_IMAGE sh -c "cd $DOCKER_TESTS && ./cpu_load_test_slave_starter.sh" &
else
cat <<End-of-message
*******************************************************************************
*******************************************************************************
** Please now run:
** cpu_load_test_slave_starter.sh
** from an external host to successfully complete this test.
**
** You probably will need to adapt the 'unicast' settings in
** cpu_load_test_client_master.json,
** cpu_load_test_service_master.json,
** cpu_load_test_client_client.json and
** cpu_load_test_service_client.json to your personal setup.
*******************************************************************************
*******************************************************************************
End-of-message
fi

# Fail gets incremented if either client or service exit
# with a non-zero exit code
wait $TEST_CLIENT_PID || FAIL=$(($FAIL+1))


sleep 4
cat <<End-of-message
*******************************************************************************
*******************************************************************************
** Now switching roles and running service on this host (master)
*******************************************************************************
*******************************************************************************
End-of-message

export VSOMEIP_CONFIGURATION=cpu_load_test_service_master.json
./cpu_load_test_service &
sleep 1

# now we can wait to all jobs to finish
for job in $(jobs -p)
do
    # Fail gets incremented if either client or service exit
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
