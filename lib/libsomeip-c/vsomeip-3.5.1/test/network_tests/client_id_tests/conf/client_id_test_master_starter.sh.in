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

if [ $# -lt 1 ]
then
    echo "Please pass a json file to this script."
    echo "For example: $0 client_id_test_diff_client_ids_diff_ports_master.json"
    exit 1
fi

MASTER_JSON_FILE=$1
CLIENT_JSON_FILE=${MASTER_JSON_FILE/master/slave}

FAIL=0

# Start the services
export VSOMEIP_APPLICATION_NAME=client_id_test_service_one
export VSOMEIP_CONFIGURATION=$1
./client_id_test_service 1 &
CLIENT_ID_PIDS[1]=$!

export VSOMEIP_APPLICATION_NAME=client_id_test_service_two
export VSOMEIP_CONFIGURATION=$1
./client_id_test_service 2 &
CLIENT_ID_PIDS[2]=$!

export VSOMEIP_APPLICATION_NAME=client_id_test_service_three
export VSOMEIP_CONFIGURATION=$1
./client_id_test_service 3 &
CLIENT_ID_PIDS[3]=$!

sleep 1

if [ ! -z "$USE_LXC_TEST" ]; then
    echo "starting client id test on slave LXC"
    ssh  -tt -i $SANDBOX_ROOT_DIR/commonapi_main/lxc-config/.ssh/mgc_lxc/rsa_key_file.pub -o StrictHostKeyChecking=no root@$LXC_TEST_SLAVE_IP "bash -ci \"set -m; cd \\\$SANDBOX_TARGET_DIR/vsomeip_lib/test/network_tests/client_id_tests; ./client_id_test_slave_starter.sh $CLIENT_JSON_FILE\"" &
elif [ ! -z "$USE_DOCKER" ]; then
    docker exec $DOCKER_IMAGE sh -c "cd $DOCKER_TESTS && ./client_id_test_slave_starter.sh $CLIENT_JSON_FILE" &
else
cat <<End-of-message
*******************************************************************************
*******************************************************************************
** Please now run:
** client_id_test_slave_starter.sh $CLIENT_JSON_FILE
** from an external host to successfully complete this test.
**
** You probably will need to adapt the 'unicast' settings in
** client_id_test_diff_client_ids_diff_ports_master.json and
** client_id_test_diff_client_ids_diff_ports_slave.json to your personal setup.
*******************************************************************************
*******************************************************************************
End-of-message
fi

# Wait until client and service are finished
for client_pid in "${CLIENT_ID_PIDS[@]}"
do
    if [ -n "$client_pid" ]; then
        # Fail gets incremented if either client or service exit
        # with a non-zero exit code
        wait "$client_pid" || ((FAIL+=1))
    fi
done

# Check if both exited successfully
if [ $FAIL -eq 0 ]
then
    exit 0
else
    exit 1
fi
