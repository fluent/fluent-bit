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
    echo "Please pass a json file and event reliability type to this script."
    echo "For example: $0 UDP subscribe_notify_test_diff_client_ids_diff_ports_master.json"
    echo "To use the same service id but different instances on the node pass SAME_SERVICE_ID as third parameter"
    exit 1
fi

# replace master with slave to be able display the correct json file to be used
# with the slave script
RELIABILITY_TYPE=$1
MASTER_JSON_FILE=$2
SAME_SERVICE_ID=$3
CLIENT_JSON_FILE=${MASTER_JSON_FILE/master/slave}

FAIL=0

# Start the services
export VSOMEIP_APPLICATION_NAME=subscribe_notify_test_service_one
export VSOMEIP_CONFIGURATION=$MASTER_JSON_FILE
./subscribe_notify_test_service 1 $RELIABILITY_TYPE $3 &

export VSOMEIP_APPLICATION_NAME=subscribe_notify_test_service_two
export VSOMEIP_CONFIGURATION=$MASTER_JSON_FILE
./subscribe_notify_test_service 2 $RELIABILITY_TYPE $3 &

export VSOMEIP_APPLICATION_NAME=subscribe_notify_test_service_three
export VSOMEIP_CONFIGURATION=$MASTER_JSON_FILE
./subscribe_notify_test_service 3 $RELIABILITY_TYPE $3 &

sleep 3

if [ ! -z "$USE_LXC_TEST" ]; then
    echo "starting subscribe_notify_test_slave_starter.sh on slave LXC with parameters $CLIENT_JSON_FILE $2"
    ssh -tt -i $SANDBOX_ROOT_DIR/commonapi_main/lxc-config/.ssh/mgc_lxc/rsa_key_file.pub -o StrictHostKeyChecking=no root@$LXC_TEST_SLAVE_IP "bash -ci \"set -m; cd \\\$SANDBOX_TARGET_DIR/vsomeip_lib/test/network_tests/subscribe_notify_tests; ./subscribe_notify_test_slave_starter.sh $RELIABILITY_TYPE $CLIENT_JSON_FILE $3\"" &
    echo "remote ssh job id: $!"
elif [ ! -z "$USE_DOCKER" ]; then
    docker exec $DOCKER_IMAGE sh -c "cd $DOCKER_TESTS && ./subscribe_notify_test_slave_starter.sh $RELIABILITY_TYPE $CLIENT_JSON_FILE $3" &
else
    cat <<End-of-message
*******************************************************************************
*******************************************************************************
** Please now run:
** subscribe_notify_test_slave_starter.sh $RELIABILITY_TYPE $CLIENT_JSON_FILE $3
** from an external host to successfully complete this test.
**
** You probably will need to adapt the 'unicast' settings in
** $MASTER_JSON_FILE and
** $CLIENT_JSON_FILE to your personal setup.
*******************************************************************************
*******************************************************************************
End-of-message
fi

if [ ! -z "$USE_DOCKER" ]; then
  FAIL=0
fi

# Wait until client and service are finished
for job in $(jobs -p)
do
    # Fail gets incremented if either client or service exit
    # with a non-zero exit code
    wait $job || ((FAIL+=1))
done

# Check if both exited successfully
if [ $FAIL -eq 0 ]
then
    exit 0
else
    exit 1
fi
