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
    echo "For example: $0 security_test_config_client_external_allow.json --allow"
    exit 1
fi

MASTER_JSON_FILE=$1
SERVICE_JSON_FILE=${MASTER_JSON_FILE/client/service}
ALLOW_DENY=$2

FAIL=0

export VSOMEIP_CONFIGURATION=$1
export VSOMEIP_APPLICATION_NAME=routingmanagerd
# start daemon
../../../examples/routingmanagerd/routingmanagerd &
PID_VSOMEIPD=$!

export VSOMEIP_CONFIGURATION=$1
export VSOMEIP_APPLICATION_NAME=client-sample
./security_test_client --remote $2 &
PID_CLIENT=$!


if [ ! -z "$USE_LXC_TEST" ]; then
    echo "starting external security test on slave LXC"
    ssh  -tt -i $SANDBOX_ROOT_DIR/commonapi_main/lxc-config/.ssh/mgc_lxc/rsa_key_file.pub -o StrictHostKeyChecking=no root@$LXC_TEST_SLAVE_IP "bash -ci \"set -m; cd \\\$SANDBOX_TARGET_DIR/vsomeip_lib/test/network_tests/security_tests; ./security_test_external_slave_start.sh $SERVICE_JSON_FILE $2\"" &
elif [ ! -z "$USE_DOCKER" ]; then
    docker exec $DOCKER_IMAGE sh -c "cd $DOCKER_TESTS && ./security_test_external_slave_start.sh $SERVICE_JSON_FILE $2" &
else
cat <<End-of-message
*******************************************************************************
*******************************************************************************
** Please now run:
** security_test_external_slave_start.sh $SERVICE_JSON_FILE $2
** from an external host to successfully complete this test.
**
** You probably will need to adapt the 'unicast' settings in
** security_test_config_service_external_allow.json and
** security_test_config_client_external_allow.json to your personal setup.
*******************************************************************************
*******************************************************************************
End-of-message
fi

# Wait until client and service are finished
for client_pid in "${PID_CLIENT}"
do
    if [ -n "$client_pid" ]; then
        # Fail gets incremented if either client or service exit
        # with a non-zero exit code
        wait "$client_pid" || ((FAIL+=1))
    fi
done

kill $PID_VSOMEIPD
kill $PID_CLIENT

# Check if both exited successfully
if [ $FAIL -eq 0 ]
then
    exit 0
else
    exit 1
fi
