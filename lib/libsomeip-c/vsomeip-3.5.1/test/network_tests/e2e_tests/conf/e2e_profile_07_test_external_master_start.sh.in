#!/bin/bash
# Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
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
    echo "Please pass a json file to this script"
    echo "For example: $0 e2e_profile_07_test_client_external.json"
    exit 1
fi

MASTER_JSON_FILE=$1
SERVICE_JSON_FILE=${MASTER_JSON_FILE/client/service}
ALLOW_DENY=$2

FAIL=0

export VSOMEIP_CONFIGURATION=$1
export VSOMEIP_APPLICATION_NAME=client-sample
./e2e_profile_07_test_client --remote &
PID_CLIENT=$!


if [ ! -z "$USE_LXC_TEST" ]; then
    echo "starting external e2e profile 07 test on slave LXC"
    ssh  -tt -i $SANDBOX_ROOT_DIR/commonapi_main/lxc-config/.ssh/mgc_lxc/rsa_key_file.pub -o StrictHostKeyChecking=no root@$LXC_TEST_SLAVE_IP "bash -ci \"set -m; cd \\\$SANDBOX_TARGET_DIR/vsomeip_lib/test/network_tests/e2e_tests; ./e2e_profile_07_test_external_slave_start.sh $SERVICE_JSON_FILE\"" &
elif [ ! -z "$USE_DOCKER" ]; then
    docker exec $DOCKER_IMAGE sh -c "cd $DOCKER_TESTS && ./e2e_profile_07_test_external_slave_start.sh $SERVICE_JSON_FILE" &
else
cat <<End-of-message
*******************************************************************************
*******************************************************************************
** Please now run:
** e2e_profile_07_test_external_slave_start.sh $SERVICE_JSON_FILE
** from an external host to successfully complete this test.
**
** You probably will need to adapt the 'unicast' settings in
** e2e_profile_07_test_service_external.json and
** e2e_profile_07_test_client_external.json to your personal setup.
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

kill $PID_CLIENT

# Check if both exited successfully
if [ $FAIL -eq 0 ]
then
    exit 0
else
    exit 1
fi
