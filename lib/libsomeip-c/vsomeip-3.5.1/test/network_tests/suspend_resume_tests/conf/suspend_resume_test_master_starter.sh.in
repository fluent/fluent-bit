#!/bin/bash
# Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Purpose: This script is needed to start the services with
# one command. This is necessary as ctest - which is used to run the
# tests - isn't able to start multiple binaries for one testcase. Therefore
# the testcase simply executes this script. This script then runs the services
# and checks that all exit successfully.

FAIL=0

# Start the service
export VSOMEIP_APPLICATION_NAME=suspend_resume_test_service
export VSOMEIP_CONFIGURATION=suspend_resume_test_service.json

# start daemon
echo -e "[TEST-sh]: Starting RoutingManager"
../../../examples/routingmanagerd/routingmanagerd &
PID_VSOMEIPD=$!

# start the service
echo -e "\n\n[TEST-sh]: Started RoutingManager with PID=$PID_VSOMEIPD"
./suspend_resume_test_service $PID_VSOMEIPD &
PID_SERVICE=$!

echo -e "\n\n[TEST-sh]: Started Service with PID=$PID_SERVICE \n\n"
sleep 1

if [ ! -z "$USE_LXC_TEST" ]; then
    echo "starting suspend_resume_test_slave_starter.sh on slave LXC with parameters $SLAVE_JSON_FILE"
    ssh -tt -i $SANDBOX_ROOT_DIR/commonapi_main/lxc-config/.ssh/mgc_lxc/rsa_key_file.pub -o StrictHostKeyChecking=no root@$LXC_TEST_SLAVE_IP "bash -ci \"set -m; cd \\\$SANDBOX_TARGET_DIR/vsomeip_lib/test/network_tests/suspend_resume_tests; ./suspend_resume_test_slave_starter.sh\"" &
    echo "remote ssh job id: $!"
elif [ ! -z "$USE_DOCKER" ]; then
    docker exec $DOCKER_IMAGE sh -c "cd $DOCKER_TESTS && ./suspend_resume_test_slave_starter.sh" &
else
    cat <<End-of-message
*******************************************************************************
*******************************************************************************
** Please now run:
** suspend_resume_test_slave_starter.sh
** from an external host to successfully complete this test.
**
** You probably will need to adapt the 'unicast' settings in
** suspend_resume_test_service.json and
** suspend_resume_test_client.json to your personal setup.
*******************************************************************************
*******************************************************************************
End-of-message
fi

if [ ! -z "$USE_DOCKER" ]; then
  FAIL=0
fi

# wait until client exits successfully
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