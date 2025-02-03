#!/bin/bash
# Copyright (C) 2015-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Purpose: This script is needed to start the services with
# one command. This is necessary as ctest - which is used to run the
# tests - isn't able to start multiple binaries for one testcase. Therefore
# the testcase simply executes this script. This script then runs the services
# and checks that all exit successfully.

FAIL=0

# Start the services
export VSOMEIP_APPLICATION_NAME=service-sample
export VSOMEIP_CONFIGURATION=climate_test_master.json
./climate_test_service &

sleep 1

if [ ! -z "$USE_LXC_TEST" ]; then
    echo "starting climate_test_slave_starter.sh on slave LXC with parameters"
    ssh -tt -i $SANDBOX_ROOT_DIR/commonapi_main/lxc-config/.ssh/mgc_lxc/rsa_key_file.pub -o StrictHostKeyChecking=no root@$LXC_TEST_SLAVE_IP "bash -ci \"set -m; cd \\\$SANDBOX_TARGET_DIR/vsomeip_lib/test/network_tests/regression_tests; ./climate_test_slave_starter.sh \"" &
    echo "remote ssh job id: $!"
elif [ ! -z "$USE_DOCKER" ]; then
    docker exec $DOCKER_IMAGE sh -c "cd $DOCKER_TESTS && ./climate_test_slave_starter.sh" &
else
    cat <<End-of-message
*******************************************************************************
*******************************************************************************
** Please now run:
** climate_test_slave_starter.sh
** from an external host to successfully complete this test.
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
