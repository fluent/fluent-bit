#!/bin/bash
# Copyright (C) 2015-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Purpose: This script is needed to start the client and service with
# one command. This is necessary as ctest - which is used to run the
# tests - isn't able to start two binaries for one testcase. Therefore
# the testcase simply executes this script. This script then runs client
# and service and checks that both exit successfully.

# Display a message to show the user that he must now call the external service
# to finish the test successfully

FAIL=0

if [ ! -z "$USE_LXC_TEST" ]; then
    echo "starting magic cookies test on slave LXC"
    ssh -tt -i $SANDBOX_ROOT_DIR/commonapi_main/lxc-config/.ssh/mgc_lxc/rsa_key_file.pub -o StrictHostKeyChecking=no root@$LXC_TEST_SLAVE_IP "bash -ci \"set -m; cd \\\$SANDBOX_TARGET_DIR/vsomeip_lib/test/network_tests/magic_cookies_tests; ./magic_cookies_test_client_start.sh\"" &
elif [ ! -z "$USE_DOCKER" ]; then
    docker exec $DOCKER_IMAGE sh -c "cd $DOCKER_TESTS && ./magic_cookies_test_client_start.sh" &
else
cat <<End-of-message
*******************************************************************************
*******************************************************************************
** Please now run:
** magic_cookies_test_client_start.sh
** from an external host to successfully complete this test.
**
** You probably will need to adapt the 'unicast' settings in
** magic_cookies_client.json and
** magic_cookies_service.json to your personal setup.
**
*******************************************************************************
*******************************************************************************
End-of-message
fi

# Start the client for magic-cookies test
export VSOMEIP_APPLICATION_NAME=magic_cookies_test_service
export VSOMEIP_CONFIGURATION=magic_cookies_test_service.json
./magic_cookies_test_service  --tcp --static-routing &

# Wait until client and service are finished
for job in $(jobs -p)
do
    # Fail gets incremented if either client or service exit
    # with a non-zero exit code
    wait $job || ((FAIL+=1))
done

# Check if client and server both exited successfully
if [ $FAIL -eq 0 ]
then
    exit 0
else
    exit 1
fi
