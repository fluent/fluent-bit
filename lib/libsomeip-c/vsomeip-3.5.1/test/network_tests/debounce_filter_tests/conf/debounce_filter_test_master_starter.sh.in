#!/bin/bash
# Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

FAIL=0

export VSOMEIP_CONFIGURATION=debounce_filter_test_client.json
../../../examples/routingmanagerd/routingmanagerd &
PID_VSOMEIPD=$!

sleep 1

./debounce_filter_test_client &
PID_MASTER=$!

sleep 1

if [ ! -z "$USE_LXC_TEST" ]; then
    echo "starting debounce_filter test on slave LXC debounce_filter_test_slave_starter.sh"
    ssh -tt -i $SANDBOX_ROOT_DIR/commonapi_main/lxc-config/.ssh/mgc_lxc/rsa_key_file.pub -o StrictHostKeyChecking=no root@$LXC_TEST_SLAVE_IP "bash -ci \"set -m; cd \\\$SANDBOX_TARGET_DIR/vsomeip_lib/test/network_tests/debounce_filter_tests; ./debounce_filter_test_slave_starter.sh\"" &
elif [ ! -z "$USE_DOCKER" ]; then
    docker exec $DOCKER_IMAGE sh -c "cd $DOCKER_TESTS; sleep 10; ./debounce_filter_test_slave_starter.sh" &
else
cat <<End-of-message
*******************************************************************************
*******************************************************************************
** Please now run:
** debounce_filter_test_slave_starter.sh
** from an external host to successfully complete this test.
**
** You probably will need to adapt the 'unicast' settings in
** debounce_filter_test_slave.json to your personal setup.
*******************************************************************************
*******************************************************************************
End-of-message
fi

# Wait until all slaves are finished
for job in $PID_MASTER
do
    # Fail gets incremented if a client exits with a non-zero exit code
    echo "waiting for $job"
    wait $job || FAIL=$(($FAIL+1))
done

kill $PID_VSOMEIPD
sleep 3

# Check if everything went well
exit $FAIL
