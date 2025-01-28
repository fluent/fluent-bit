#!/bin/bash
# Copyright (C) 2015-2018 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

FAIL=0

if [ $# -lt 2 ]
then
    echo "Please pass a operation and communication mode to this script."
    echo "For example: $0 PAYLOAD_FIXED UDP"
    echo "Valid operation modes include [PAYLOAD_FIXED, PAYLOAD_DYNAMIC]"
    echo "Valid communication modes include [UDP, TCP]"
    exit 1
fi
TESTMODE=$1
COMMUNICATIONMODE=$2

export VSOMEIP_CONFIGURATION=event_test_master.json
../../../examples/routingmanagerd/routingmanagerd &
PID_VSOMEIPD=$!

./event_test_client $TESTMODE $COMMUNICATIONMODE &
PID_CLIENT=$!

sleep 1

if [ ! -z "$USE_LXC_TEST" ]; then
    echo "starting offer test on slave LXC offer_test_external_slave_starter.sh"
    ssh -tt -i $SANDBOX_ROOT_DIR/commonapi_main/lxc-config/.ssh/mgc_lxc/rsa_key_file.pub -o StrictHostKeyChecking=no root@$LXC_TEST_SLAVE_IP "bash -ci \"set -m; cd \\\$SANDBOX_TARGET_DIR/vsomeip_lib/test/network_tests/event_tests; ./event_test_slave_starter.sh $COMMUNICATIONMODE\"" &
elif [ ! -z "$USE_DOCKER" ]; then
    docker exec $DOCKER_IMAGE sh -c "cd $DOCKER_TESTS && sleep 10; ./event_test_slave_starter.sh $COMMUNICATIONMODE" &
else
cat <<End-of-message
*******************************************************************************
*******************************************************************************
** Please now run:
** event_test_slave_starter.sh $COMMUNICATIONMODE
** from an external host to successfully complete this test.
**
** You probably will need to adapt the 'unicast' settings in
** event_test_slave_{udp,tcp}.json to your personal setup.
*******************************************************************************
*******************************************************************************
End-of-message
fi

# Wait until all clients and services are finished
for job in $PID_CLIENT
do
    # Fail gets incremented if a client exits with a non-zero exit code
    echo "waiting for $job"
    wait $job || FAIL=$(($FAIL+1))
done

kill $PID_VSOMEIPD
sleep 1

# Check if everything went well
exit $FAIL
