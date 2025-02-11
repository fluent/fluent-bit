#!/bin/bash
# Copyright (C) 2015-2019 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

FAIL=0

if [ $# -lt 2 ]
then
    echo "Please pass a operation and communication mode to this script."
    echo "For example: $0 SERVICE UDP"
    echo "Valid operation modes include [SERVICE, CLIENT]"
    echo "Valid communication modes include [UDP, TCP]"
    exit 1
fi

OPERATIONMODE=$1
COMMUNICATIONMODE=$2

if [ "$OPERATIONMODE" = "SERVICE" ]; then
    MASTER_APPLICATION=second_address_test_service
    SLAVE_OPERATIONMODE="CLIENT"

    if [ "$COMMUNICATIONMODE" = "TCP" ]; then
        export VSOMEIP_CONFIGURATION=second_address_test_master_service_tcp.json
    elif [ "$COMMUNICATIONMODE" = "UDP" ]; then
        export VSOMEIP_CONFIGURATION=second_address_test_master_service_udp.json
    fi

elif [ "$OPERATIONMODE" = "CLIENT" ]; then
    MASTER_APPLICATION=second_address_test_client
    SLAVE_OPERATIONMODE="SERVICE"
    export VSOMEIP_CONFIGURATION=second_address_test_master_client.json
fi

rm -f /tmp/vsomeip*

../../../examples/routingmanagerd/routingmanagerd &
PID_VSOMEIPD=$!

./$MASTER_APPLICATION $COMMUNICATIONMODE &
PID_MASTER=$!

sleep 1

if [ ! -z "$USE_LXC_TEST" ]; then
    echo "starting offer test on slave LXC second_address_test_slave_starter.sh"
    ssh -tt -i $SANDBOX_ROOT_DIR/commonapi_main/lxc-config/.ssh/mgc_lxc/rsa_key_file.pub -o StrictHostKeyChecking=no root@$LXC_TEST_SLAVE_IP "bash -ci \"set -m; cd \\\$SANDBOX_TARGET_DIR/vsomeip_lib/test/network_tests/second_address_tests; ./second_address_test_slave_starter.sh $SLAVE_OPERATIONMODE $COMMUNICATIONMODE\"" &
elif [ ! -z "$USE_DOCKER" ]; then
    docker exec $DOCKER_IMAGE sh -c "cd $DOCKER_TESTS; sleep 10; ./second_address_test_slave_starter.sh $SLAVE_OPERATIONMODE $COMMUNICATIONMODE" &
else
cat <<End-of-message
*******************************************************************************
*******************************************************************************
** Please now run:
** second_address_test_slave_starter.sh $COMMUNICATIONMODE
** from an external host to successfully complete this test.
**
** You probably will need to adapt the 'unicast' settings in
** second_address_test_slave_{udp,tcp}.json to your personal setup.
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
sleep 1

# Check if everything went well
exit $FAIL
