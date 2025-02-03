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

if [ $# -lt 2 ]; then
    echo "Please pass a json file and a subscription type to this script."
    echo "Valid subscription types include:"
    echo "            [UDP, TCP]"
    echo "For example: $0 UDP subscribe_notify_test_one_event_two_eventgroups_master.json"
    exit 1
fi

# replace master with slave to be able display the correct json file to be used
# with the slave script
RELIABILITY_TYPE=$1
MASTER_JSON_FILE=$2
if [ $1 == "UDP" ]; then
    SLAVE_JSON_FILE=${MASTER_JSON_FILE/master/udp_slave}
elif [ $1 == "TCP" ]; then
    SLAVE_JSON_FILE=${MASTER_JSON_FILE/master/tcp_slave}
fi

FAIL=0

export VSOMEIP_CONFIGURATION=$2
# start daemon
../../../examples/routingmanagerd/routingmanagerd &
PID_VSOMEIPD=$!

# Start the client
./subscribe_notify_test_one_event_two_eventgroups_client $1 &
PID_CLIENT=$!
sleep 1

if [ ! -z "$USE_LXC_TEST" ]; then
    echo "starting subscribe_notify_test_slave_starter.sh on slave LXC with parameters $SLAVE_JSON_FILE"
    ssh -tt -i $SANDBOX_ROOT_DIR/commonapi_main/lxc-config/.ssh/mgc_lxc/rsa_key_file.pub -o StrictHostKeyChecking=no root@$LXC_TEST_SLAVE_IP "bash -ci \"set -m; cd \\\$SANDBOX_TARGET_DIR/vsomeip_lib/test/network_tests/subscribe_notify_tests; ./subscribe_notify_test_one_event_two_eventgroups_slave_starter.sh $RELIABILITY_TYPE $SLAVE_JSON_FILE\"" &
    echo "remote ssh job id: $!"
elif [ ! -z "$USE_DOCKER" ]; then
    docker exec $DOCKER_IMAGE sh -c "cd $DOCKER_TESTS && ./subscribe_notify_test_one_event_two_eventgroups_slave_starter.sh $RELIABILITY_TYPE $SLAVE_JSON_FILE" &
else
    cat <<End-of-message
*******************************************************************************
*******************************************************************************
** Please now run:
** subscribe_notify_test_one_event_two_eventgroups_slave_starter.sh $RELIABILITY_TYPE $SLAVE_JSON_FILE
** from an external host to successfully complete this test.
**
** You probably will need to adapt the 'unicast' settings in
** subscribe_notify_test_diff_client_ids_diff_ports_master.json and
** subscribe_notify_test_diff_client_ids_diff_ports_slave.json to your personal setup.
*******************************************************************************
*******************************************************************************
End-of-message
fi

if [ ! -z "$USE_DOCKER" ]; then
  FAIL=0
fi

# wait until client exits successfully
wait $PID_CLIENT || FAIL=$(($FAIL+1))


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
