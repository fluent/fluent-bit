#!/bin/sh
# Copyright (C) 2015-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
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
    echo "Please pass a json file to this script."
    echo "For example: $0 initial_event_test_diff_client_ids_diff_ports_master.json"
    echo "To use the same service id but different instances on the node pass SAME_SERVICE_ID as third parameter"
    echo "To ensure the first client only subscribes to one event pass SUBSCRIBE_ONLY_ONE as third/fourth parameter"
    exit 1
fi

PASSED_JSON_FILE=$1
# Remove processed options from $@
shift 1
REMAINING_OPTIONS="$@"

print_starter_message () {

if [ ! -z "$USE_LXC_TEST" ]; then
    echo "starting initial event test on slave LXC with params $CLIENT_JSON_FILE $REMAINING_OPTIONS"
    ssh -tt -i $SANDBOX_ROOT_DIR/commonapi_main/lxc-config/.ssh/mgc_lxc/rsa_key_file.pub -o StrictHostKeyChecking=no root@$LXC_TEST_SLAVE_IP "bash -ci \"set -m; cd \\\$SANDBOX_TARGET_DIR/vsomeip_lib/test/network_tests; ./initial_event_test_slave_starter.sh $CLIENT_JSON_FILE $REMAINING_OPTIONS\"" &
elif [ ! -z "$USE_DOCKER" ]; then
    docker exec $DOCKER_IMAGE sh -c "cd $DOCKER_TESTS && ./initial_event_test_slave_starter.sh $CLIENT_JSON_FILE $REMAINING_OPTIONS" &
else
cat <<End-of-message
*******************************************************************************
*******************************************************************************
** Please now run:
** initial_event_test_slave_starter.sh $CLIENT_JSON_FILE $REMAINING_OPTIONS
** from an external host to successfully complete this test.
**
** You probably will need to adapt the 'unicast' settings in
** initial_event_test_diff_client_ids_diff_ports_master.json and
** initial_event_test_diff_client_ids_diff_ports_slave.json to your personal setup.
*******************************************************************************
*******************************************************************************
End-of-message
fi
}

# replace master with slave to be able display the correct json file to be used
# with the slave script
MASTER_JSON_FILE=$PASSED_JSON_FILE
CLIENT_JSON_FILE="<corresponding-slave-json-for-$MASTER_JSON_FILE>"

FAIL=0

# Start the services
export VSOMEIP_CONFIGURATION=$PASSED_JSON_FILE

export VSOMEIP_APPLICATION_NAME=initial_event_test_service_one
./initial_event_test_service 1 $REMAINING_OPTIONS &
PID_SERVICE_ONE=$!

export VSOMEIP_APPLICATION_NAME=initial_event_test_service_two
./initial_event_test_service 2 $REMAINING_OPTIONS &
PID_SERVICE_TWO=$!

export VSOMEIP_APPLICATION_NAME=initial_event_test_service_three
./initial_event_test_service 3 $REMAINING_OPTIONS &
PID_SERVICE_THREE=$!

sleep 3

unset VSOMEIP_APPLICATION_NAME

# Start first client which subscribes remotely
./initial_event_test_client 9000 DONT_EXIT $REMAINING_OPTIONS &
FIRST_PID=$!

# Start availability checker in order to wait until the services on the remote
# were started as well
./initial_event_test_availability_checker 1234 $REMAINING_OPTIONS &
PID_AVAILABILITY_CHECKER=$!

sleep 1

print_starter_message

# remove SUBSCRIBE_ONLY_ONCE parameter from $REMAINING_OPTIONS to ensure the
# following clients subscribe normaly
REMAINING_OPTIONS=${REMAINING_OPTIONS%SUBSCRIBE_ONLY_ONE}
REMAINING_OPTIONS=${REMAINING_OPTIONS#SUBSCRIBE_ONLY_ONE}


# wait until the services on the remote node were started as well
echo "WAITING FOR SERVICE AVAILABILITY"
wait $PID_AVAILABILITY_CHECKER
echo "ALL SERVICES ARE AVAILABLE NOW"

sleep 2

./initial_event_test_client 9001 STRICT_CHECKING $REMAINING_OPTIONS &
CLIENT_PID_ONE=$!
./initial_event_test_client 9002 STRICT_CHECKING $REMAINING_OPTIONS &
CLIENT_PID_TWO=$!
./initial_event_test_client 9003 STRICT_CHECKING $REMAINING_OPTIONS &
CLIENT_PID_THREE=$!
./initial_event_test_client 9004 STRICT_CHECKING $REMAINING_OPTIONS &
CLIENT_PID_FOUR=$!
./initial_event_test_client 9005 STRICT_CHECKING $REMAINING_OPTIONS &
CLIENT_PID_FIVE=$!
./initial_event_test_client 9006 STRICT_CHECKING $REMAINING_OPTIONS &
CLIENT_PID_SIX=$!
./initial_event_test_client 9007 STRICT_CHECKING $REMAINING_OPTIONS &
CLIENT_PID_SEVEN=$!
./initial_event_test_client 9008 STRICT_CHECKING $REMAINING_OPTIONS &
CLIENT_PID_EIGHT=$!
./initial_event_test_client 9009 STRICT_CHECKING $REMAINING_OPTIONS &
CLIENT_PID_NINE=$!
./initial_event_test_client 9010 STRICT_CHECKING $REMAINING_OPTIONS &
CLIENT_PID_TEN=$!
./initial_event_test_client 9011 STRICT_CHECKING $REMAINING_OPTIONS &
CLIENT_PID_ELEVEN=$!

# Wait until all clients are finished
# Fail gets incremented if a client exits with a non-zero exit code
wait $CLIENT_PID_ONE || FAIL=$(($FAIL+1))
wait $CLIENT_PID_TWO || FAIL=$(($FAIL+1))
wait $CLIENT_PID_THREE || FAIL=$(($FAIL+1))
wait $CLIENT_PID_FOUR || FAIL=$(($FAIL+1))
wait $CLIENT_PID_FIVE || FAIL=$(($FAIL+1))
wait $CLIENT_PID_SIX || FAIL=$(($FAIL+1))
wait $CLIENT_PID_SEVEN || FAIL=$(($FAIL+1))
wait $CLIENT_PID_EIGHT || FAIL=$(($FAIL+1))
wait $CLIENT_PID_NINE || FAIL=$(($FAIL+1))
wait $CLIENT_PID_TEN || FAIL=$(($FAIL+1))
wait $CLIENT_PID_ELEVEN || FAIL=$(($FAIL+1))

# wait until all clients exited on slave side
./initial_event_test_stop_service MASTER &
PID_STOP_SERVICE=$!
wait $PID_STOP_SERVICE

# shutdown the first client
kill $FIRST_PID
wait $FIRST_PID || FAIL=$(($FAIL+1))

# shutdown the services
kill $PID_SERVICE_THREE
kill $PID_SERVICE_TWO
kill $PID_SERVICE_ONE

sleep 1
echo ""

# Check if they exited successfully
if [ $FAIL -eq 0 ]
then
    exit 0
else
    exit 1
fi
