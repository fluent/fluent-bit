#!/bin/bash
# Copyright (C) 2015-2019 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Purpose: This script is needed to start the routing manager daemon and the
# clients with one command. This is necessary as ctest - which is used to run
# the tests - isn't able to start multiple binaries for one testcase. Therefore
# the testcase simply executes this script. This script then runs the routing
# manager daemon and the clients and checks if all of them exit successfully.

if [ $# -lt 2 ]; then
    echo "Error: Please pass a protocol and communication mode to this script."
    echo "Valid protocols are [UDP,TCP]."
    echo "Valid communication modes are [sync, async]."
    echo "For example $> $0 UDP sync"
    exit 1;
fi

FAIL=0
PROTOCOL=$1
COMMUNICATION_MODE=$2

start_clients(){
    export VSOMEIP_CONFIGURATION=npdu_test_client_npdu.json

    # Start the routing manager daemon
    export VSOMEIP_APPLICATION_NAME=npdu_test_routing_manager_daemon_client_side
    ./npdu_test_rmd_client_side &

    # sleep 1 second to let the RMD startup.
    sleep 1
    # Start client 1
    export VSOMEIP_APPLICATION_NAME=npdu_test_client_one
    ./npdu_test_client_1 $* &

    # Start client 2
    export VSOMEIP_APPLICATION_NAME=npdu_test_client_two
    ./npdu_test_client_2 $* &

    # Start client 3
    export VSOMEIP_APPLICATION_NAME=npdu_test_client_three
    ./npdu_test_client_3 $* &

    # Start client 4
    export VSOMEIP_APPLICATION_NAME=npdu_test_client_four
    ./npdu_test_client_4 $* &
}

wait_for_bg_processes(){
    # Wait until client and service are finished
    for job in $(jobs -p)
    do
        # Fail gets incremented if one of the jobs exit
        # with a non-zero exit code
        wait $job || ((FAIL+=1))
    done

    # Check if everything exited successfully
    if [ $FAIL -eq 0 ]
    then
        echo "All clients exited successfully"
    else
        echo "Something went wrong"
        exit 1
    fi
}


echo "Contacting services via $PROTOCOL"
start_clients --$PROTOCOL --max-payload-size $PROTOCOL --$COMMUNICATION_MODE
wait_for_bg_processes

exit 0
