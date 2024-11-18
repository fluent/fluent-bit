#!/bin/bash
# Copyright (C) 2015-2019 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Purpose: This script is needed to start the routing manager daemon and the
# services with one command. This is necessary as ctest - which is used to run
# the tests - isn't able to start multiple binaries for one testcase. Therefore
# the testcase simply executes this script. This script then runs the routing
# manager daemon and the services and checks if all of them exit successfully.

FAIL=0

if [ $# -lt 2 ]; then
    echo "Error: Please pass a protocol and communication mode to this script."
    echo "Valid protocols are [UDP,TCP]."
    echo "Valid communication modes are [sync, async]."
    echo "For example $> $0 UDP sync"
    exit 1;
fi

start_services(){
    export VSOMEIP_CONFIGURATION=npdu_test_service_npdu.json

    # Start the routing manager daemon
    export VSOMEIP_APPLICATION_NAME=npdu_test_routing_manager_daemon_service_side
    ./npdu_test_rmd_service_side &

    # sleep 1 second to let the RMD startup.
    sleep 1

    # Start service 1
    export VSOMEIP_APPLICATION_NAME=npdu_test_service_one
    ./npdu_test_service_1 $* &

    # Start service 2
    export VSOMEIP_APPLICATION_NAME=npdu_test_service_two
    ./npdu_test_service_2 $* &

    # Start service 3
    export VSOMEIP_APPLICATION_NAME=npdu_test_service_three
    ./npdu_test_service_3 $* &

    # Start service 4
    export VSOMEIP_APPLICATION_NAME=npdu_test_service_four
    ./npdu_test_service_4 $* &
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
        echo "All services exited successfully"
    else
        echo "Something went wrong"
        exit 1
    fi
}


start_services

if [ ! -z "$USE_LXC_TEST" ]; then
    echo "starting magic cookies test on slave LXC"
    ssh -tt -i $SANDBOX_ROOT_DIR/commonapi_main/lxc-config/.ssh/mgc_lxc/rsa_key_file.pub -o StrictHostKeyChecking=no root@$LXC_TEST_SLAVE_IP "bash -ci \"set -m; cd \\\$SANDBOX_TARGET_DIR/vsomeip_lib/test/network_tests/npdu_tests; ./npdu_test_client_npdu_start.sh $*\"" &
elif [ ! -z "$USE_DOCKER" ]; then
    docker exec $DOCKER_IMAGE sh -c "cd $DOCKER_TESTS && ./npdu_test_client_npdu_start.sh $*" &
else
sleep 1
cat <<End-of-message
*******************************************************************************
*******************************************************************************
** Please now run:
** npdu_test_client_npdu_start.sh $*
** from an external host to successfully complete this test.
**
** You probably will need to adapt the 'unicast' settings in
** npdu_test_client_npdu.json and
** npdu_test_service_npdu.json to your personal setup.
*******************************************************************************
*******************************************************************************
End-of-message
fi

wait_for_bg_processes

exit 0
