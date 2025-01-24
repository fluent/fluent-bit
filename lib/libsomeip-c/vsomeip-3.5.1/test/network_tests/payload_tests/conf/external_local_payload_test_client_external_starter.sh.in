#!/bin/bash
# Copyright (C) 2015-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Purpose: This script is needed to start the client and service with
# one command. This is necessary as ctest - which is used to run the
# tests - isn't able to start two binaries for one testcase. Therefore
# the testcase simply executes this script. This script then runs client
# and service and checks that both exit sucessfully.

FAIL=0

# Parameter 1: the pid to check
# Parameter 2: number of TCP/UDP sockets the process should have open
check_tcp_udp_sockets_are_open ()
{
    # Check that the passed pid/process does listen on at least one TCP/UDP socket
    # awk is used to avoid the case when a inode number is the same as a PID. The awk
    # program filters the netstat output down to the protocol (1st field) and
    # the PID/Program name (last field) fields.
    SERVICE_SOCKETS_LISTENING=$(netstat -tulpen 2> /dev/null | awk '{print $1 "\t"  $NF}' | grep $1 | wc -l)
    if [ $SERVICE_SOCKETS_LISTENING -lt $2 ]
    then
        ((FAIL+=1))
    fi
}

# Parameter 1: the pid to check
check_tcp_udp_sockets_are_closed ()
{
    # Check that the passed pid/process does not listen on any TCP/UDP socket
    # or has any active connection via a TCP/UDP socket
    # awk is used to avoid the case when a inode number is the same as a PID. The awk
    # program filters the netstat output down to the protocol (1st field) and
    # the PID/Program name (last field) fields.
    SERVICE_SOCKETS_LISTENING=$(netstat -tulpen 2> /dev/null | awk '{print $1 "\t"  $NF}' | grep $1 | wc -l)
    if [ $SERVICE_SOCKETS_LISTENING -ne 0 ]
    then
        ((FAIL+=1))
    fi

    SERVICE_SOCKETS_CONNECTED=$(netstat -tupen 2> /dev/null | awk '{print $1 "\t"  $NF}' | grep $1 | wc -l)
    if [ $SERVICE_SOCKETS_CONNECTED -ne 0 ]
    then
        ((FAIL+=1))
    fi
}

# Start the service for payload test with UDP
export VSOMEIP_APPLICATION_NAME=external_local_payload_test_service
export VSOMEIP_CONFIGURATION=external_local_payload_test_service.json
./payload_test_service --udp &
SERIVCE_PID=$!

# Display a message to show the user that he must now call the external client
# to finish the test successfully
if [ ! -z "$USE_LXC_TEST" ]; then
    echo "starting external local payload on slave LXC"
    ssh -tt -i $SANDBOX_ROOT_DIR/commonapi_main/lxc-config/.ssh/mgc_lxc/rsa_key_file.pub -o StrictHostKeyChecking=no root@$LXC_TEST_SLAVE_IP "bash -ci \"set -m; cd \\\$SANDBOX_TARGET_DIR/vsomeip_lib/test/network_tests/payload_tests; ./external_local_payload_test_client_external_start.sh\"" &
    echo "remote ssh job id: $!"
elif [ ! -z "$USE_DOCKER" ]; then
    docker exec $DOCKER_IMAGE sh -c "cd $DOCKER_TESTS && ./external_local_payload_test_client_external_start.sh" &
else
cat <<End-of-message
*******************************************************************************
*******************************************************************************
** Please now run:
** external_local_payload_test_client_external_start.sh
** from an external host to successfully complete this test.
**
** You probably will need to adapt the 'unicast' settings in
** external_local_payload_test_client_external.json and
** external_local_payload_test_service.json to your personal setup.
*******************************************************************************
*******************************************************************************
End-of-message
fi

# The service should listen on a TCP and UDP socket now
sleep 1
check_tcp_udp_sockets_are_open $SERIVCE_PID 2

# Wait until service is finished
# The client remotely shuts down the service if he has successfully transmitted
# all the packets with different payloads. Therefore we can assume that everything
# went well, even if we can only check the exit code of the service here.

# Fail gets incremented if either client or service exit
# with a non-zero exit code
wait $SERIVCE_PID || ((FAIL+=1))


# Start the service for payload test with tcp
export VSOMEIP_APPLICATION_NAME=external_local_payload_test_service
export VSOMEIP_CONFIGURATION=external_local_payload_test_service.json
./payload_test_service --tcp &
SERIVCE_PID=$!

# The service should listen on a TCP and UDP socket now
sleep 1
check_tcp_udp_sockets_are_open $SERIVCE_PID 2


# Wait until service is finished
# The client remotely shuts down the service if he has successfully transmitted
# all the packets with different payloads. Therefore we can assume that everything
# went well, even if we can only check the exit code of the service here.

# Fail gets incremented if either client or service exit
# with a non-zero exit code
wait $SERIVCE_PID || ((FAIL+=1))

# Check if server exited sucessfully
if [ $FAIL -eq 0 ]
then
    exit 0
else
    exit 1
fi
