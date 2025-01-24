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

if [[ $# -gt 0 && $1 != "RANDOM" && $1 != "LIMITED" && $1 != "LIMITEDGENERAL" && $1 != "QUEUELIMITEDGENERAL" && $1 != "QUEUELIMITEDSPECIFIC" && $1 != "UDP" ]]
then
    echo "The only allowed parameter to this script is RANDOM or LIMITED, LIMITEDGENERAL, QUEUELIMITEDGENERAL, QUEUELIMITEDSPECIFIC or UDP"
    echo "Like $0 RANDOM"
    exit 1
fi

FAIL=0

# Start the client
if [[ $# -gt 0 && $1 == "RANDOM" ]]; then
    export VSOMEIP_CONFIGURATION=big_payload_test_tcp_client_random.json
elif [[ $# -gt 0 && $1 == "LIMITEDGENERAL" ]]; then
    export VSOMEIP_CONFIGURATION=big_payload_test_tcp_client_limited_general.json
elif [[ $# -gt 0 && $1 == "QUEUELIMITEDGENERAL" ]]; then
    export VSOMEIP_CONFIGURATION=big_payload_test_tcp_client_queue_limited_general.json
elif [[ $# -gt 0 && $1 == "QUEUELIMITEDSPECIFIC" ]]; then
    export VSOMEIP_CONFIGURATION=big_payload_test_tcp_client_queue_limited_specific.json
elif [[ $# -gt 0 && $1 == "UDP" ]]; then
    export VSOMEIP_CONFIGURATION=big_payload_test_udp_client.json
else
    export VSOMEIP_CONFIGURATION=big_payload_test_tcp_client.json
fi
./big_payload_test_client $1 &
BIG_PAYLOAD_TEST_PID=$!

if [ ! -z "$USE_LXC_TEST" ]; then
    echo "starting big payload test on slave LXC"
    if [[ $# -gt 0 ]]; then
        ssh -tt -i $SANDBOX_ROOT_DIR/commonapi_main/lxc-config/.ssh/mgc_lxc/rsa_key_file.pub -o StrictHostKeyChecking=no root@$LXC_TEST_SLAVE_IP "bash -ci \"set -m; cd \\\$SANDBOX_TARGET_DIR/vsomeip_lib/test/network_tests/big_payload_tests; ./big_payload_test_external_service_start.sh $1\"" &
    else
        ssh -tt -i $SANDBOX_ROOT_DIR/commonapi_main/lxc-config/.ssh/mgc_lxc/rsa_key_file.pub -o StrictHostKeyChecking=no root@$LXC_TEST_SLAVE_IP 'bash -ci "set -m; cd \$SANDBOX_TARGET_DIR/vsomeip_lib/test/network_tests/big_payload_tests; ./big_payload_test_external_service_start.sh"' &
    fi
elif [ ! -z "$USE_DOCKER" ]; then
    if [[ $# -gt 0 ]]; then
       docker exec $DOCKER_IMAGE sh -c "cd $DOCKER_TESTS && ./big_payload_test_external_service_start.sh $1" &
    else
       docker exec $DOCKER_IMAGE sh -c "cd $DOCKER_TESTS && ./big_payload_test_external_service_start.sh" &
    fi
else
cat <<End-of-message
*******************************************************************************
*******************************************************************************
** Please now run:
** big_payload_test_external_service_start.sh $1
** from an external host to successfully complete this test.
**
** You probably will need to adapt the 'unicast' settings in
** big_payload_test_tcp_service.json and
** big_payload_test_tcp_client.json to your personal setup.
*******************************************************************************
*******************************************************************************
End-of-message
fi

# Wait until client and service are finished
for job in $(jobs -p)
do
    # Fail gets incremented if either client or service exit
    # with a non-zero exit code
    wait $job || ((FAIL+=1))
done

# Check if client and server both exited successfully
exit $FAIL
