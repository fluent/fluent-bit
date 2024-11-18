#!/bin/bash
# Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

FAIL=0

# call other container
if [ ! -z "$USE_LXC_TEST" ]; then
    ssh -tt -i $SANDBOX_ROOT_DIR/commonapi_main/lxc-config/.ssh/mgc_lxc/rsa_key_file.pub -o StrictHostKeyChecking=no root@$LXC_TEST_SLAVE_IP "bash -ci \"set -m; cd \\\$SANDBOX_TARGET_DIR/vsomeip_lib/test/network_tests/offer_stop_offer_test; ./offer_stop_offer_test_service_starter.sh\"" &
elif [ ! -z "$USE_DOCKER" ]; then
    docker exec $DOCKER_IMAGE sh -c "cd $DOCKER_TESTS; sleep 10; ./offer_stop_offer_test_service_starter.sh" &
fi

# start client
export VSOMEIP_CONFIGURATION=offer_stop_offer_test_client.json
export VSOMEIP_APPLICATION_NAME="client-sample"
./offer_stop_offer_test_client
