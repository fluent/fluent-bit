#!/bin/bash
# Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# start routing host
export VSOMEIP_CONFIGURATION=offer_stop_offer_test_service.json
export VSOMEIP_APPLICATION_NAME="routingmanagerd"
../../../examples/routingmanagerd/routingmanagerd &

HOST_PID=$!

# start service app
export VSOMEIP_CONFIGURATION=offer_stop_offer_test_service.json
export VSOMEIP_APPLICATION_NAME="service-sample"

./offer_stop_offer_test_service

kill -9 $HOST_PID
