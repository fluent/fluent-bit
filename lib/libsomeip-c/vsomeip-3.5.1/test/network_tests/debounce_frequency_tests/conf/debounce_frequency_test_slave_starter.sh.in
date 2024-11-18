#!/bin/bash
# Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

FAIL=0

export VSOMEIP_CONFIGURATION=debounce_frequency_test_service.json
../../../examples/routingmanagerd/routingmanagerd &
PID_VSOMEIPD=$!

sleep 1

if ! ./debounce_frequency_test_service
then
    # Fail gets incremented if a client exits with a non-zero exit code
    FAIL=$(($FAIL+1))
fi

# kill the services
kill $PID_VSOMEIPD
sleep 3

# Check if everything went well
exit $FAIL
