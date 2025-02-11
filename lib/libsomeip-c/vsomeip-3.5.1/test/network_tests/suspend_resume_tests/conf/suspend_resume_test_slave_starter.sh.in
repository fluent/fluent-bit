#!/bin/bash
# Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

FAIL=0

# Start the client
export VSOMEIP_APPLICATION_NAME=suspend_resume_test_client
export VSOMEIP_CONFIGURATION=suspend_resume_test_client.json
./suspend_resume_test_client &
PID_CLIENT=$!

# Wait until all applications are finished
for job in $(jobs -p)
do
    # Fail gets incremented if one of the binaries exits
    # with a non-zero exit code
    wait $job || ((FAIL+=1))
done

# Check if both exited successfully
if [ $FAIL -eq 0 ]
then
    exit 0
else
    exit 1
fi
