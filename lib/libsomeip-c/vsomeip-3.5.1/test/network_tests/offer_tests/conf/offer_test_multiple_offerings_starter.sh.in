#!/bin/bash

FAIL=0
# Start the application
# Note: Every service (daemon, services, client) are per-thread in this executable

export VSOMEIP_CONFIGURATION=offer_test_multiple_offerings.json

if ! ./offer_test_multiple_offerings
then
    ((FAIL+=1))
fi

exit $FAIL
