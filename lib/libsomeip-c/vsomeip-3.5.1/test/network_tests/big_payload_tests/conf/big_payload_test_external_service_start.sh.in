#!/bin/bash
# Copyright (C) 2015-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

if [[ $# -gt 0 && $1 != "RANDOM" && $1 != "LIMITED" && $1 != "LIMITEDGENERAL" && $1 != "QUEUELIMITEDGENERAL" && $1 != "QUEUELIMITEDSPECIFIC" && $1 != "UDP" ]]
then
    echo "The only allowed parameter to this script is RANDOM, LIMITED, LIMITEDGENERAL, QUEUELIMITEDGENERAL, QUEUELIMITEDSPECIFIC or UDP"
    echo "Like $0 RANDOM"
    exit 1
fi

# Start the service
if [[ $# -gt 0 && $1 == "RANDOM" ]]; then
    export VSOMEIP_CONFIGURATION=big_payload_test_tcp_service_random.json
elif [[ $# -gt 0 && $1 == "LIMITEDGENERAL" ]]; then
    export VSOMEIP_CONFIGURATION=big_payload_test_tcp_service_limited_general.json
elif [[ $# -gt 0 && $1 == "QUEUELIMITEDGENERAL" ]]; then
    export VSOMEIP_CONFIGURATION=big_payload_test_tcp_service_queue_limited_general.json
elif [[ $# -gt 0 && $1 == "QUEUELIMITEDSPECIFIC" ]]; then
    export VSOMEIP_CONFIGURATION=big_payload_test_tcp_service_queue_limited_specific.json
elif [[ $# -gt 0 && $1 == "UDP" ]]; then
    export VSOMEIP_CONFIGURATION=big_payload_test_udp_service.json
else
    export VSOMEIP_CONFIGURATION=big_payload_test_tcp_service.json
fi
./big_payload_test_service $1
