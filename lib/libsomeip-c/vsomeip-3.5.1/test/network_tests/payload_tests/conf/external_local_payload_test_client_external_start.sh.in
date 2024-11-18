#!/bin/bash
# Copyright (C) 2015-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

export VSOMEIP_APPLICATION_NAME=external_local_payload_test_client_external
export VSOMEIP_CONFIGURATION=external_local_payload_test_client_external.json
./payload_test_client --udp --max-payload-size UDP
# We sleep to let the service restart with --tcp option so we can test
# communication via TCP.
sleep 5
./payload_test_client --tcp --max-payload-size TCP
