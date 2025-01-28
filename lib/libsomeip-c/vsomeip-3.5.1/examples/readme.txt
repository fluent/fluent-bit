# Copyright (C) 2014-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

To use the example applications you need two devices on the same network. The network addresses within
the configuration files need to be adapted to match the devices addresses.

To start the request/response-example from the build-directory do:

HOST1: env VSOMEIP_CONFIGURATION=../../config/vsomeip-local.json VSOMEIP_APPLICATION_NAME=client-sample ./request-sample
HOST1: env VSOMEIP_CONFIGURATION=../../config/vsomeip-local.json VSOMEIP_APPLICATION_NAME=service-sample ./response-sample

To start the subscribe/notify-example from the build-directory do:

HOST1: env VSOMEIP_CONFIGURATION=../../config/vsomeip-local.json VSOMEIP_APPLICATION_NAME=client-sample ./subscribe-sample
HOST1: env VSOMEIP_CONFIGURATION=../../config/vsomeip-local.json VSOMEIP_APPLICATION_NAME=service-sample ./notify-sample
