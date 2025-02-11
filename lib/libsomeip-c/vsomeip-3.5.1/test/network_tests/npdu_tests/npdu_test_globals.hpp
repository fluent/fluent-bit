// Copyright (C) 2015-2019 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef NPDU_TESTS_NPDU_TEST_GLOBALS_HPP_
#define NPDU_TESTS_NPDU_TEST_GLOBALS_HPP_

namespace npdu_test {

// Routing manager daemon
constexpr vsomeip::client_t RMD_CLIENT_ID_CLIENT_SIDE = 0x6666;
constexpr vsomeip::service_t RMD_SERVICE_ID_CLIENT_SIDE = 0x6666;

constexpr vsomeip::client_t RMD_CLIENT_ID_SERVICE_SIDE = 0x6667;
constexpr vsomeip::service_t RMD_SERVICE_ID_SERVICE_SIDE = 0x6667;

constexpr vsomeip::instance_t RMD_INSTANCE_ID = 0x6666;
constexpr vsomeip::method_t RMD_SHUTDOWN_METHOD_ID = 0x6666;



constexpr vsomeip::method_t NPDU_SERVICE_SHUTDOWNMETHOD_ID = 0x7777;

constexpr std::array<vsomeip::service_t, 4> service_ids =
    { 0x1000, 0x2000, 0x3000, 0x4000 };
constexpr std::array<vsomeip::instance_t, 4> instance_ids =
    { service_ids[0] >> 12,
      service_ids[1] >> 12,
      service_ids[2] >> 12,
      service_ids[3] >> 12 };
constexpr std::array<std::array<vsomeip::method_t, 4>, 4> method_ids = {{
    { service_ids[0]+1, service_ids[0]+2 ,service_ids[0]+3 ,service_ids[0]+4 },
    { service_ids[1]+1, service_ids[1]+2 ,service_ids[1]+3 ,service_ids[1]+4 },
    { service_ids[2]+1, service_ids[2]+2 ,service_ids[2]+3 ,service_ids[2]+4 },
    { service_ids[3]+1, service_ids[3]+2 ,service_ids[3]+3 ,service_ids[3]+4 }
}};

constexpr std::array<vsomeip::client_t, 4> client_ids_clients =
    { 0x1111, 0x2222, 0x3333, 0x4444 };

constexpr std::array<vsomeip::client_t, 4> client_ids_services = service_ids;

}
#endif /* NPDU_TESTS_NPDU_TEST_GLOBALS_HPP_ */
