// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <memory>
#include <gtest/gtest.h>
#include <common/utility.hpp>

namespace {
std::unordered_set<vsomeip_v3::client_t> clients;
std::unordered_set<vsomeip_v3::client_t> local_clients;
vsomeip_v3::client_t client_1 = 10;
vsomeip_v3::client_t client_2 = 11;
vsomeip_v3::client_t client_3 = 12;
vsomeip_v3::uid_t uid = 4003030;
vsomeip_v3::gid_t gid = 4003032;
vsomeip_sec_ip_addr_t host_address = 0;
}

TEST(get_clients, test)
{
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    vsomeip_sec_client_t its_sec_client_uid_gid = utility::create_uds_client(uid, gid, host_address);

    // Local_clients has now one client(10).
    local_clients.insert(client_1);

    // Clients should be empty.
    EXPECT_TRUE(clients.empty());

    // Should do nothing because there is not a client to uid_gid mapping yet.
    security->get_clients(uid, gid, clients);

    // clients should still be empty.
    EXPECT_TRUE(clients.empty());

    // Stores client to uid_gid_mapping.
    security->store_client_to_sec_client_mapping(client_1, &its_sec_client_uid_gid);
    security->get_clients(uid, gid, clients);

    // Clients and local_clients should be equal and have the same client(10).
    EXPECT_EQ(clients, local_clients);

    // Repeat with two more clients.
    security->store_client_to_sec_client_mapping(client_2, &its_sec_client_uid_gid);
    security->store_client_to_sec_client_mapping(client_3, &its_sec_client_uid_gid);

    local_clients.insert(client_2);
    local_clients.insert(client_3);

    security->get_clients(uid, gid, clients);

    // Clients and local_clients should be equal and have the same 3 clients(10,11,12).
    EXPECT_EQ(clients, local_clients);
}
