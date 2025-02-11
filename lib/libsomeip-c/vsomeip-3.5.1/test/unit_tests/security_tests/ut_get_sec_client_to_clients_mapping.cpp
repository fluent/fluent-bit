// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <memory>
#include <gtest/gtest.h>
#include <common/utility.hpp>

namespace{
vsomeip_v3::client_t client = 10;
vsomeip_v3::uid_t uid_1 = 4003030;
vsomeip_v3::gid_t gid_1 = 4003032;
vsomeip_v3::uid_t uid_2 = 1;
vsomeip_v3::gid_t gid_2 = 1;
vsomeip_sec_ip_addr_t host_address = 0;
}

TEST(get_sec_client_to_clients_mapping, test)
{
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    std::set<vsomeip_v3::client_t> clients_1;
    clients_1.insert(client);

    vsomeip_sec_client_t its_sec_client_uid_gid = utility::create_uds_client(uid_1, gid_1, host_address);
    vsomeip_sec_client_t its_sec_client_uid_gid_alternate = utility::create_uds_client(uid_2, gid_2, host_address);

    // Client and uid_gid should not be stored yet.
    EXPECT_FALSE(security->get_sec_client_to_clients_mapping(&its_sec_client_uid_gid, clients_1));

    // Add client and uid_gid mappings.
    security->store_sec_client_to_client_mapping(&its_sec_client_uid_gid, client);

    std::set<vsomeip_v3::client_t> clients_2;

    // Clients and clients_2 should not be equal.
    EXPECT_NE(clients_1, clients_2);

    // Client and uid_gid mapping should be returned.
    EXPECT_TRUE(security->get_sec_client_to_clients_mapping(&its_sec_client_uid_gid, clients_2));

    // Clients and clients_2 should be equal if get was successful.
    EXPECT_EQ(clients_1, clients_2);

    // Alternate_uid_gid is not stored, this should return false.
    EXPECT_FALSE(security->get_sec_client_to_clients_mapping(&its_sec_client_uid_gid_alternate, clients_1));

    // Add alternate client and uid_gid mappings.
    security->store_sec_client_to_client_mapping(&its_sec_client_uid_gid_alternate, client);

    std::set<vsomeip_v3::client_t> clients_3;

    // Clients and clients_3 should not be equal.
    EXPECT_NE(clients_1, clients_3);

    // Alternate client and uid_gid mapping should be returned.
    EXPECT_TRUE(security->get_sec_client_to_clients_mapping(&its_sec_client_uid_gid_alternate, clients_3));

    // Clients and clients_3 should be equal if get was successful.
    EXPECT_EQ(clients_1, clients_3);
}
