// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <memory>
#include <gtest/gtest.h>
#include <common/utility.hpp>

namespace {
vsomeip_v3::client_t client = 10;
vsomeip_v3::client_t alternate_client = 11;
vsomeip_v3::uid_t uid_1 = 4003030;
vsomeip_v3::gid_t gid_1 = 4003032;
vsomeip_v3::uid_t uid_2 = 1;
vsomeip_v3::gid_t gid_2 = 1;
vsomeip_v3::uid_t uid_3 = 2;
vsomeip_v3::gid_t gid_3 = 2;
vsomeip_sec_ip_addr_t host_address = 0;
}

TEST(get_client_to_sec_client_mapping, test)
{
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    vsomeip_sec_client_t its_sec_client_uid_gid_1 = utility::create_uds_client(uid_1, gid_1, host_address);
    vsomeip_sec_client_t its_sec_client_uid_gid_2 = utility::create_uds_client(uid_2, gid_2, host_address);
    vsomeip_sec_client_t its_sec_client_uid_gid_3 = utility::create_uds_client(uid_3, gid_3, host_address);

    // Client and uid_gid should not be stored yet.
    EXPECT_FALSE(security->get_client_to_sec_client_mapping(client, its_sec_client_uid_gid_1));

    // Add client and uid_gid mappings.
    security->store_client_to_sec_client_mapping(client, &its_sec_client_uid_gid_1);

    // uid_gid and uid_gid_2 should not be equal.
    EXPECT_NE(its_sec_client_uid_gid_1.group, its_sec_client_uid_gid_2.group);
    EXPECT_NE(its_sec_client_uid_gid_1.user, its_sec_client_uid_gid_2.user);

    // Client and uid_gid mapping should be returned.
    EXPECT_TRUE(security->get_client_to_sec_client_mapping(client, its_sec_client_uid_gid_2));

    // uid_gid and uid_gid_2 should be equal if get was successful.
    EXPECT_EQ(its_sec_client_uid_gid_1.group, its_sec_client_uid_gid_2.group);
    EXPECT_EQ(its_sec_client_uid_gid_1.user, its_sec_client_uid_gid_2.user);

    // Alternate_client is not stored, this should return false.
    EXPECT_FALSE(security->get_client_to_sec_client_mapping(alternate_client, its_sec_client_uid_gid_1));

    // Add alternate client and uid_gid mappings.
    security->store_client_to_sec_client_mapping(alternate_client, &its_sec_client_uid_gid_1);

    // uid_gid and uid_gid_3 should not be equal.
    EXPECT_NE(its_sec_client_uid_gid_1.group, its_sec_client_uid_gid_3.group);
    EXPECT_NE(its_sec_client_uid_gid_1.user, its_sec_client_uid_gid_3.user);

    // Alternate client and uid_gid mapping should be returned.
    EXPECT_TRUE(security->get_client_to_sec_client_mapping(alternate_client, its_sec_client_uid_gid_3));

    // uid_gid and uid_gid_3 should be equal if get was successful.
    EXPECT_EQ(its_sec_client_uid_gid_1.group, its_sec_client_uid_gid_3.group);
    EXPECT_EQ(its_sec_client_uid_gid_1.user, its_sec_client_uid_gid_3.user);
    }
