// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <memory>
#include <gtest/gtest.h>
#include <common/utility.hpp>

namespace
{
vsomeip_v3::client_t client = 10;
vsomeip_v3::uid_t uid = 4003030;
vsomeip_v3::gid_t gid = 4003032;
vsomeip_sec_ip_addr_t host_address = 0;
}

TEST(remove_client_to_sec_client_mapping, check_no_policies_loaded)
{
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    vsomeip_sec_client_t its_sec_client = utility::create_uds_client(uid, gid, host_address);

    // client and uid_gid should not be stored yet
    EXPECT_FALSE(security->get_client_to_sec_client_mapping (client, its_sec_client));

    // client and uid_gid should not be stored yet
    EXPECT_FALSE(security->remove_client_to_sec_client_mapping(client));

    // add client and uid_gid mappings
    security->store_client_to_sec_client_mapping(client, &its_sec_client);
    security->store_sec_client_to_client_mapping(&its_sec_client, client);

    // client and uid_gid mapping should be returned
    EXPECT_TRUE(security->get_client_to_sec_client_mapping(client, its_sec_client));

    // client and uid_gid mapping should be in the vector and able to be removed
    EXPECT_TRUE(security->remove_client_to_sec_client_mapping(client));

    // client and uid_gid should be removed from the vector
    EXPECT_FALSE(security->get_client_to_sec_client_mapping(client, its_sec_client));
}
