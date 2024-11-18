// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <memory>
#include <gtest/gtest.h>
#include <common/utility.hpp>

namespace {
vsomeip_v3::uid_t invalid_uid = 1;
vsomeip_v3::uid_t valid_uid = 4003017;
vsomeip_v3::gid_t invalid_gid = 1;
vsomeip_v3::gid_t valid_gid = 5002;
vsomeip_sec_ip_addr_t host_address = 0;
}

TEST(check_routing_credentials, check_policies_loaded) {
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    //force load of some policies
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::vector<std::string> dir_skip;
    utility::read_data(utility::get_all_files_in_dir(utility::get_policies_path(), dir_skip), policy_elements, its_failed);

    for (const auto& e : policy_elements)
        security->load(e, false);

    //check if the load worked
    ASSERT_TRUE(policy_elements.size() > 0);
    ASSERT_TRUE(its_failed.size() == 0);

    // create security clients
    vsomeip_sec_client_t its_sec_client_valid = utility::create_uds_client(valid_uid, valid_gid, host_address);
    vsomeip_sec_client_t its_sec_client_invalid = utility::create_uds_client(invalid_uid, invalid_gid, host_address);
    vsomeip_sec_client_t its_sec_client_valid_uid_invalid_gid = utility::create_uds_client(valid_uid, invalid_gid, host_address);
    vsomeip_sec_client_t its_sec_client_invalid_uid_valid_gid = utility::create_uds_client(invalid_uid, valid_gid, host_address);

    //valid uid and gid -> the check must return true
    EXPECT_TRUE(security->check_routing_credentials(&its_sec_client_valid));

    //invalid gid and valid gid -> the check must return false
    EXPECT_FALSE(security->check_routing_credentials(&its_sec_client_valid_uid_invalid_gid));

    //invalid uid and valid gid -> the check must return false
    EXPECT_FALSE(security->check_routing_credentials(&its_sec_client_invalid_uid_valid_gid));

    //invalid uid and gid -> the check must return false
    EXPECT_FALSE(security->check_routing_credentials(&its_sec_client_invalid));
}

// check_routing_credentials with policies loaded in lazy mode
// vsomeip's security implementation can be put in a so called 'Audit Mode' where
// all security violations will be logged but allowed.
// To activate the 'Audit Mode' the 'security' object has to be included in the
// json file but the 'check_routing_credentials' switch has to be set to false.
TEST(check_routing_credentials, check_policies_loaded_lazy_load) {
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    //force load of some policies
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::vector<std::string> dir_skip;
    utility::read_data(utility::get_all_files_in_dir(utility::get_policies_path(), dir_skip), policy_elements, its_failed);

    // load policies in lazy mode so that check_routing_credentials is false
    for (const auto& e : policy_elements)
        security->load(e, true);

    //check if the load worked
    ASSERT_TRUE(policy_elements.size() > 0);
    ASSERT_TRUE(its_failed.size() == 0);

    // create security clients
    vsomeip_sec_client_t its_sec_client_valid = utility::create_uds_client(valid_uid, valid_gid, host_address);
    vsomeip_sec_client_t its_sec_client_invalid = utility::create_uds_client(invalid_uid, invalid_gid, host_address);
    vsomeip_sec_client_t its_sec_client_valid_uid_invalid_gid = utility::create_uds_client(valid_uid, invalid_gid, host_address);
    vsomeip_sec_client_t its_sec_client_invalid_uid_valid_gid = utility::create_uds_client(invalid_uid, valid_gid, host_address);

    //expect check_routing_credentials_ false so method always returns true
    EXPECT_TRUE(security->check_routing_credentials(&its_sec_client_valid));
    EXPECT_TRUE(security->check_routing_credentials(&its_sec_client_valid_uid_invalid_gid));
    EXPECT_TRUE(security->check_routing_credentials(&its_sec_client_invalid_uid_valid_gid));
    EXPECT_TRUE(security->check_routing_credentials(&its_sec_client_invalid));
}
