// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <gtest/gtest.h>

#include <common/utility.hpp>

namespace {
    vsomeip_v3::client_t client = 1;
    vsomeip_v3::uid_t invalid_uid = 1;
    vsomeip_v3::uid_t valid_uid = 4004201;
    vsomeip_v3::gid_t invalid_gid = 1;
    vsomeip_v3::gid_t valid_gid = 4004200;
    vsomeip_sec_ip_addr_t host_address = 0;
}

TEST(check_credentials_test, check_no_policies_loaded) {

    std::unique_ptr<vsomeip_v3::policy_manager_impl> its_manager(new vsomeip_v3::policy_manager_impl);

    //no policies loaded -> check credentials will return false independent of the uid or gid
    ASSERT_TRUE(its_manager->is_audit());
    ASSERT_FALSE(its_manager->is_enabled());

    // create security clients
    vsomeip_sec_client_t its_sec_client_invalid = utility::create_uds_client(invalid_uid, invalid_gid, host_address);
    EXPECT_TRUE(its_manager->check_credentials(client, &its_sec_client_invalid));
}

TEST(check_credentials_test, check_policies_loaded) {

    std::unique_ptr<vsomeip_v3::policy_manager_impl> its_manager(
            new vsomeip_v3::policy_manager_impl);

    //force load of some policies
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::vector<std::string> dir_skip;

    utility::read_data(utility::get_all_files_in_dir(
            utility::get_policies_path(), dir_skip), policy_elements, its_failed);

    for (const auto& e : policy_elements)
        its_manager->load(e, false);

    //check if the load worked
    ASSERT_TRUE(policy_elements.size() > 0);
    ASSERT_TRUE(its_failed.size() == 0);

    //the check_credentials_ and the policy_enabled_ variables should be set to true
    ASSERT_FALSE(its_manager->is_audit());
    ASSERT_TRUE(its_manager->is_enabled());

    // create security clients
    vsomeip_sec_client_t its_sec_client_valid = utility::create_uds_client(valid_uid, valid_gid, host_address);

    vsomeip_sec_client_t its_sec_client_invalid = utility::create_uds_client(invalid_uid, invalid_gid, host_address);

    //invalid uid and gid -> the check must return false
    EXPECT_FALSE(its_manager->check_credentials(client, &its_sec_client_invalid));

    //invalid uid and valid gid -> the check must return false
    EXPECT_FALSE(its_manager->check_credentials(client, &its_sec_client_invalid));

    //valid uid and invalid gid -> the check must return false
    EXPECT_FALSE(its_manager->check_credentials(client, &its_sec_client_invalid));

    //valid uid and gid -> the check must return true
    EXPECT_TRUE(its_manager->check_credentials(client, &its_sec_client_valid));
}

// check_credentials with policies loaded but in audit mode
// vsomeip's security implementation can be put in a so called 'Audit Mode' where
// all security violations will be logged but allowed.
// To activate the 'Audit Mode' the 'security' object has to be included in the
// json file but the 'check_credentials' switch has to be set to false.
TEST(check_credentials_test, check_policies_loaded_in_audit_mode) {

    std::unique_ptr<vsomeip_v3::policy_manager_impl> its_manager(
            new vsomeip_v3::policy_manager_impl);

    //force load of some policies
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::vector<std::string> dir_skip;
    utility::read_data(utility::get_all_files_in_dir(
            utility::get_policies_path(), dir_skip), policy_elements, its_failed);

    //the check_credentials_ variable is force to be false
    utility::force_check_credentials(policy_elements, "false");

    for (const auto& e : policy_elements)
        its_manager->load(e, false);

    //check if the load worked
    ASSERT_TRUE(policy_elements.size() > 0);
    ASSERT_TRUE(its_failed.size() == 0);

    //expect check_credentials_ false and the policy_enabled_ true
    ASSERT_TRUE(its_manager->is_audit());
    ASSERT_TRUE(its_manager->is_enabled());

    // create security clients
    vsomeip_sec_client_t its_sec_client_valid = utility::create_uds_client(valid_uid, valid_gid, host_address);
    vsomeip_sec_client_t its_sec_client_invalid_valid = utility::create_uds_client(invalid_uid, valid_gid, host_address);
    vsomeip_sec_client_t its_sec_client_valid_invalid = utility::create_uds_client(valid_uid, invalid_gid, host_address);
    vsomeip_sec_client_t its_sec_client_invalid = utility::create_uds_client(invalid_uid, invalid_gid, host_address);

    // is expected check_credentials method always return true
    //invalid uid and gid
    EXPECT_TRUE(its_manager->check_credentials(client, &its_sec_client_invalid));

    //invalid uid and valid gid
    EXPECT_TRUE(its_manager->check_credentials(client, &its_sec_client_invalid_valid));

    //valid uid and invalid gid
    EXPECT_TRUE(its_manager->check_credentials(client, &its_sec_client_valid_invalid));

    //valid uid and gid
    EXPECT_TRUE(its_manager->check_credentials(client, &its_sec_client_valid));
}
