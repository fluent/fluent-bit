// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <memory>
#include <gtest/gtest.h>
#include <common/utility.hpp>
namespace{

vsomeip_v3::uid_t uid_1 = 4003016;
vsomeip_v3::gid_t gid_1 = 4003016;
vsomeip_sec_ip_addr_t host_address = 0;
vsomeip_v3::service_t service_1 = 0xf8c2;

vsomeip_v3::service_t deny_service = 0x40;

vsomeip_v3::instance_t instance = 0x03;
vsomeip_v3::instance_t any_instance = 0xfffe;

vsomeip_v3::uid_t invalid_uid = 1;
vsomeip_v3::gid_t invalid_gid = 1;
vsomeip_v3::uid_t ANY_UID = 0xFFFFFFFF;
vsomeip_v3::gid_t ANY_GID = 0xFFFFFFFF;

vsomeip_v3::gid_t deny_uid  = 9000;
vsomeip_v3::gid_t deny_gid  = 9000;
}

TEST(is_offer_allowed, check_no_policies_loaded)
{
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    ASSERT_FALSE(security->is_enabled());

    vsomeip_sec_client_t its_sec_client_invalid = utility::create_uds_client(invalid_uid, invalid_gid, host_address);

    // no policies loaded -> is_offer_allowed must return true
    EXPECT_TRUE(security->is_offer_allowed(&its_sec_client_invalid, service_1, instance));
}

TEST(is_offer_allowed, check_policies_loaded)
{
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    // force load of some policies
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::vector<std::string> dir_skip;
    utility::read_data(utility::get_all_files_in_dir(utility::get_policies_path(), dir_skip), policy_elements, its_failed);

    // check if the load worked
    ASSERT_TRUE(policy_elements.size() > 0);
    ASSERT_TRUE(its_failed.size() == 0);

    for (const auto &e : policy_elements)
    {
        security->load(e, false);
    }

    // check if the policies are loaded and check_credentials_ variable are true
    ASSERT_TRUE(security->is_enabled());
    ASSERT_FALSE(security->is_audit());

    // create security clients
    vsomeip_sec_client_t its_sec_client_valid = utility::create_uds_client(uid_1, gid_1, host_address);
    vsomeip_sec_client_t its_sec_client_invalid = utility::create_uds_client(invalid_uid, invalid_gid, host_address);
    vsomeip_sec_client_t its_sec_client_valid_uid_invalid_gid = utility::create_uds_client(uid_1, invalid_gid, host_address);
    vsomeip_sec_client_t its_sec_client_invalid_uid_valid_gid = utility::create_uds_client(invalid_uid, gid_1, host_address);
    vsomeip_sec_client_t its_sec_client_deny = utility::create_uds_client(deny_uid, deny_gid, host_address);
    vsomeip_sec_client_t its_sec_client_any = utility::create_uds_client(ANY_UID, ANY_GID, host_address);

    // valid credential for valid service / instance
    EXPECT_TRUE(security->is_offer_allowed(&its_sec_client_valid, service_1, instance));

    // request with the same credentials and service but with a different instance
    // is_offer_allowed return true because it's define ANY_INSTANCE in the policy
    EXPECT_TRUE(security->is_offer_allowed(&its_sec_client_valid, service_1, any_instance));

    // invalid credential for the service / instance
    EXPECT_FALSE(security->is_offer_allowed(&its_sec_client_invalid_uid_valid_gid, service_1, instance));
    EXPECT_FALSE(security->is_offer_allowed(&its_sec_client_valid_uid_invalid_gid, service_1, instance));
    EXPECT_FALSE(security->is_offer_allowed(&its_sec_client_invalid, service_1, instance));

    // test deny offer
    // deny client with credentials for the service
    EXPECT_FALSE(security->is_offer_allowed(&its_sec_client_deny, deny_service, instance));
    // credentials exists in deny policy, but not for that service
    EXPECT_TRUE(security->is_offer_allowed(&its_sec_client_deny, service_1, instance));

    // ANY_UID and ANY_GID
    EXPECT_FALSE(security->is_offer_allowed(&its_sec_client_any, service_1, instance));
}

// is_offer_allowed with policies loaded but in audit mode
// vsomeip's security implementation can be put in a so called 'Audit Mode' where
// all security violations will be logged but allowed.
// To activate the 'Audit Mode' the 'security' object has to be included in the
// json file but the 'check_credentials' switch has to be set to false.

TEST(is_offer_allowed, check_policies_loaded_in_audit_mode)
{
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    // create security clients
    vsomeip_sec_client_t its_sec_client_valid = utility::create_uds_client(uid_1, gid_1, host_address);
    vsomeip_sec_client_t its_sec_client_invalid = utility::create_uds_client(invalid_uid, invalid_gid, host_address);
    vsomeip_sec_client_t its_sec_client_valid_uid_invalid_gid = utility::create_uds_client(uid_1, invalid_gid, host_address);
    vsomeip_sec_client_t its_sec_client_invalid_uid_valid_gid = utility::create_uds_client(invalid_uid, gid_1, host_address);
    vsomeip_sec_client_t its_sec_client_deny = utility::create_uds_client(deny_uid, deny_gid, host_address);
    vsomeip_sec_client_t its_sec_client_any = utility::create_uds_client(ANY_UID, ANY_GID, host_address);

    // force load of some policies
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::vector<std::string> dir_skip;
    utility::read_data(utility::get_all_files_in_dir(utility::get_policies_path(), dir_skip), policy_elements, its_failed);

    // check if the load worked
    ASSERT_TRUE(policy_elements.size() > 0);
    ASSERT_TRUE(its_failed.size() == 0);

    utility::force_check_credentials(policy_elements, "false");

    for (const auto &e : policy_elements)
    {
        security->load(e, false);
    }

    // check if the policies are loaded and check_credentials_ variable are true
    ASSERT_TRUE(security->is_enabled());
    ASSERT_TRUE(security->is_audit());

    // valid credential for valid service / instance
    EXPECT_TRUE(security->is_offer_allowed(&its_sec_client_valid, service_1, instance));

    // request with the same credentials and service but with a different instance
    // is_offer_allowed return true because it's define ANY_INSTANCE in the policy
    EXPECT_TRUE(security->is_offer_allowed(&its_sec_client_valid, service_1, any_instance));

    // invalid credential for the service / instance
    EXPECT_TRUE(security->is_offer_allowed(&its_sec_client_invalid_uid_valid_gid, service_1, instance));
    EXPECT_TRUE(security->is_offer_allowed(&its_sec_client_valid_uid_invalid_gid, service_1, instance));
    EXPECT_TRUE(security->is_offer_allowed(&its_sec_client_invalid, service_1, instance));

    // test deny offer
    // deny client with credentials for the service
    EXPECT_TRUE(security->is_offer_allowed(&its_sec_client_deny, deny_service, instance));
    // credentials exists in deny policy, but not for that service
    EXPECT_TRUE(security->is_offer_allowed(&its_sec_client_deny, service_1, instance));

    // ANY_UID and ANY_GID
    EXPECT_TRUE(security->is_offer_allowed(&its_sec_client_any, service_1, instance));
}
