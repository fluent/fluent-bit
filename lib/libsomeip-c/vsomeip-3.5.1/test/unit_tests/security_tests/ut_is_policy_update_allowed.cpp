// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <memory>
#include <iostream>
#include <gtest/gtest.h>
#include <common/utility.hpp>

namespace {
std::string configuration_file { "/vsomeip/0_0/vsomeip_security.json" };

vsomeip_v3::uid_t valid_uid { 0 };
vsomeip_v3::uid_t invalid_uid { 1234567 };

vsomeip_v3::gid_t valid_gid { 0 };

vsomeip_v3::service_t valid_service { 0xf913 };
vsomeip_v3::service_t invalid_service { 0x41 };
}

#ifndef __QNX__
TEST(is_policy_update_allowed, check_whitelist_disabled)
{
    // Test object.
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    // Get some configurations.
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::set<std::string> input { utility::get_policies_path() + configuration_file };
    utility::read_data(input, policy_elements, its_failed);

    // Load the configuration into the security.
    ASSERT_GT(policy_elements.size(), 0) << "Failed to fetch policy elements!";
    const bool check_whitelist { false };
    utility::add_security_whitelist(policy_elements.at(0), check_whitelist);
    security->load(policy_elements.at(0), false);

    // Create policy credentials.
    boost::icl::discrete_interval<uid_t> its_uids(valid_uid, valid_uid);
    boost::icl::interval_set<gid_t> its_gids;
    its_gids.insert(boost::icl::interval<gid_t>::closed(valid_gid, valid_gid));

    // Create a policy.
    std::shared_ptr<vsomeip::policy> policy(std::make_shared<vsomeip::policy>());
    policy->credentials_ += std::make_pair(its_uids, its_gids);
    policy->allow_who_ = true;
    policy->allow_what_ = true;

    // NO REQUESTS IN POLICY ---------------------------------------------------------------------//

    EXPECT_TRUE(security->is_policy_update_allowed(invalid_uid, policy))
            << "Failed to allow policy update with invalid user id when check_whitelist is "
               "disabled!";

    EXPECT_TRUE(security->is_policy_update_allowed(valid_uid, policy))
            << "Failed to allow policy update with valid user id when check_whitelist is "
               "disabled!";

    // ONLY VALID REQUESTS IN POLICY -------------------------------------------------------------//

    boost::icl::discrete_interval<vsomeip::instance_t> its_instances(0x1, 0x2);
    boost::icl::interval_set<vsomeip::method_t> its_methods;
    its_methods.insert(boost::icl::interval<vsomeip::method_t>::closed(0x01, 0x2));
    boost::icl::interval_map<vsomeip::instance_t, boost::icl::interval_set<vsomeip::method_t>>
            its_instances_methods;
    its_instances_methods += std::make_pair(its_instances, its_methods);

    // Add a valid request to the policy.
    policy->requests_ += std::make_pair(
            boost::icl::discrete_interval<vsomeip::service_t>(
                    valid_service, valid_service, boost::icl::interval_bounds::closed()),
            its_instances_methods);

    EXPECT_TRUE(security->is_policy_update_allowed(invalid_uid, policy))
            << "Failed to allow policy update with invalid user id and valid request when "
               "check_whitelist is disabled!";

    EXPECT_TRUE(security->is_policy_update_allowed(valid_uid, policy))
            << "Failed to allow policy update with valid user id and valid request when "
               "check_whitelist is disabled!";

    // INVALID REQUESTS IN POLICY ----------------------------------------------------------------//

    // Add a invalid request to the policy.
    policy->requests_ += std::make_pair(
            boost::icl::discrete_interval<vsomeip::service_t>(
                    invalid_service, invalid_service, boost::icl::interval_bounds::closed()),
            its_instances_methods);

    EXPECT_TRUE(security->is_policy_update_allowed(invalid_uid, policy))
            << "Failed to allow policy update with invalid user id and invalid request when "
               "check_whitelist is disabled!";

    EXPECT_TRUE(security->is_policy_update_allowed(valid_uid, policy))
            << "Failed to allow policy update with valid user id and invalid request when "
               "check_whitelist is disabled!";
}

TEST(is_policy_update_allowed, check_whitelist_enabled)
{
    // Test object.
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    // Get some configurations.
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::set<std::string> input { utility::get_policies_path() + configuration_file };
    utility::read_data(input, policy_elements, its_failed);

    // Load the policy into the security.
    ASSERT_GT(policy_elements.size(), 0) << "Failed to fetch policy elements!";
    const bool check_whitelist { true };
    utility::add_security_whitelist(policy_elements.at(0), check_whitelist);
    security->load(policy_elements.at(0), false);

    // Create policy credentials.
    boost::icl::discrete_interval<uid_t> its_uids(valid_uid, valid_uid);
    boost::icl::interval_set<gid_t> its_gids;
    its_gids.insert(boost::icl::interval<gid_t>::closed(valid_gid, valid_gid));

    // Create a policy.
    std::shared_ptr<vsomeip::policy> policy(std::make_shared<vsomeip::policy>());
    policy->credentials_ += std::make_pair(its_uids, its_gids);
    policy->allow_who_ = true;
    policy->allow_what_ = true;

    // NO REQUESTS IN POLICY ---------------------------------------------------------------------//

    EXPECT_FALSE(security->is_policy_update_allowed(invalid_uid, policy))
            << "Failed to deny policy update with invalid user id!";

    EXPECT_TRUE(security->is_policy_update_allowed(valid_uid, policy))
            << "Failed to allow policy update with valid user id!";

    // ONLY VALID REQUESTS IN POLICY -------------------------------------------------------------//

    boost::icl::discrete_interval<vsomeip::instance_t> its_instances(0x1, 0x2);
    boost::icl::interval_set<vsomeip::method_t> its_methods;
    its_methods.insert(boost::icl::interval<vsomeip::method_t>::closed(0x01, 0x2));
    boost::icl::interval_map<vsomeip::instance_t, boost::icl::interval_set<vsomeip::method_t>>
            its_instances_methods;
    its_instances_methods += std::make_pair(its_instances, its_methods);

    // Add valid request to the policy.
    policy->requests_ += std::make_pair(
            boost::icl::discrete_interval<vsomeip::service_t>(
                    valid_service, valid_service, boost::icl::interval_bounds::closed()),
            its_instances_methods);

    EXPECT_FALSE(security->is_policy_update_allowed(invalid_uid, policy))
            << "Failed to deny policy update with invalid user id and valid request!";

    EXPECT_TRUE(security->is_policy_update_allowed(valid_uid, policy))
            << "Failed to allow policy update with valid user id and valid request!";

    // INVALID REQUESTS IN POLICY ----------------------------------------------------------------//

    // Add invalid request to the policy.
    policy->requests_ += std::make_pair(
            boost::icl::discrete_interval<vsomeip::service_t>(
                    invalid_service, invalid_service, boost::icl::interval_bounds::closed()),
            its_instances_methods);

    EXPECT_FALSE(security->is_policy_update_allowed(invalid_uid, policy))
            << "Failed to deny policy update with invalid user id and invalid request!";

    EXPECT_FALSE(security->is_policy_update_allowed(valid_uid, policy))
            << "Failed to deny policy update with valid user id and invalid request!";
}
#endif

TEST(is_policy_update_allowed, null_policy)
{
    // Test objects.
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);
    std::shared_ptr<vsomeip_v3::policy> policy = nullptr;

    // NO POLICIES LOADED ------------------------------------------------------------------------//

    ASSERT_EXIT((security->is_policy_update_allowed(0, policy), exit(0)),
                testing::ExitedWithCode(0), ".*")
            << "Could not handle a nullptr when no policies are loaded!";

    EXPECT_TRUE(security->is_policy_update_allowed(0, policy))
            << "Denied update of policy when security whitelist is not loaded!";

    // LOADED POLICY W/O SECURITY WHITELIST ------------------------------------------------------//

    // Get some configurations.
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::set<std::string> input { utility::get_policies_path() + configuration_file };
    utility::read_data(input, policy_elements, its_failed);

    // Load the policy into the security.
    ASSERT_GT(policy_elements.size(), 0) << "Failed to fetch policy elements!";
    security->load(policy_elements.at(0), false);

    ASSERT_EXIT((security->is_policy_update_allowed(0, policy), exit(0)),
                testing::ExitedWithCode(0), ".*")
            << "Could not handle a nullptr when a policy without a security whitelist was loaded!";

    EXPECT_TRUE(security->is_policy_update_allowed(0, policy))
            << "Denied update of policy when security whitelist is not loaded!";

    // LOADED POLICY W/ SECURITY WHITELIST -------------------------------------------------------//

    // Add a security whitelist to the policy.

    utility::add_security_whitelist(policy_elements.at(0), true);

    security->load(policy_elements.at(0), false);

    ASSERT_EXIT((security->is_policy_update_allowed(0, policy), exit(0)),
                testing::ExitedWithCode(0), ".*")
            << "Could not handle a nullptr when a policy with a security whitelist was loaded!";

    EXPECT_FALSE(security->is_policy_update_allowed(0, policy))
            << "Allowed update of invalid policy!";
}
