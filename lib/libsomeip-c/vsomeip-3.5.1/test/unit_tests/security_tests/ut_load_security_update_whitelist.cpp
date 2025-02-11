// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <memory>
#include <gtest/gtest.h>
#include <common/utility.hpp>

namespace {
std::string configuration_file { "/vsomeip/0_0/vsomeip_security.json" };
vsomeip_v3::service_t valid_service_id = 0xf91f;
vsomeip_v3::service_t invalid_service_id = 0xf923;
vsomeip_v3::uid_t valid_uid = 4017205;
vsomeip_v3::uid_t invalid_uid = 111111;
}

// Since this set of tests check a private method, there is the need to indirectly change the
// parameters used by load_security_update_whitelist, and check its changes using other methods.
// The is_policy_removal_allowed method checks if a selected uid is present in the whitelist.
// The is_policy_update_allowed method checks if a selected service_id is present in the whitelist.

TEST(load_security_update_whitelist, check_uids)
{
    // LOADED POLICY W/O UIDS ON SECURITY WHITELIST ---------------------------------------------//
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    // Force load of some policies.
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::set<std::string> input { utility::get_policies_path() + configuration_file };
    utility::read_data(input, policy_elements, its_failed);

    // Check if the load worked.
    ASSERT_EQ(its_failed.size(), 0);

    std::vector<vsomeip_v3::service_t> services;
    utility::get_policy_services(policy_elements.at(0), services);

    // Add a security whitelist with an empty list of user uids.
    std::vector<vsomeip_v3::uid_t> user_ids;
    utility::add_security_whitelist(policy_elements.at(0), user_ids, services, true);

    // Using load function to indirectly call load_security_update_whitelist.
    security->load(policy_elements.at(0));

    // Check that the valid and invalid uids are not present in the whitelist by calling a method
    // that verifies that condition.
    ASSERT_FALSE(security->is_policy_removal_allowed(valid_uid))
            << "The whitelist unexpectedly holds a valid uid";

    ASSERT_FALSE(security->is_policy_removal_allowed(invalid_uid))
            << "The whitelist unexpectedly holds an invalid uid";

    // LOADED POLICY WITH UIDS ON SECURITY WHITELIST ---------------------------------------------//
    utility::get_policy_uids(policy_elements.at(0), user_ids);

    // Add a security whitelist with list of user uids loaded.
    utility::add_security_whitelist(policy_elements.at(0), user_ids, services, true);

    // Using load function to indirectly call load_security_update_whitelist.
    security->load(policy_elements.at(0));

    // Check that the valid and invalid uids are not present in the whitelist by calling a method
    // that verifies that condition.
    ASSERT_TRUE(security->is_policy_removal_allowed(valid_uid))
            << "The whitelist expected to hold a valid uid";

    ASSERT_FALSE(security->is_policy_removal_allowed(invalid_uid))
            << "The whitelist unexpectedly holds an invalid uid";
}

TEST(load_security_update_whitelist, check_service_ids)
{
    // LOADED POLICY W/O SERVICE IDS ON SECURITY WHITELIST -------------------------------------//
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    // Force load of some policies.
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::set<std::string> input { utility::get_policies_path() + configuration_file };
    utility::read_data(input, policy_elements, its_failed);

    // Check if the load worked.
    ASSERT_EQ(its_failed.size(), 0);

    std::vector<vsomeip_v3::uid_t> user_ids;
    utility::get_policy_uids(policy_elements.at(0), user_ids);

    // Add a security whitelist with an empty list of service ids.
    std::vector<vsomeip_v3::service_t> services;
    utility::add_security_whitelist(policy_elements.at(0), user_ids, services, true);

    // Using load function to indirectly call load_security_update_whitelist.
    security->load(policy_elements.at(0));

    std::shared_ptr<vsomeip::policy> policy(std::make_shared<vsomeip::policy>());

    vsomeip::service_t its_service(valid_service_id);
    vsomeip::service_t its_invalid_service(invalid_service_id);

    boost::icl::discrete_interval<vsomeip::instance_t> its_instances(0x1, 0x2);
    boost::icl::interval_set<vsomeip::method_t> its_methods;
    its_methods.insert(boost::icl::interval<vsomeip::method_t>::closed(0x01, 0x2));
    boost::icl::interval_map<vsomeip::instance_t, boost::icl::interval_set<vsomeip::method_t>>
            its_instances_methods;
    its_instances_methods += std::make_pair(its_instances, its_methods);

    // Add a valid request to the policy
    policy->requests_ +=
            std::make_pair(boost::icl::discrete_interval<vsomeip::service_t>(
                                   its_service, its_service, boost::icl::interval_bounds::closed()),
                           its_instances_methods);

    // Check its presence using the is_policy_update_allowed method.
    ASSERT_FALSE(security->is_policy_update_allowed(valid_uid, policy))
            << "The whitelist unexpectedly holds a valid service_id";

    // Add an invalid request to the policy
    policy->requests_ += std::make_pair(boost::icl::discrete_interval<vsomeip::service_t>(
                                                 its_invalid_service, its_invalid_service,
                                                 boost::icl::interval_bounds::closed()),
                                         its_instances_methods);

    // Check its presence using the is_policy_update_allowed method.
    ASSERT_FALSE(security->is_policy_update_allowed(valid_uid, policy))
            << "The whitelist unexpectedly holds an invalid service_id";

    // LOADED POLICY WITH SERVICE IDS ON SECURITY WHITELIST --------------------------------------//
    utility::get_policy_services(policy_elements.at(0), services);
    utility::add_security_whitelist(policy_elements.at(0), user_ids, services, true);

    security->load(policy_elements.at(0));

    // Reset the policies pointer to add a correct serviceid and an incorrect one.
    policy->requests_.clear();

    // Add a valid request to the policy.
    policy->requests_ +=
            std::make_pair(boost::icl::discrete_interval<vsomeip::service_t>(
                                   its_service, its_service, boost::icl::interval_bounds::closed()),
                           its_instances_methods);

    // Check its presence using the is_policy_update_allowed method.
    ASSERT_TRUE(security->is_policy_update_allowed(valid_uid, policy))
            << "The whitelist expected to hold a valid service_id";

    // Add an invalid request to the policy.
    policy->requests_ += std::make_pair(boost::icl::discrete_interval<vsomeip::service_t>(
                                                 its_invalid_service, its_invalid_service,
                                                 boost::icl::interval_bounds::closed()),
                                         its_instances_methods);

    // Check its presence using the is_policy_update_allowed method.
    ASSERT_FALSE(security->is_policy_update_allowed(invalid_uid, policy))
            << "The whitelist unexpectedly holds an invalid service_id";
}

TEST(load_security_update_whitelist, check_whitelist_disabled)
{
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    // Force load of some policies.
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::set<std::string> input { utility::get_policies_path() + configuration_file };
    utility::read_data(input, policy_elements, its_failed);

    // Check if the load worked.
    ASSERT_EQ(its_failed.size(), 0);

    std::vector<vsomeip_v3::uid_t> user_ids;
    utility::get_policy_uids(policy_elements.at(0), user_ids);

    std::vector<vsomeip_v3::service_t> services;
    utility::get_policy_services(policy_elements.at(0), services);

    // Add a security whitelist with check_whitelist disabled.
    utility::add_security_whitelist(policy_elements.at(0), user_ids, services, false);

    security->load(policy_elements.at(0));

    std::shared_ptr<vsomeip::policy> policy(std::make_shared<vsomeip::policy>());

    vsomeip::service_t its_service(valid_service_id);
    vsomeip::service_t its_invalid_service(invalid_service_id);

    boost::icl::discrete_interval<vsomeip::instance_t> its_instances(0x1, 0x2);
    boost::icl::interval_set<vsomeip::method_t> its_methods;
    its_methods.insert(boost::icl::interval<vsomeip::method_t>::closed(0x01, 0x2));
    boost::icl::interval_map<vsomeip::instance_t, boost::icl::interval_set<vsomeip::method_t>>
            its_instances_methods;
    its_instances_methods += std::make_pair(its_instances, its_methods);

    // Add a valid request to the policy.
    policy->requests_ +=
            std::make_pair(boost::icl::discrete_interval<vsomeip::service_t>(
                                   its_service, its_service, boost::icl::interval_bounds::closed()),
                           its_instances_methods);

    ASSERT_TRUE(security->is_policy_removal_allowed(valid_uid))
            << "The whitelist is disabled, a valid uid should be allowed to be removed";

    ASSERT_TRUE(security->is_policy_removal_allowed(invalid_uid))
            << "The whitelist is disabled, an invalid uid should be allowed to be removed";

    ASSERT_TRUE(security->is_policy_update_allowed(valid_uid, policy))
            << "The whitelist is disabled, a valid service_id should be allowed to be updated";

    // Add an invalid request to the policy.
    policy->requests_ += std::make_pair(boost::icl::discrete_interval<vsomeip::service_t>(
                                                 its_invalid_service, its_invalid_service,
                                                 boost::icl::interval_bounds::closed()),
                                         its_instances_methods);

    ASSERT_TRUE(security->is_policy_update_allowed(valid_uid, policy))
            << "The whitelist is disabled, a valid service_id should be allowed to be updated";
}
