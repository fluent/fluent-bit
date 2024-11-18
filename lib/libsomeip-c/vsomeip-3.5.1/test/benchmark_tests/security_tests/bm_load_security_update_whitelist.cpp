// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <benchmark/benchmark.h>
#include <common/utility.hpp>
namespace {
std::string configuration_file { "/vsomeip/0_0/vsomeip_security.json" };
}

// Since this set of tests check a private method, there is the need to indirectly change the
// parameters used by load_security_update_whitelist, and check its changes using other methods.
// The is_policy_removal_allowed method checks if a selected uid is present in the whitelist.
// The is_policy_update_allowed method checks if a selected service_id is present in the whitelist.

static void BM_load_security_update_whitelist_check_no_uids_loaded(benchmark::State &state)
{
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    // Force load of some policies.
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::set<std::string> input { utility::get_policies_path() + configuration_file };
    utility::read_data(input, policy_elements, its_failed);

    std::vector<vsomeip_v3::uid_t> user_ids;

    std::vector<vsomeip_v3::service_t> services;
    utility::get_policy_services(policy_elements.at(0), services);

    // Add a security whitelist with an empty list of user uids.
    utility::add_security_whitelist(policy_elements.at(0), user_ids, services, true);

    // Using load function to indirectly call load_security_update_whitelist.
    for (auto _ : state) {
    security->load(policy_elements.at(0));
    }
}

static void BM_load_security_update_whitelist_check_uids_loaded(benchmark::State &state)
{
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    // Force load of some policies.
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::set<std::string> input { utility::get_policies_path() + configuration_file };
    utility::read_data(input, policy_elements, its_failed);

    std::vector<vsomeip_v3::uid_t> user_ids;
    utility::get_policy_uids(policy_elements.at(0), user_ids);

    std::vector<vsomeip_v3::service_t> services;
    utility::get_policy_services(policy_elements.at(0), services);

    // Add a security whitelist with a list of uids loaded
    utility::add_security_whitelist(policy_elements.at(0), user_ids, services, true);

    // Using load function to indirectly call load_security_update_whitelist.
    for (auto _ : state) {
    security->load(policy_elements.at(0));
    }
}

static void BM_load_security_update_whitelist_check_no_service_ids_loaded(benchmark::State &state)
{
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    // Force load of some policies with an empty service id vector.
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::set<std::string> input { utility::get_policies_path() + configuration_file };
    utility::read_data(input, policy_elements, its_failed);

    std::vector<vsomeip_v3::uid_t> user_ids;
    utility::get_policy_uids(policy_elements.at(0), user_ids);

    std::vector<vsomeip_v3::service_t> services;

    // Add a security whitelist with an empty list of user uids.
    utility::add_security_whitelist(policy_elements.at(0), user_ids, services, true);

    // Using load function to indirectly call load_security_update_whitelist.
    for (auto _ : state) {
        security->load(policy_elements.at(0));
    }
}

static void BM_load_security_update_whitelist_check_service_ids_loaded(benchmark::State &state)
{
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    // Force load of some policies.
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::set<std::string> input { utility::get_policies_path() + configuration_file };
    utility::read_data(input, policy_elements, its_failed);

    std::vector<vsomeip_v3::uid_t> user_ids;
    utility::get_policy_uids(policy_elements.at(0), user_ids);

    std::vector<vsomeip_v3::service_t> services;
    utility::get_policy_services(policy_elements.at(0), services);

    // Add a security whitelist with list of service ids loaded.
    utility::add_security_whitelist(policy_elements.at(0), user_ids, services, true);

    // Using load function to indirectly call load_security_update_whitelist.
    for (auto _ : state) {
        security->load(policy_elements.at(0));
    }
}

static void BM_load_security_update_whitelist_check_whitelist_disabled(benchmark::State &state)
{
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    // Force load of some policies.
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::set<std::string> input { utility::get_policies_path() + configuration_file };
    utility::read_data(input, policy_elements, its_failed);

    std::vector<vsomeip_v3::uid_t> user_ids;
    utility::get_policy_uids(policy_elements.at(0), user_ids);

    std::vector<vsomeip_v3::service_t> services;
    utility::get_policy_services(policy_elements.at(0), services);

    // Add a security whitelist with check_whitelist disabled
    utility::add_security_whitelist(policy_elements.at(0), user_ids, services, false);

    // Using load function to indirectly call load_security_update_whitelist.
    for (auto _ : state) {
        security->load(policy_elements.at(0));
    }
}

BENCHMARK(BM_load_security_update_whitelist_check_no_uids_loaded);
BENCHMARK(BM_load_security_update_whitelist_check_no_service_ids_loaded);
BENCHMARK(BM_load_security_update_whitelist_check_uids_loaded);
BENCHMARK(BM_load_security_update_whitelist_check_service_ids_loaded);
BENCHMARK(BM_load_security_update_whitelist_check_whitelist_disabled);
