// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <gtest/gtest.h>
#include <common/utility.hpp>
#include <benchmark/benchmark.h>

namespace {
std::string configuration_file { "/vsomeip/0_0/vsomeip_security.json" };
}

// Since this set of tests check a private method, there is the need to indirectly change the
// parameters used by load_policies, and check its changes using other methods.
// The remove_security_policy method checks if there is any loaded policy.
// The is_audit method checks the check_credentials value.
// No test was created for allow_remote_clients because it was inacessible.

static void BM_load_policies_loaded_policies(benchmark::State &state)
{
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    // Force load of some policies.
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::set<std::string> input { utility::get_policies_path() + configuration_file };
    utility::read_data(input, policy_elements, its_failed);

    // Using load function to indirectly call load_policies.
    for (auto _ : state) {
        security->load(policy_elements.at(0));
    }
}

static void BM_load_policies_no_policies(benchmark::State &state)
{
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    // Force load of some policies.
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::set<std::string> input { utility::get_policies_path() + configuration_file };
    utility::read_data(input, policy_elements, its_failed);

    // Remove all the policies from the file.
    policy_elements.at(0).tree_.get_child("security").erase("policies");

    // Using load function to indirectly call load_policies.
    for (auto _ : state) {
        security->load(policy_elements.at(0));
    }
}

static void  BM_load_policies_check_credentials_true(benchmark::State &state)
{
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    // Force load of some policies without the check credentials value set.
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::set<std::string> input { utility::get_policies_path() + configuration_file };
    utility::read_data(input, policy_elements, its_failed);

    // Load the check credentials value as false.
    bool check_credentials_value {true};
    policy_elements.at(0).tree_.add<bool>("security.check_credentials", check_credentials_value);

    // Using load function to indirectly call load_policies.
    for (auto _ : state) {
        security->load(policy_elements.at(0));
    }
}

static void  BM_load_policies_check_credentials_false(benchmark::State &state)
{
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    // Force load of some policies without the check credentials value set.
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::set<std::string> input { utility::get_policies_path() + configuration_file };
    utility::read_data(input, policy_elements, its_failed);

    // Load the check credentials value as false.
    bool check_credentials_value {false};
    policy_elements.at(0).tree_.add<bool>("security.check_credentials", check_credentials_value);

    // Using load function to indirectly call load_policies.
    for (auto _ : state) {
        security->load(policy_elements.at(0));
    }
}

BENCHMARK(BM_load_policies_loaded_policies);
BENCHMARK(BM_load_policies_no_policies);
BENCHMARK(BM_load_policies_check_credentials_true);
BENCHMARK(BM_load_policies_check_credentials_false);
