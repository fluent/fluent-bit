// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <benchmark/benchmark.h>

#include <common/utility.hpp>

namespace
{
    std::string configuration_file{"/vsomeip/vsomeip_policy_extensions.json"}; // set configuration file policy extension
}

static void BM_configuration_element(benchmark::State &state)
{
    // Test object path
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    // Set element
    std::vector<vsomeip_v3::configuration_element> full_element = {};

    // After load try again and check size
    std::set<std::string> its_failed;
    std::vector<std::string> dir_skip;
    utility::read_data(utility::get_all_files_in_dir(
                           utility::get_policies_path(), dir_skip),
                       full_element, its_failed);

    // Load element and force lazy load = false
    for (auto _ : state)
    {
        security->load(full_element.at(0), false);
    }
}

static void BM_lazy_load(benchmark::State &state)
{
    // Test object path
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    // Set element and lazy load = true
    std::vector<vsomeip_v3::configuration_element> element = {};
    const bool lazy_load = true;

    // Load
    std::set<std::string> its_failed;
    std::vector<std::string> dir_skip;
    utility::read_data(utility::get_all_files_in_dir(
                           utility::get_policies_path(), dir_skip),
                       element, its_failed);

    for (auto _ : state)
    {
        security->load(element.at(0), lazy_load);
    }
}

BENCHMARK(BM_configuration_element);
BENCHMARK(BM_lazy_load);
