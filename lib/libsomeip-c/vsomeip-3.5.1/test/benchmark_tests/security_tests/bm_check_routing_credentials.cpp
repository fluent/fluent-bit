// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <benchmark/benchmark.h>

#include <common/utility.hpp>

namespace{
vsomeip_v3::uid_t invalid_uid = 1;
vsomeip_v3::uid_t valid_uid = 4003017;
vsomeip_v3::gid_t invalid_gid = 1;
vsomeip_v3::gid_t valid_gid = 5002;
vsomeip_sec_ip_addr_t host_address = 0;
}

static void BM_check_routing_credentials_policies_not_loaded(benchmark::State& state) {
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    vsomeip_sec_client_t its_sec_client_invalid = utility::create_uds_client(invalid_uid, invalid_gid, host_address);

    for (auto _ : state)
        security->check_routing_credentials(&its_sec_client_invalid);
}

static void BM_check_routing_credentials_policies_loaded_invalid_values(benchmark::State& state) {
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::vector<std::string> dir_skip;

    vsomeip_sec_client_t its_sec_client_invalid = utility::create_uds_client(invalid_uid, invalid_gid, host_address);

    utility::read_data(utility::get_all_files_in_dir(utility::get_policies_path(), dir_skip), policy_elements, its_failed);
    for (const auto& e : policy_elements) {
        security->load(e, false);
    }

    for (auto _ : state)
        security->check_routing_credentials(&its_sec_client_invalid);
}

static void BM_check_routing_credentials_policies_loaded_valid_values(benchmark::State& state) {
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    vsomeip_sec_client_t its_sec_client_valid = utility::create_uds_client(valid_uid, valid_gid, host_address);

    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::vector<std::string> dir_skip;
    utility::read_data(utility::get_all_files_in_dir(utility::get_policies_path(), dir_skip), policy_elements, its_failed);
    for (const auto& e : policy_elements) {
        security->load(e, false);
    }

    for (auto _ : state)
        security->check_routing_credentials(&its_sec_client_valid);
}

static void BM_check_routing_credentials_policies_loaded_lazy_load_invalid_values(benchmark::State& state) {
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    vsomeip_sec_client_t its_sec_client_invalid = utility::create_uds_client(invalid_uid, invalid_gid, host_address);

    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::vector<std::string> dir_skip;
    utility::read_data(utility::get_all_files_in_dir(utility::get_policies_path(), dir_skip), policy_elements, its_failed);
    for (const auto& e : policy_elements) {
        security->load(e, true);
    }

    for (auto _ : state)
        security->check_routing_credentials(&its_sec_client_invalid);
}

static void BM_check_routing_credentials_policies_loaded_lazy_load_valid_values(benchmark::State& state) {
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    vsomeip_sec_client_t its_sec_client_valid = utility::create_uds_client(valid_uid, valid_gid, host_address);

    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::vector<std::string> dir_skip;
    utility::read_data(utility::get_all_files_in_dir(utility::get_policies_path(), dir_skip), policy_elements, its_failed);
    for (const auto& e : policy_elements) {
        security->load(e, true);
    }

    for (auto _ : state)
        security->check_routing_credentials(&its_sec_client_valid);
}

BENCHMARK(BM_check_routing_credentials_policies_not_loaded);
BENCHMARK(BM_check_routing_credentials_policies_loaded_invalid_values);
BENCHMARK(BM_check_routing_credentials_policies_loaded_valid_values);
BENCHMARK(BM_check_routing_credentials_policies_loaded_lazy_load_invalid_values);
BENCHMARK(BM_check_routing_credentials_policies_loaded_lazy_load_valid_values);
