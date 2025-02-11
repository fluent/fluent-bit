// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <benchmark/benchmark.h>

#include <common/utility.hpp>

namespace {

vsomeip_v3::uid_t uid_1 = 4003016;
vsomeip_v3::gid_t gid_1 = 4003016;
vsomeip_sec_ip_addr_t host_address = 0;
vsomeip_v3::service_t service_1 = 0xf8c2;

vsomeip_v3::service_t deny_service = 0x40;

vsomeip_v3::instance_t instance = 0x03;

vsomeip_v3::uid_t invalid_uid = 1;
vsomeip_v3::gid_t invalid_gid = 1;

vsomeip_v3::gid_t deny_uid  = 9000;
vsomeip_v3::gid_t deny_gid  = 9000;
}

static void BM_is_offer_allowed_policies_not_loaded(benchmark::State& state) {
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    vsomeip_sec_client_t its_sec_client_invalid = utility::create_uds_client(invalid_uid, invalid_gid, host_address);

    for (auto _ : state)
    {
        security->is_offer_allowed(&its_sec_client_invalid, service_1, instance);
    }
}

static void BM_is_offer_allowed_policies_loaded_valid_values(benchmark::State& state) {
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    //force load of some policies
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::vector<std::string> dir_skip;
    utility::read_data(utility::get_all_files_in_dir(utility::get_policies_path(), dir_skip), policy_elements, its_failed);

    vsomeip_sec_client_t its_sec_client_valid = utility::create_uds_client(uid_1, gid_1, host_address);

    for (const auto& e : policy_elements) {
        security->load(e, false);
    }

    for (auto _ : state) {
        security->is_offer_allowed(&its_sec_client_valid, service_1, instance);
    }
}

static void BM_is_offer_allowed_policies_loaded_invalid_values(benchmark::State& state) {
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    //force load of some policies
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::vector<std::string> dir_skip;
    utility::read_data(utility::get_all_files_in_dir(utility::get_policies_path(), dir_skip), policy_elements, its_failed);

    vsomeip_sec_client_t its_sec_client_invalid = utility::create_uds_client(invalid_uid, invalid_gid, host_address);

    for (const auto& e : policy_elements) {
        security->load(e, false);
    }

    for (auto _ : state) {
        security->is_offer_allowed(&its_sec_client_invalid, service_1, instance);
    }
}

static void BM_is_offer_allowed_policies_loaded_deny_valid_values(benchmark::State& state) {
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    //force load of some policies
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::vector<std::string> dir_skip;
    utility::read_data(utility::get_all_files_in_dir(utility::get_policies_path(), dir_skip), policy_elements, its_failed);

    vsomeip_sec_client_t its_sec_client_deny = utility::create_uds_client(deny_uid, deny_gid, host_address);

    for (const auto& e : policy_elements) {
        security->load(e, false);
    }

    for (auto _ : state) {
        security->is_offer_allowed(&its_sec_client_deny, deny_service, instance);
    }
}

static void BM_is_offer_allowed_policies_loaded_audit_mode_valid_values(benchmark::State& state) {
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    //force load of some policies
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::vector<std::string> dir_skip;
    utility::read_data(utility::get_all_files_in_dir(utility::get_policies_path(), dir_skip), policy_elements, its_failed);
    utility::force_check_credentials(policy_elements, "false");

    vsomeip_sec_client_t its_sec_client_valid = utility::create_uds_client(uid_1, gid_1, host_address);

    for (const auto& e : policy_elements) {
        security->load(e, false);
    }

    for (auto _ : state) {
        security->is_offer_allowed(&its_sec_client_valid, service_1, instance);
    }
}

static void BM_is_offer_allowed_policies_loaded_audit_mode_invalid_values(benchmark::State& state) {
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    //force load of some policies
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::vector<std::string> dir_skip;
    utility::read_data(utility::get_all_files_in_dir(utility::get_policies_path(), dir_skip), policy_elements, its_failed);
    utility::force_check_credentials(policy_elements, "false");

    vsomeip_sec_client_t its_sec_client_invalid = utility::create_uds_client(invalid_uid, invalid_gid, host_address);

    for (const auto& e : policy_elements) {
        security->load(e, false);
    }

    for (auto _ : state) {
        security->is_offer_allowed(&its_sec_client_invalid, service_1, instance);
    }
}

static void BM_is_offer_allowed_policies_loaded_audit_mode_deny_valid_values(benchmark::State& state) {
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    //force load of some policies
    std::set<std::string> its_failed;
    std::vector<vsomeip_v3::configuration_element> policy_elements;
    std::vector<std::string> dir_skip;
    utility::read_data(utility::get_all_files_in_dir(utility::get_policies_path(), dir_skip), policy_elements, its_failed);
    utility::force_check_credentials(policy_elements, "false");

    vsomeip_sec_client_t its_sec_client_deny = utility::create_uds_client(deny_uid, deny_gid, host_address);

    for (const auto& e : policy_elements) {
        security->load(e, false);
    }

    for (auto _ : state) {
        security->is_offer_allowed(&its_sec_client_deny, deny_service, instance);
    }
}

BENCHMARK(BM_is_offer_allowed_policies_not_loaded);
BENCHMARK(BM_is_offer_allowed_policies_loaded_valid_values);
BENCHMARK(BM_is_offer_allowed_policies_loaded_invalid_values);
BENCHMARK(BM_is_offer_allowed_policies_loaded_deny_valid_values);
BENCHMARK(BM_is_offer_allowed_policies_loaded_audit_mode_valid_values);
BENCHMARK(BM_is_offer_allowed_policies_loaded_audit_mode_invalid_values);
BENCHMARK(BM_is_offer_allowed_policies_loaded_audit_mode_deny_valid_values);
