// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <benchmark/benchmark.h>

#include <common/utility.hpp>

namespace{
vsomeip_v3::client_t client = 10;
vsomeip_v3::uid_t uid_1 = 4003030;
vsomeip_v3::gid_t gid_1 = 4003032;
vsomeip_v3::uid_t uid_2 = 1;
vsomeip_v3::gid_t gid_2 = 1;
vsomeip_sec_ip_addr_t host_address = 0;
}

static void BM_get_sec_client_to_clients_mapping_valid_values(benchmark::State &state)
{
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    vsomeip_sec_client_t its_sec_client_uid_gid = utility::create_uds_client(uid_1, gid_1, host_address);
    vsomeip_sec_client_t its_sec_client_uid_gid_alternate = utility::create_uds_client(uid_2, gid_2, host_address);

    // Add client and uid_gid mappings.
    security->store_sec_client_to_client_mapping(&its_sec_client_uid_gid, client);

    std::set<vsomeip_v3::client_t> clients_1;
    for (auto _ : state) {
        security->get_sec_client_to_clients_mapping(&its_sec_client_uid_gid, clients_1);
    }

    // Add alternate client and uid_gid mappings.
    security->store_sec_client_to_client_mapping(&its_sec_client_uid_gid_alternate, client);

    std::set<vsomeip_v3::client_t> clients_2;
    for (auto _ : state) {
        security->get_sec_client_to_clients_mapping(&its_sec_client_uid_gid_alternate, clients_2);
    }
}

static void BM_get_sec_client_to_clients_mapping_invalid_values(benchmark::State &state)
{
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    vsomeip_sec_client_t its_sec_client_uid_gid = utility::create_uds_client(uid_1, gid_1, host_address);
    vsomeip_sec_client_t its_sec_client_uid_gid_alternate = utility::create_uds_client(uid_2, gid_2, host_address);

    std::set<vsomeip_v3::client_t> clients;
    for (auto _ : state) {
        security->get_sec_client_to_clients_mapping(&its_sec_client_uid_gid, clients);
    }

    for (auto _ : state) {
        security->get_sec_client_to_clients_mapping(&its_sec_client_uid_gid_alternate, clients);
    }
}

BENCHMARK(BM_get_sec_client_to_clients_mapping_valid_values);
BENCHMARK(BM_get_sec_client_to_clients_mapping_invalid_values);
