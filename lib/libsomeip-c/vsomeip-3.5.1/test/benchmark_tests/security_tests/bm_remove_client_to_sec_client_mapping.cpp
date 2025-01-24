// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <benchmark/benchmark.h>

#include <common/utility.hpp>

namespace{
vsomeip_v3::client_t client = 10;
vsomeip_v3::uid_t uid = 4003030;
vsomeip_v3::gid_t gid = 4003032;
vsomeip_sec_ip_addr_t host_address = 0;

std::pair<uint32_t, uint32_t> client_uid_gid{uid, gid};
}

static void BM_remove_client_to_sec_client_mapping_invalid_values(benchmark::State &state)
{
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    vsomeip_sec_client_t its_sec_client = utility::create_uds_client(uid, gid, host_address);

    for (auto _ : state) {
        security->get_client_to_sec_client_mapping(client, its_sec_client);
    }

    for (auto _ : state) {
        security->remove_client_to_sec_client_mapping(client);
    }
}

static void BM_remove_client_to_sec_client_mapping_valid_values(benchmark::State &state)
{
    std::unique_ptr<vsomeip_v3::policy_manager_impl> security(new vsomeip_v3::policy_manager_impl);

    vsomeip_sec_client_t its_sec_client = utility::create_uds_client(uid, gid, host_address);

    security->store_client_to_sec_client_mapping(client, &its_sec_client);
    security->store_sec_client_to_client_mapping(&its_sec_client, client);

    for (auto _ : state) {
        security->get_client_to_sec_client_mapping(client, its_sec_client);
    }

    for (auto _ : state) {
        security->remove_client_to_sec_client_mapping(client);
    }
}

BENCHMARK(BM_remove_client_to_sec_client_mapping_invalid_values);
BENCHMARK(BM_remove_client_to_sec_client_mapping_valid_values);
