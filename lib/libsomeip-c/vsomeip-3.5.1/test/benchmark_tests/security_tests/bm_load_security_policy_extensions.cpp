// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <benchmark/benchmark.h>

#include <common/utility.hpp>

// create valid and invalid user credentials
namespace
{
  std::string configuration_file{
      "/vsomeip/vsomeip_policy_extensions.json"}; // set configuration file policy

} // namespace

static void BM_configuration_element(benchmark::State &state)
{
  // Test object path
  std::unique_ptr<vsomeip_v3::policy_manager_impl> security{
      new vsomeip_v3::policy_manager_impl};

  // set element
  std::vector<vsomeip_v3::configuration_element> element;
  std::vector<vsomeip_v3::configuration_element> full_element;

  // After load try again and check size
  std::set<std::string> its_failed;
  std::vector<std::string> dir_skip;
  utility::read_data(
      utility::get_all_files_in_dir(utility::get_policies_path(), dir_skip),
      full_element, its_failed);

  // load each e into policy_elements
  for (const auto &e : full_element)
  {
    security->load(e, false); // for each e in policy_elements vector load e
  }

  // force lazy load = false
  for (auto _ : state)
  {
    security->load(full_element.at(0), false);
  }
}

static void BM_is_policy_extension_loaded(benchmark::State &state)
{
  // Test object path.
  std::unique_ptr<vsomeip_v3::policy_manager_impl> security{
      new vsomeip_v3::policy_manager_impl};

  // Set element.
  std::vector<vsomeip_v3::configuration_element> policy_elements;

  // Force Load of policies.
  std::set<std::string> its_failed;
  std::set<std::string> input{utility::get_policies_path() +
                              configuration_file};
  utility::read_data(input, policy_elements, its_failed);

  // Load policies.
  security->load(policy_elements.at(0));

  // Check JSON container string.
  std::string policy_extension_container{"android-rse"};

  // Set extension as loaded.
  bool loaded_extension = true;

  for (auto _ : state)
  {
    security->set_is_policy_extension_loaded(policy_extension_container, loaded_extension);
  }
}

static void BM_is_policy_extension_not_loaded(benchmark::State &state)
{
  // Test object path.
  std::unique_ptr<vsomeip_v3::policy_manager_impl> security{
      new vsomeip_v3::policy_manager_impl};

  // Set element.
  std::vector<vsomeip_v3::configuration_element> policy_elements;

  // Force Load of policies.
  std::set<std::string> its_failed;
  std::set<std::string> input{utility::get_policies_path() +
                              configuration_file};
  utility::read_data(input, policy_elements, its_failed);

  // Load policies.
  security->load(policy_elements.at(0));

  // Check JSON container string.
  std::string policy_extension_container{"android-rse"};

  // Set extension NOT loaded.
  bool loaded_extension = false;

  for (auto _ : state)
  {
    security->set_is_policy_extension_loaded(policy_extension_container, loaded_extension);
  }
}

static void BM_is_policy_extension_not_found(benchmark::State &state)
{
  // Test object path
  std::unique_ptr<vsomeip_v3::policy_manager_impl> security{
      new vsomeip_v3::policy_manager_impl};

  // set element
  std::vector<vsomeip_v3::configuration_element> policy_elements;

  for (auto _ : state)
  {
    security->is_policy_extension_loaded("");
  }
}

BENCHMARK(BM_configuration_element);
BENCHMARK(BM_is_policy_extension_loaded);
BENCHMARK(BM_is_policy_extension_not_loaded);
BENCHMARK(BM_is_policy_extension_not_found);
