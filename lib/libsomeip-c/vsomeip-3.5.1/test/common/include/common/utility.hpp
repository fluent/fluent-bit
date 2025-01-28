// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <vsomeip/vsomeip.hpp>

#include "../../../implementation/configuration/include/configuration_impl.hpp"
#include "../../../implementation/routing/include/routing_manager_impl.hpp"
#include "../../../implementation/security/include/policy_manager_impl.hpp"
#include "../../../implementation/configuration/include/configuration_impl.hpp"
#include "../../../implementation/utility/include/utility.hpp"

// This is needed to silence internal warnings in boost, when e.g. including <boost/property_tree/json_parser.hpp>
#define BOOST_BIND_GLOBAL_PLACEHOLDERS

#include <boost/filesystem.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <iostream>

class utility {
public:
    static void load_policy_data(std::string _input,
        std::vector<vsomeip_v3::configuration_element> &_elements,
        std::set<std::string> &_failed);

    static void read_data(const std::set<std::string> &_input,
        std::vector<vsomeip_v3::configuration_element> &_elements, std::set<std::string> &_failed);

    static std::set<std::string> get_all_files_in_dir(const std::string &_dir_path,
        const std::vector<std::string> &_dir_skip_list);

    static std::string get_policies_path();

    static vsomeip_sec_client_t create_uds_client(uid_t user, gid_t group, vsomeip_sec_ip_addr_t host);

    static void force_check_credentials(std::vector<vsomeip_v3::configuration_element> &_policy_elements, std::string _value);
    /**
     * @brief Get all of the user ids in the given policy element.
     *
     * @param _policy_element
     * @param _out_uids
     */
    static void get_policy_uids(vsomeip_v3::configuration_element &_policy_element,
                                std::vector<vsomeip_v3::uid_t> &_out_uids);

    /**
     * @brief Get all of the services in the given policy element.
     *
     * @param _policy_element
     * @param _out_services
     */
    static void get_policy_services(vsomeip_v3::configuration_element &_policy_element,
                                    std::vector<vsomeip_v3::service_t> &_out_services);

    /**
     * @brief Add a security whitelist to the given policy element. Uses all user ids and
     * services mentioned in the policy.
     *
     * @param _policy_element
     * @param _check_whitelist
     */
    static void add_security_whitelist(vsomeip_v3::configuration_element &_policy_element,
                                       const bool _check_whitelist);

    /**
     * @brief Add a security whitelist with the given ids and services to the policy element.
     *
     * @param _policy_element
     * @param _user_ids
     * @param _services
     * @param _check_whitelist
     */
    static void add_security_whitelist(vsomeip_v3::configuration_element &_policy_element,
                                       const std::vector<vsomeip_v3::uid_t> &_user_ids,
                                       const std::vector<vsomeip_v3::service_t> &_services,
                                       const bool _check_whitelist);
};
