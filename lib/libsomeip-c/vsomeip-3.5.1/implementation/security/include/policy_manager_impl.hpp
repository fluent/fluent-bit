// Copyright (C) 2019-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_SECURITY_POLICY_MANAGER_IMPL_HPP_
#define VSOMEIP_V3_SECURITY_POLICY_MANAGER_IMPL_HPP_

#include <map>
#include <mutex>
#include <unordered_set>
#include <vector>

#include <boost/property_tree/ptree.hpp>
#include <boost/filesystem.hpp>
#include <boost/thread.hpp>

#include <vsomeip/export.hpp>
#include <vsomeip/internal/policy_manager.hpp>
#include <vsomeip/vsomeip_sec.h>

#include "../include/policy.hpp"

namespace vsomeip_v3 {

struct configuration_element;

class VSOMEIP_IMPORT_EXPORT policy_manager_impl
#ifndef VSOMEIP_DISABLE_SECURITY
        : public policy_manager
#endif // !VSOMEIP_DISABLE_SECURITY
{
public:
    enum class policy_loaded_e : std::uint8_t {
        POLICY_PATH_FOUND_AND_LOADED = 0x0,
        POLICY_PATH_FOUND_AND_NOT_LOADED = 0x1,
        POLICY_PATH_INEXISTENT = 0x2
    };

    policy_manager_impl();

#ifndef VSOMEIP_DISABLE_SECURITY
    // policy_manager interface
    std::shared_ptr<policy> create_policy() const;
    void print_policy(const std::shared_ptr<policy> &_policy) const;

    bool parse_uid_gid(const byte_t* &_buffer, uint32_t &_buffer_size,
            uid_t &_uid, gid_t &_gid) const;
    bool parse_policy(const byte_t* &_buffer, uint32_t &_buffer_size,
            uid_t &_uid, gid_t &_gid,
            const std::shared_ptr<policy> &_policy) const;

    bool is_policy_update_allowed(uid_t _uid,
            std::shared_ptr<policy> &_policy) const;
    bool is_policy_removal_allowed(uid_t _uid) const;

    // extension
    void load(const configuration_element &_element,
            const bool _lazy_load = false);

    void update_security_policy(uid_t _uid, uid_t _gid, const std::shared_ptr<policy>& _policy);
    bool remove_security_policy(uid_t _uid, uid_t _gid);

    void add_security_credentials(uid_t _uid, uid_t _gid,
            const std::shared_ptr<policy>& _credentials_policy, client_t _client);

    void get_requester_policies(const std::shared_ptr<policy> _policy,
            std::set<std::shared_ptr<policy> > &_requesters) const;
    void get_clients(uid_t _uid, gid_t _gid, std::unordered_set<client_t> &_clients) const;

    bool is_policy_extension(const std::string &_path) const;
    std::string get_policy_extension_path(const std::string &_client_host) const;

    void set_policy_extension_base_path(const std::string &_path);
    std::string get_security_config_folder(const std::string &its_folder) const;
    std::string get_policy_extension_path_unlocked(const std::string &_client_host) const;

    policy_loaded_e is_policy_extension_loaded(const std::string &_client_host) const;
    void set_is_policy_extension_loaded(const std::string &_client_host, const bool _loaded);

private:

    // Configuration
    bool exist_in_any_client_policies_unlocked(std::shared_ptr<policy> &_policy);
    void load_policies(const configuration_element &_element);
    void load_policy(const boost::property_tree::ptree &_tree);
    void load_policy_body(std::shared_ptr<policy> &_policy,
            const boost::property_tree::ptree::const_iterator &_tree);
    void load_credential(const boost::property_tree::ptree &_tree,
            boost::icl::interval_map<uid_t, boost::icl::interval_set<gid_t> > &_ids);
    bool load_routing_credentials(const configuration_element &_element);
    template<typename T_>
    void load_interval_set(const boost::property_tree::ptree &_tree,
            boost::icl::interval_set<T_> &_range, bool _exclude_margins = false);
    void load_security_update_whitelist(const configuration_element &_element);
    void load_security_policy_extensions(const configuration_element &_element);
#endif // !VSOMEIP_DISABLE_SECURITY

public:
    bool is_enabled() const;
    bool is_audit() const;

    bool check_credentials(client_t _client,
            const vsomeip_sec_client_t *_sec_client);
    bool check_routing_credentials(
            const vsomeip_sec_client_t *_sec_client) const;
    void set_routing_credentials(uid_t _uid, gid_t _gid,
            const std::string &_name);

    bool is_client_allowed(const vsomeip_sec_client_t *_sec_client,
            service_t _service, instance_t _instance, method_t _method,
            bool _is_request_service = false) const;
    bool is_offer_allowed(const vsomeip_sec_client_t *_sec_client,
            service_t _service, instance_t _instance) const;

    bool get_sec_client_to_clients_mapping(const vsomeip_sec_client_t *_sec_client,
            std::set<client_t> &_clients);
    bool remove_client_to_sec_client_mapping(client_t _client);

    bool get_client_to_sec_client_mapping(client_t _client, vsomeip_sec_client_t &_sec_client);
    bool store_client_to_sec_client_mapping(client_t _client, const vsomeip_sec_client_t *_sec_client);
    void store_sec_client_to_client_mapping(const vsomeip_sec_client_t *_sec_client, client_t _client);

private:
#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable : 4251)
#endif
#ifndef VSOMEIP_DISABLE_SECURITY
    mutable boost::shared_mutex  any_client_policies_mutex_;
    std::vector<std::shared_ptr<policy> > any_client_policies_;

    mutable boost::shared_mutex is_client_allowed_cache_mutex_;
    mutable std::map<std::pair<uid_t, gid_t>,
        std::set<std::tuple<service_t, instance_t, method_t> >
    > is_client_allowed_cache_;

    bool policy_enabled_;
    bool check_credentials_;
    bool allow_remote_clients_;
    bool check_whitelist_;

    mutable std::mutex service_interface_whitelist_mutex_;
    boost::icl::interval_set<service_t> service_interface_whitelist_;

    mutable std::mutex uid_whitelist_mutex_;
    boost::icl::interval_set<uint32_t> uid_whitelist_;

    mutable std::mutex policy_base_path_mutex_;
    std::string policy_base_path_;

    mutable boost::shared_mutex policy_extension_paths_mutex_;
    //map[hostname, pair[path,  map[complete path with UID/GID, control loading]]
    std::map<std::string, std::pair<std::string, std::map<std::string, bool>>> policy_extension_paths_;

    bool check_routing_credentials_;
#endif // !VSOMEIP_DISABLE_SECURITY

    bool is_configured_;

    mutable std::mutex routing_credentials_mutex_;
    std::pair<uint32_t, uint32_t> routing_credentials_;

    mutable std::mutex ids_mutex_;
    std::map<client_t, vsomeip_sec_client_t> ids_;

    struct vsomeip_sec_client_comparator_t {
        bool operator()(const vsomeip_sec_client_t &_lhs, const vsomeip_sec_client_t &_rhs) const {
            if (_lhs.port < _rhs.port) {
                return true;
            } else if (_lhs.port == _rhs.port) {
                if (_lhs.port == VSOMEIP_SEC_PORT_UNUSED) {
                    return ((_lhs.user < _rhs.user)
                        || ((_lhs.user == _rhs.user)
                        && (_lhs.group < _rhs.group)));
                } else {
                    return ((_lhs.host < _rhs.host)
                        || ((_lhs.host == _rhs.host)
                        && (_lhs.port < _rhs.port)));
                }
            }
            return false;
        }
    };

    mutable std::mutex sec_client_to_clients_mutex_;
    std::map<vsomeip_sec_client_t, std::set<client_t>, vsomeip_sec_client_comparator_t> sec_client_to_clients_;
#ifdef _WIN32
#pragma warning(pop)
#endif
};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_SECURITY_POLICY_MANAGER_IMPL_HPP_
