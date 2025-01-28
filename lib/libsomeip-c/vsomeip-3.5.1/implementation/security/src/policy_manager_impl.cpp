// Copyright (C) 2019-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #define NOMINMAX
    #include <windows.h>
    #include <stdlib.h>
#endif

#include <algorithm>
#include <sstream>

#include "../include/policy_manager_impl.hpp"
#include "../../configuration/include/configuration_element.hpp"
#ifdef ANDROID
#include "../../configuration/include/internal_android.hpp"
#else
#include "../../configuration/include/internal.hpp"
#endif // ANDROID
#include "../../utility/include/utility.hpp"

namespace vsomeip_v3 {

template<typename T_>
void read_data(const std::string &_in, T_ &_out) {
    std::stringstream its_converter;

    if (_in.size() > 2
            && _in[0] == '0'
            && (_in[1] == 'x' || _in[1] == 'X'))
        its_converter << std::hex << _in;
    else
        its_converter << std::dec << _in;

    its_converter >> _out;
}

policy_manager_impl::policy_manager_impl()
    :
#ifndef VSOMEIP_DISABLE_SECURITY
    policy_enabled_(false),
    check_credentials_(false),
    allow_remote_clients_(true),
    check_whitelist_(false),
    policy_base_path_(""),
    check_routing_credentials_(false),
#endif // !VSOMEIP_DISABLE_SECURITY
    is_configured_(false)
{
}

bool
policy_manager_impl::is_enabled() const {
#ifdef VSOMEIP_DISABLE_SECURITY
    return false;
#else
    return policy_enabled_;
#endif
}

bool
policy_manager_impl::is_audit() const {
#ifdef VSOMEIP_DISABLE_SECURITY
    return false;
#else
    return !check_credentials_;
#endif
}

bool
policy_manager_impl::check_credentials(client_t _client,
        const vsomeip_sec_client_t *_sec_client) {

#ifdef VSOMEIP_DISABLE_SECURITY
    (void)_client;
    (void)_sec_client;

    return true;
#else
    if (!policy_enabled_)
        return true;

    if (!_sec_client)
        return true;

    if (_sec_client->port != VSOMEIP_SEC_PORT_UNUSED)
        return true;

    uid_t its_uid(_sec_client->user);
    gid_t its_gid(_sec_client->group);

    bool has_id(false);

    boost::shared_lock<boost::shared_mutex> its_lock(any_client_policies_mutex_);
    for (const auto &p : any_client_policies_) {

        std::lock_guard<std::mutex> its_policy_lock(p->mutex_);

        bool has_uid, has_gid(false);

        const auto found_uid = p->credentials_.find(its_uid);
        has_uid = (found_uid != p->credentials_.end());
        if (has_uid) {
            const auto found_gid = found_uid->second.find(its_gid);
            has_gid = (found_gid != found_uid->second.end());
        }

        has_id = (has_uid && has_gid);

        if ((has_id && p->allow_who_) || (!has_id && !p->allow_who_)) {
            // Code is unaccessible due to logic checks.
            if (!store_client_to_sec_client_mapping(_client, _sec_client)) {
                std::string security_mode_text = "!";
                if (!check_credentials_) {
                    security_mode_text = " but will be allowed due to audit mode is active!";
                }
                VSOMEIP_INFO << "vSomeIP Security: Client 0x" << std::hex << _client
                        << " with UID/GID=" << std::dec << its_uid << "/" << its_gid
                        << " : Check credentials failed as existing credentials would be overwritten"
                        << security_mode_text;
                return !check_credentials_;
            }
            store_sec_client_to_client_mapping(_sec_client, _client);
            return true;
        }
    }

    std::string security_mode_text = " ~> Skip!";
    if (!check_credentials_) {
        security_mode_text = " but will be allowed due to audit mode is active!";
    }
    VSOMEIP_INFO << "vSomeIP Security: Client 0x" << std::hex << _client
                 << " with UID/GID=" << std::dec << its_uid << "/" << its_gid
                 << " : Check credentials failed" << security_mode_text;

    return !check_credentials_;
#endif // VSOMEIP_DISABLE_SECURITY
}

bool
policy_manager_impl::check_routing_credentials(
        const vsomeip_sec_client_t *_sec_client) const {

#ifdef VSOMEIP_DISABLE_SECURITY
    (void)_sec_client;

    return true;
#else
    uid_t its_uid(0);
    gid_t its_gid(0);
    bool is_known_uid_gid(false);

    std::lock_guard<std::mutex> its_lock(routing_credentials_mutex_);
    if (_sec_client && _sec_client->port == VSOMEIP_SEC_PORT_UNUSED) {
        its_uid = _sec_client->user;
        its_gid = _sec_client->group;

        if (routing_credentials_.first == its_uid
                && routing_credentials_.second == its_gid) {

            return true;
        }

        is_known_uid_gid = true;
    }

    std::string security_mode_text = "!";
    if (!check_routing_credentials_) {

        security_mode_text = " but will be allowed due to audit mode is active!";
    }

    VSOMEIP_INFO << "vSomeIP Security: UID/GID="
            << (is_known_uid_gid ? std::to_string(its_uid) : "n/a")
            << "."
            << (is_known_uid_gid ? std::to_string(its_gid) : "n/a")
            << " : Check routing credentials failed as "
            << "configured routing manager credentials "
            << "do not match with routing manager credentials"
            << security_mode_text;

    return !check_routing_credentials_;
#endif // VSOMEIP_DISABLE_SECURITY
}

void
policy_manager_impl::set_routing_credentials(uid_t _uid, gid_t _gid,
        const std::string &_name) {

    if (is_configured_) {
        VSOMEIP_WARNING << "vSomeIP Security: Multiple definitions of routing-credentials."
                << " Ignoring definition from " << _name;
    } else {
        routing_credentials_ = std::make_pair(_uid, _gid);
        is_configured_ = true;
    }
}

bool
policy_manager_impl::is_client_allowed(const vsomeip_sec_client_t *_sec_client,
        service_t _service, instance_t _instance, method_t _method,
        bool _is_request_service) const {

#ifdef VSOMEIP_DISABLE_SECURITY
    (void)_sec_client;
    (void)_service;
    (void)_instance;
    (void)_method;
    (void)_is_request_service;

    return true;
#else
    if (!policy_enabled_) {
        return true;
    }

    uid_t its_uid(ANY_UID);
    gid_t its_gid(ANY_GID);
    if (_sec_client) {
        if (_sec_client->port == VSOMEIP_SEC_PORT_UNUSED) {
            its_uid = _sec_client->user;
            its_gid = _sec_client->group;
        } else {
            return true;
        }
    } else {
        std::string security_mode_text = " ~> Skip!";
        if (!check_credentials_) {
            security_mode_text = " but will be allowed due to audit mode is active!";
        }
        VSOMEIP_INFO << "vSomeIP Security: uid/gid "
                <<  std::dec << its_uid << "/" << its_gid << " is not valid."
                << "Therefore it isn't allowed to communicate to service/instance "
                << _service << "/" << _instance
                << security_mode_text;

        return !check_credentials_;
    }

    // Check cache
    auto its_credentials = std::make_pair(its_uid, its_gid);
    auto its_key = std::make_tuple(_service, _instance, _method);
    {
        boost::shared_lock<boost::shared_mutex> its_cache_lock(is_client_allowed_cache_mutex_);
        const auto its_iter = is_client_allowed_cache_.find(its_credentials);
        if (its_iter != is_client_allowed_cache_.end()) {
            if (its_iter->second.find(its_key) != its_iter->second.end()) {
                return true;
            }
        }
    }


    // Check policies
    boost::shared_lock<boost::shared_mutex> its_lock(any_client_policies_mutex_);
    for (const auto &p : any_client_policies_) {
        std::lock_guard<std::mutex> its_policy_lock(p->mutex_);
        bool has_uid, has_gid(false);
        bool is_matching(false);

        const auto found_uid = p->credentials_.find(its_uid);
        has_uid = (found_uid != p->credentials_.end());
        if (has_uid) {
            const auto found_gid = found_uid->second.find(its_gid);
            has_gid = (found_gid != found_uid->second.end());
        }

        const auto found_service = p->requests_.find(_service);
        if (found_service != p->requests_.end()) {
            const auto found_instance = found_service->second.find(_instance);
            if (found_instance != found_service->second.end()) {
                if (!_is_request_service) {
                    const auto found_method = found_instance->second.find(_method);
                    is_matching = (found_method != found_instance->second.end());
                } else {
                    // handle VSOMEIP_REQUEST_SERVICE
                    is_matching = true;
                }
            }
        }

        if ((has_uid && has_gid && p->allow_who_) || ((!has_uid || !has_gid) && !p->allow_who_)) {
            if (p->allow_what_) {
                // allow policy
                if (is_matching) {
                    boost::unique_lock<boost::shared_mutex> its_cache_lock(is_client_allowed_cache_mutex_);
                    is_client_allowed_cache_[its_credentials].insert(its_key);
                    return true;
                }
            } else {
                // deny policy
                // allow client if the service / instance / !ANY_METHOD was not found
                if ((!is_matching && (_method != ANY_METHOD))
                        // allow client if the service / instance / ANY_METHOD was not found
                        // and it is a "deny nothing" policy
                        || (!is_matching && (_method == ANY_METHOD) && p->requests_.empty())) {
                     boost::unique_lock<boost::shared_mutex> its_cache_lock(is_client_allowed_cache_mutex_);
                     is_client_allowed_cache_[its_credentials].insert(its_key);
                     return true;
                }
            }
        }
    }

    std::string security_mode_text = " ~> Skip!";
    if (!check_credentials_) {
        security_mode_text = " but will be allowed due to audit mode is active!";
    }

    VSOMEIP_INFO << "vSomeIP Security: UID/GID="
            << std::dec << its_uid << "/" << its_gid
            << " : Isn't allowed to communicate with service/instance/(method / event) "
            << std::hex << _service << "/" << _instance << "/" << _method
            << security_mode_text;

    return !check_credentials_;
#endif // VSOMEIP_DISABLE_SECURITY
}

bool
policy_manager_impl::is_offer_allowed(const vsomeip_sec_client_t *_sec_client,
        service_t _service, instance_t _instance) const {

#ifdef VSOMEIP_DISABLE_SECURITY
    (void)_sec_client;
    (void)_service;
    (void)_instance;

    return true;
#else
    if (!policy_enabled_)
        return true;

    uint32_t its_uid(ANY_UID), its_gid(ANY_GID);
    if (_sec_client) {
        if (_sec_client->port == VSOMEIP_SEC_PORT_UNUSED) {
            its_uid = _sec_client->user;
            its_gid = _sec_client->group;
        } else {
            return true;
        }
    } else {
        std::string security_mode_text = " ~> Skip offer!";
        if (!check_credentials_) {
            security_mode_text = " but will be allowed due to audit mode is active!";
        }
        VSOMEIP_INFO << "vSomeIP Security: uid/gid "
                <<  std::dec << its_uid << "/" << its_gid << " is not valid."
                << "Therefore it isn't allowed to offer service/instance "
                << _service << "/" << _instance
                << security_mode_text;

        return !check_credentials_;
    }

    boost::shared_lock<boost::shared_mutex> its_lock(any_client_policies_mutex_);
    for (const auto &p : any_client_policies_) {
        std::lock_guard<std::mutex> its_policy_lock(p->mutex_);
        bool has_uid, has_gid(false), has_offer(false);

        const auto found_uid = p->credentials_.find(its_uid);
        has_uid = (found_uid != p->credentials_.end());
        if (has_uid) {
            const auto found_gid = found_uid->second.find(its_gid);
            has_gid = (found_gid != found_uid->second.end());
        }

        const auto found_service = p->offers_.find(_service);
        if (found_service != p->offers_.end()) {
            const auto found_instance = found_service->second.find(_instance);
            has_offer = (found_instance != found_service->second.end());
        }

        if ((has_uid && has_gid && p->allow_who_)
                || ((!has_uid || !has_gid) && !p->allow_who_)) {
            if (p->allow_what_ == has_offer) {
                return true;
            }
        }
    }

    std::string security_mode_text = " ~> Skip offer!";
    if (!check_credentials_) {
        security_mode_text = " but will be allowed due to audit mode is active!";
    }

    VSOMEIP_INFO << "vSomeIP Security: UID/GID="
            << std::dec << its_uid << "/" << its_gid
            << " isn't allowed to offer service/instance "
            << std::hex << _service << "/" << _instance
            << security_mode_text;

    return !check_credentials_;
#endif // VSOMEIP_DISABLE_SECURITY
}

#ifndef VSOMEIP_DISABLE_SECURITY
void
policy_manager_impl::load(const configuration_element &_element, const bool _lazy_load) {

    load_policies(_element);
    if (!_lazy_load) {

        load_security_update_whitelist(_element);
        load_security_policy_extensions(_element);
           load_routing_credentials(_element);

        if (policy_enabled_ && check_credentials_)
            VSOMEIP_INFO << "Security configuration is active.";

        if (policy_enabled_ && !check_credentials_)
            VSOMEIP_INFO << "Security configuration is active but in audit mode (allow all)";
    }
}

bool
policy_manager_impl::remove_security_policy(uid_t _uid, gid_t _gid) {
    boost::unique_lock<boost::shared_mutex> its_lock(any_client_policies_mutex_);
    bool was_removed(false);
    if (!any_client_policies_.empty()) {
        std::vector<std::shared_ptr<policy>>::iterator p_it = any_client_policies_.begin();
        while (p_it != any_client_policies_.end()) {
            bool is_matching(false);
            {
                std::lock_guard<std::mutex> its_policy_lock((*p_it)->mutex_);
                bool has_uid(false), has_gid(false);
                const auto found_uid = (*p_it)->credentials_.find(_uid);
                has_uid = (found_uid != (*p_it)->credentials_.end());
                if (has_uid) {
                    const auto found_gid = found_uid->second.find(_gid);
                    has_gid = (found_gid != found_uid->second.end());
                }

                // only remove "credentials allow" policies to prevent removal of
                // blacklist configured in file
                if (has_uid && has_gid && (*p_it)->allow_who_) {
                    is_matching = true;
                }
            }
            if (is_matching) {
                was_removed = true;
                p_it = any_client_policies_.erase(p_it);
            } else {
                ++p_it;
            }

            boost::unique_lock<boost::shared_mutex> its_cache_lock(is_client_allowed_cache_mutex_);
            is_client_allowed_cache_.erase(std::make_pair(_uid, _gid));
        }
    }
    return was_removed;
}

void
policy_manager_impl::update_security_policy(uid_t _uid, gid_t _gid,
        const std::shared_ptr<policy> &_policy) {

    boost::unique_lock<boost::shared_mutex> its_lock(any_client_policies_mutex_);
    std::shared_ptr<policy> its_matching_policy;
    for (auto p : any_client_policies_) {
        std::lock_guard<std::mutex> its_guard(p->mutex_);
        if (p->credentials_.size() == 1) {
            const auto its_uids = *(p->credentials_.begin());
            if (its_uids.first.lower() == _uid
                    && its_uids.first.upper() == _uid) {
                if (its_uids.second.size() == 1) {
                    const auto its_gids = *(its_uids.second.begin());
                    if (its_gids.lower() == _gid
                            && its_gids.upper() == _gid) {
                        if (p->allow_who_ == _policy->allow_who_) {
                            its_matching_policy = p;
                            break;
                        }
                    }
                }
            }
        }
    }

    if (its_matching_policy) {
        std::lock_guard<std::mutex> its_guard{its_matching_policy->mutex_};
        for (const auto &r : _policy->requests_) {
            service_t its_lower, its_upper;
            get_bounds(r.first, its_lower, its_upper);
            for (auto s = its_lower; s <= its_upper; s++) {
                boost::icl::discrete_interval<service_t> its_service(s, s,
                        boost::icl::interval_bounds::closed());
                its_matching_policy->requests_ += std::make_pair(its_service, r.second);
            }
        }
        for (const auto &o : _policy->offers_) {
            service_t its_lower, its_upper;
            get_bounds(o.first, its_lower, its_upper);
            for (auto s = its_lower; s <= its_upper; s++) {
                boost::icl::discrete_interval<service_t> its_service(s, s,
                        boost::icl::interval_bounds::closed());
                its_matching_policy->offers_ += std::make_pair(its_service, o.second);
            }
        }
    } else {
        any_client_policies_.push_back(_policy);
    }

    boost::unique_lock<boost::shared_mutex> its_cache_lock(is_client_allowed_cache_mutex_);
    is_client_allowed_cache_.erase(std::make_pair(_uid, _gid));
}

void
policy_manager_impl::add_security_credentials(uid_t _uid, gid_t _gid,
        const std::shared_ptr<policy> &_policy, client_t _client) {

    bool was_found(false);
    boost::unique_lock<boost::shared_mutex> its_lock(any_client_policies_mutex_);
    for (const auto &p : any_client_policies_) {
        bool has_uid(false), has_gid(false);

        std::lock_guard<std::mutex> its_policy_lock(p->mutex_);
        const auto found_uid = p->credentials_.find(_uid);
        has_uid = (found_uid != p->credentials_.end());
        if (has_uid) {
            const auto found_gid = found_uid->second.find(_gid);
            has_gid = (found_gid != found_uid->second.end());
        }

        if (has_uid && has_gid && p->allow_who_) {
            was_found = true;
            break;
        }
    }

    // Do not add the new (credentials-only-policy) if a allow
    // credentials policy with same credentials was found
    if (!was_found) {
        any_client_policies_.push_back(_policy);
        VSOMEIP_INFO << __func__ << " Added security credentials at client: 0x"
                << std::hex << _client << std::dec << " with UID: " << _uid << " GID: " << _gid;
    }
}

bool
policy_manager_impl::is_policy_update_allowed(uid_t _uid, std::shared_ptr<policy> &_policy) const {

    bool is_uid_allowed(false);
    {
        std::lock_guard<std::mutex> its_lock(uid_whitelist_mutex_);
        const auto found_uid = uid_whitelist_.find(_uid);
        is_uid_allowed = (found_uid != uid_whitelist_.end());
    }

    if (is_uid_allowed && _policy) {
        std::lock_guard<std::mutex> its_lock(service_interface_whitelist_mutex_);
        std::lock_guard<std::mutex> its_policy_lock(_policy->mutex_);
        for (const auto &its_request : _policy->requests_) {
            bool has_service(false);

            service_t its_service(0);
            for (its_service = its_request.first.lower();
                    its_service <= its_request.first.upper();
                    its_service++) {

                const auto found_service = service_interface_whitelist_.find(its_service);
                has_service = (found_service != service_interface_whitelist_.end());
                if (!has_service)
                    break;
            }

            if (!has_service) {
                if (!check_whitelist_) {
                    VSOMEIP_INFO << "vSomeIP Security: Policy update requesting service ID: "
                            << std::hex << its_service
                            << " is not allowed, but will be allowed due to whitelist audit mode is active!";
                } else {
                    VSOMEIP_WARNING << "vSomeIP Security: Policy update requesting service ID: "
                            << std::hex << its_service
                            << " is not allowed! -> ignore update";
                }
                return !check_whitelist_;
            }
        }
        return true;
    } else {
        if (!check_whitelist_) {
            VSOMEIP_INFO << "vSomeIP Security: Policy update for UID: " << std::dec << _uid
                    << " is not allowed, but will be allowed due to whitelist audit mode is active!";
        } else {
            VSOMEIP_WARNING << "vSomeIP Security: Policy update for UID: " << std::dec << _uid
                    << " is not allowed! -> ignore update";
        }
        return !check_whitelist_;
    }
}

bool
policy_manager_impl::is_policy_removal_allowed(uid_t _uid) const {
    std::lock_guard<std::mutex> its_lock(uid_whitelist_mutex_);
    for (auto its_uid_range : uid_whitelist_) {
        if (its_uid_range.lower() <= _uid && _uid <= its_uid_range.upper()) {
            return true;
        }
    }

    if (!check_whitelist_) {
        VSOMEIP_INFO << "vSomeIP Security: Policy removal for UID: "
                << std::dec << _uid
                << " is not allowed, but will be allowed due to whitelist audit mode is active!";
    } else {
        VSOMEIP_WARNING << "vSomeIP Security: Policy removal for UID: "
                << std::dec << _uid
                << " is not allowed! -> ignore removal";
    }
    return !check_whitelist_;
}

bool
policy_manager_impl::parse_policy(const byte_t* &_buffer, uint32_t &_buffer_size,
        uid_t &_uid, gid_t &_gid, const std::shared_ptr<policy> &_policy) const {

    bool is_valid = _policy->deserialize(_buffer, _buffer_size);
    if (is_valid)
        is_valid = _policy->get_uid_gid(_uid, _gid);
    return is_valid;
}

///////////////////////////////////////////////////////////////////////////////
// Configuration
///////////////////////////////////////////////////////////////////////////////
bool
policy_manager_impl::exist_in_any_client_policies_unlocked(std::shared_ptr<policy> &_policy) {
    for (const auto &p : any_client_policies_) {
        std::lock_guard<std::mutex> its_policy_lock(p->mutex_);
        if (p->credentials_ == _policy->credentials_ &&
            p->requests_ == _policy->requests_ &&
            p->offers_ == _policy->offers_ &&
            p->allow_what_ == _policy->allow_what_ &&
            p->allow_who_ == _policy->allow_who_) {
                return true;
            }
    }
    return false;
}

void
policy_manager_impl::load_policies(const configuration_element &_element) {
#ifdef _WIN32
        return;
#endif
    try {
        auto optional = _element.tree_.get_child_optional("security");
        if (!optional) {
            return;
        }
        policy_enabled_ = true;
        auto found_policy = _element.tree_.get_child("security");
        for (auto its_security = found_policy.begin();
                its_security != found_policy.end(); ++its_security) {
            if (its_security->first == "check_credentials") {
                if (its_security->second.data() == "true") {
                    check_credentials_ = true;
                } else {
                    check_credentials_ = false;
                }
            } else if (its_security->first == "allow_remote_clients")  {
                if (its_security->second.data() == "true") {
                    allow_remote_clients_ = true;
                } else {
                    allow_remote_clients_ = false;
                }
            } else if (its_security->first == "policies") {
                for (auto its_policy = its_security->second.begin();
                        its_policy != its_security->second.end(); ++its_policy) {
                    load_policy(its_policy->second);
                }
            }
        }
    } catch (...) {
    }
}

void
policy_manager_impl::load_policy(const boost::property_tree::ptree &_tree) {

    std::shared_ptr<policy> policy(std::make_shared<policy>());
    bool allow_deny_set(false);
    for (auto i = _tree.begin(); i != _tree.end(); ++i) {
        if (i->first == "credentials") {
            boost::icl::interval_set<uid_t> its_uid_interval_set;
            boost::icl::interval_set<gid_t> its_gid_interval_set;
            boost::icl::discrete_interval<uid_t> its_uid_interval;
            boost::icl::discrete_interval<gid_t> its_gid_interval;

            bool has_uid(false), has_gid(false);
            bool has_uid_range(false), has_gid_range(false);
            for (auto n = i->second.begin();
                    n != i->second.end(); ++n) {
                std::string its_key(n->first);
                std::string its_value(n->second.data());
                if (its_key == "uid") {
                    if(n->second.data().empty()) {
                        load_interval_set(n->second, its_uid_interval_set);
                        has_uid_range = true;
                    } else {
                        if (its_value != "any") {
                            uint32_t its_uid;
                            read_data(its_value, its_uid);
                            its_uid_interval = boost::icl::construct<
                                boost::icl::discrete_interval<uid_t> >(
                                        its_uid, its_uid,
                                        boost::icl::interval_bounds::closed());
                        } else {
                            its_uid_interval = boost::icl::construct<
                                boost::icl::discrete_interval<uid_t> >(
                                        std::numeric_limits<uid_t>::min(),
                                        std::numeric_limits<uid_t>::max(),
                                        boost::icl::interval_bounds::closed());
                        }
                        has_uid = true;
                    }
                } else if (its_key == "gid") {
                    if(n->second.data().empty()) {
                        load_interval_set(n->second, its_gid_interval_set);
                        has_gid_range = true;
                    } else {
                        if (its_value != "any") {
                            uint32_t its_gid;
                            read_data(its_value, its_gid);
                            its_gid_interval = boost::icl::construct<
                                boost::icl::discrete_interval<gid_t> >(
                                        its_gid, its_gid,
                                        boost::icl::interval_bounds::closed());
                        } else {
                            its_gid_interval = boost::icl::construct<
                                boost::icl::discrete_interval<gid_t> >(
                                        std::numeric_limits<gid_t>::min(),
                                        std::numeric_limits<gid_t>::max(),
                                        boost::icl::interval_bounds::closed());
                        }
                        has_gid = true;
                    }
                } else if (its_key == "allow" || its_key == "deny") {
                    policy->allow_who_ = (its_key == "allow");
                    load_credential(n->second, policy->credentials_);
                }
            }

            if (has_uid && has_gid) {
                its_gid_interval_set.insert(its_gid_interval);

                policy->credentials_ += std::make_pair(its_uid_interval, its_gid_interval_set);
                policy->allow_who_ = true;
            }
            if (has_uid_range && has_gid_range) {
                for (const auto u : its_uid_interval_set)
                    policy->credentials_ += std::make_pair(u, its_gid_interval_set);
                policy->allow_who_ = true;
            }
        } else if (i->first == "allow") {
            if (allow_deny_set) {
                VSOMEIP_WARNING << "vSomeIP Security: Security configuration: \"allow\" tag overrides "
                        << "already set \"deny\" tag. "
                        << "Either \"deny\" or \"allow\" is allowed.";
            }
            allow_deny_set = true;
            policy->allow_what_ = true;
            load_policy_body(policy, i);
        } else if (i->first == "deny") {
            if (allow_deny_set) {
                VSOMEIP_WARNING << "vSomeIP Security: Security configuration: \"deny\" tag overrides "
                        << "already set \"allow\" tag. "
                        << "Either \"deny\" or \"allow\" is allowed.";
            }
            allow_deny_set = true;
            policy->allow_what_ = false;
            load_policy_body(policy, i);
        }
    }
    boost::unique_lock<boost::shared_mutex> its_lock(any_client_policies_mutex_);
    if (!exist_in_any_client_policies_unlocked(policy))
        any_client_policies_.push_back(policy);

}

void
policy_manager_impl::load_policy_body(std::shared_ptr<policy> &_policy,
        const boost::property_tree::ptree::const_iterator &_tree) {

    for (auto l = _tree->second.begin(); l != _tree->second.end(); ++l) {
        if (l->first == "requests") {
            for (auto n = l->second.begin(); n != l->second.end(); ++n) {
                service_t its_service = 0x0;
                instance_t its_instance = 0x0;
                boost::icl::interval_map<instance_t,
                    boost::icl::interval_set<method_t> > its_instance_method_intervals;
                for (auto k = n->second.begin(); k != n->second.end(); ++k) {
                    if (k->first == "service") {
                        read_data(k->second.data(), its_service);
                    } else if (k->first == "instance") { // legacy definition for instances
                        boost::icl::interval_set<instance_t> its_instance_interval_set;
                        boost::icl::interval_set<method_t> its_method_interval_set;
                        boost::icl::discrete_interval<instance_t> all_instances(0x01, 0xFFFF,
                                boost::icl::interval_bounds::closed());
                        boost::icl::discrete_interval<method_t> all_methods(0x01, 0xFFFF,
                                boost::icl::interval_bounds::closed());

                        std::string its_value(k->second.data());
                        if (its_value != "any") {
                            read_data(its_value, its_instance);
                            if (its_instance != 0x0) {
                                its_instance_interval_set.insert(its_instance);
                                its_method_interval_set.insert(all_methods);
                            }
                        } else {
                            its_instance_interval_set.insert(all_instances);
                            its_method_interval_set.insert(all_methods);
                        }
                        for (const auto i : its_instance_interval_set) {
                            its_instance_method_intervals
                                += std::make_pair(i, its_method_interval_set);
                        }
                    } else if (k->first == "instances") { // new instances definition
                        for (auto p = k->second.begin(); p != k->second.end(); ++p) {
                            boost::icl::interval_set<instance_t> its_instance_interval_set;
                            boost::icl::interval_set<method_t> its_method_interval_set;
                            boost::icl::discrete_interval<method_t> all_methods(0x01, 0xFFFF,
                                    boost::icl::interval_bounds::closed());
                            for (auto m = p->second.begin(); m != p->second.end(); ++m) {
                                if (m->first == "ids") {
                                    load_interval_set(m->second, its_instance_interval_set);
                                } else if (m->first == "methods") {
                                    load_interval_set(m->second, its_method_interval_set);
                                }
                            }
                            if (its_method_interval_set.empty())
                                its_method_interval_set.insert(all_methods);
                            for (const auto i : its_instance_interval_set) {
                                its_instance_method_intervals
                                    += std::make_pair(i, its_method_interval_set);
                            }
                        }

                        if (its_instance_method_intervals.empty()) {
                            boost::icl::interval_set<instance_t> its_legacy_instance_interval_set;
                            boost::icl::interval_set<method_t> its_legacy_method_interval_set;
                            boost::icl::discrete_interval<method_t> all_methods(0x01, 0xFFFF,
                                    boost::icl::interval_bounds::closed());
                            its_legacy_method_interval_set.insert(all_methods);

                            // try to only load instance ranges with any method to be allowed
                            load_interval_set(k->second, its_legacy_instance_interval_set);
                            for (const auto i : its_legacy_instance_interval_set) {
                                its_instance_method_intervals
                                    += std::make_pair(i, its_legacy_method_interval_set);
                            }
                        }
                    }
                }
                if (its_service != 0x0 && !its_instance_method_intervals.empty()) {
                    _policy->requests_ += std::make_pair(
                            boost::icl::discrete_interval<service_t>(
                                    its_service, its_service,
                                    boost::icl::interval_bounds::closed()),
                            its_instance_method_intervals);
                }
            }
        } else if (l->first == "offers") {
            for (auto n = l->second.begin(); n != l->second.end(); ++n) {
                service_t its_service(0x0);
                instance_t its_instance(0x0);
                boost::icl::interval_set<instance_t> its_instance_interval_set;
                for (auto k = n->second.begin(); k != n->second.end(); ++k) {
                    if (k->first == "service") {
                        read_data(k->second.data(), its_service);
                    } else if (k->first == "instance") { // legacy definition for instances
                        std::string its_value(k->second.data());
                        if (its_value != "any") {
                            read_data(its_value, its_instance);
                            if (its_instance != 0x0) {
                                its_instance_interval_set.insert(its_instance);
                            }
                        } else {
                            its_instance_interval_set.insert(
                                    boost::icl::discrete_interval<instance_t>(
                                        0x0001, 0xFFFF));
                        }
                    } else if (k->first == "instances") { // new instances definition
                        load_interval_set(k->second, its_instance_interval_set);
                    }
                }
                if (its_service != 0x0 && !its_instance_interval_set.empty()) {
                    _policy->offers_
                        += std::make_pair(
                                boost::icl::discrete_interval<service_t>(
                                        its_service, its_service,
                                        boost::icl::interval_bounds::closed()),
                                its_instance_interval_set);
                }
            }
        }
    }
}


void
policy_manager_impl::load_credential(
        const boost::property_tree::ptree &_tree,
        boost::icl::interval_map<uid_t,
            boost::icl::interval_set<gid_t> > &_credentials) {

    for (auto i = _tree.begin(); i != _tree.end(); ++i) {
        boost::icl::interval_set<uid_t> its_uid_interval_set;
        boost::icl::interval_set<gid_t> its_gid_interval_set;

        for (auto j = i->second.begin(); j != i->second.end(); ++j) {
            std::string its_key(j->first);
            if (its_key == "uid") {
                load_interval_set(j->second, its_uid_interval_set);
            } else if (its_key == "gid") {
                load_interval_set(j->second, its_gid_interval_set);
            } else {
                VSOMEIP_WARNING << "vSomeIP Security: Security configuration: "
                        << "Malformed credential (contains illegal key \""
                        << its_key << "\")";
            }
        }

        for (const auto its_uid_interval : its_uid_interval_set) {
            _credentials
                += std::make_pair(its_uid_interval, its_gid_interval_set);
        }
    }
}

bool
policy_manager_impl::load_routing_credentials(const configuration_element &_element) {
    try {
        auto its_routing_cred = _element.tree_.get_child("routing-credentials");
        if (is_configured_) {
            VSOMEIP_WARNING << "vSomeIP Security: Multiple definitions of routing-credentials."
                    << " Ignoring definition from " << _element.name_;
        } else {
            for (auto i = its_routing_cred.begin();
                    i != its_routing_cred.end();
                    ++i) {
                std::string its_key(i->first);
                std::string its_value(i->second.data());
                if (its_key == "uid") {
                    uint32_t its_uid(0);
                    read_data(its_value, its_uid);
                    std::lock_guard<std::mutex> its_lock(routing_credentials_mutex_);
                    std::get<0>(routing_credentials_) = its_uid;
                } else if (its_key == "gid") {
                    uint32_t its_gid(0);
                    read_data(its_value, its_gid);
                    std::lock_guard<std::mutex> its_lock(routing_credentials_mutex_);
                    std::get<1>(routing_credentials_) = its_gid;
                }
            }
            check_routing_credentials_ = true;
            is_configured_ = true;
        }
    } catch (...) {
        return false;
    }
    return true;
}


void
policy_manager_impl::load_security_update_whitelist(const configuration_element &_element) {
#ifdef _WIN32
        return;
#endif
    try {
        auto optional = _element.tree_.get_child_optional("security-update-whitelist");
        if (!optional) {
            return;
        }
        auto found_whitelist = _element.tree_.get_child("security-update-whitelist");
        for (auto its_whitelist = found_whitelist.begin();
                its_whitelist != found_whitelist.end(); ++its_whitelist) {

            if (its_whitelist->first == "uids") {
                {
                    std::lock_guard<std::mutex> its_lock(uid_whitelist_mutex_);
                    load_interval_set(its_whitelist->second, uid_whitelist_);
                }
            } else if (its_whitelist->first == "services") {
                {
                    std::lock_guard<std::mutex> its_lock(service_interface_whitelist_mutex_);
                    load_interval_set(its_whitelist->second, service_interface_whitelist_);
                }
            } else if (its_whitelist->first == "check-whitelist") {
                if (its_whitelist->second.data() == "true") {
                    check_whitelist_ = true;
                } else {
                    check_whitelist_ = false;
                }
            }
        }
    } catch (...) {
    }
}

void
policy_manager_impl::load_security_policy_extensions(const configuration_element &_element) {
#ifdef _WIN32
        return;
#endif
    try {
        auto optional = _element.tree_.get_child_optional("container_policy_extensions");
        if (!optional) {
            return;
        }
        auto found_policy_extensions = _element.tree_.get_child("container_policy_extensions");
        boost::filesystem::path its_base_path;
        {
            boost::unique_lock<boost::shared_mutex> its_lock(policy_extension_paths_mutex_);
            its_base_path = boost::filesystem::path(policy_base_path_);
        }

        for (auto i = found_policy_extensions.begin();
                i != found_policy_extensions.end(); ++i) {
            boost::filesystem::path its_canonical_path;
            std::string its_client_host("");
            std::string its_path("");
            auto its_data = i->second;
            for (auto j = its_data.begin(); j != its_data.end(); ++j) {
                std::string its_key(j->first);
                std::string its_value(j->second.data());
                if (its_key == "container") {
                    if(its_value != "") {
                        its_client_host = its_value;
                    }
                } else if (its_key == "path") {
                    if(its_value != "") {
                        its_path = its_value;
                     }
                }
            }

            std::string str = VSOMEIP_DEFAULT_CONFIGURATION_FOLDER;
            std::string its_filesystem_path = str.substr(0, str.find_last_of("\\/"))
                + its_path.erase(0, its_path.find_first_of("\\/"));

            if (!utility::is_folder(its_filesystem_path)) {
                VSOMEIP_DEBUG << __func__ << ": The path "
                        << its_filesystem_path
                        << " is not valid";
            }
            std::map<std::string, bool> empty_map;
            policy_extension_paths_[its_client_host] = std::make_pair(its_filesystem_path, empty_map);

            VSOMEIP_INFO << __func__ << ": Insert policy extension path: [" << its_filesystem_path
                    << "] for hostname: [" << its_client_host << "]";
        }
    } catch (...) {
    }
}

template<typename T_>
void policy_manager_impl::load_interval_set(
        const boost::property_tree::ptree &_tree,
        boost::icl::interval_set<T_> &_intervals, bool _exclude_margins) {

    boost::icl::interval_set<T_> its_intervals;
    T_ its_min = std::numeric_limits<T_>::min();
    T_ its_max = std::numeric_limits<T_>::max();

    if (_exclude_margins) {
        its_min++;
        its_max--;
    }

    const std::string its_key(_tree.data());
    if (its_key == "any") {
        its_intervals.insert(boost::icl::discrete_interval<T_>::closed(
                its_min, its_max));
    } else {
        for (auto i = _tree.begin(); i != _tree.end(); ++i) {
            auto its_data = i->second;
            if (!its_data.data().empty()) {
                T_ its_id;
                read_data(its_data.data(), its_id);
                if (its_id >= its_min && its_id <= its_max)
                    its_intervals.insert(its_id);
            } else {
                T_ its_first, its_last;
                bool has_first(false), has_last(false);
                for (auto j = its_data.begin(); j != its_data.end(); ++j) {
                    std::string its_key(j->first);
                    std::string its_value(j->second.data());
                    if (its_key == "first") {
                        if (its_value == "min") {
                            its_first = its_min;
                        } else {
                            read_data(its_value, its_first);
                        }
                        has_first = true;
                    } else if (its_key == "last") {
                        if (its_value == "max") {
                            its_last = its_max;
                        } else {
                            read_data(its_value, its_last);
                        }
                        has_last = true;
                    } else {
                        VSOMEIP_WARNING << "vSomeIP Security: Security configuration: "
                                << " Malformed range. Contains illegal key ("
                                << its_key << ")";
                    }
                }
                if (has_first && has_last && its_first <= its_last) {
                    its_intervals.insert(
                        boost::icl::discrete_interval<T_>::closed(its_first, its_last));
                }
            }
        }
    }

    _intervals = its_intervals;
}

void
policy_manager_impl::get_requester_policies(const std::shared_ptr<policy> _policy,
        std::set<std::shared_ptr<policy> > &_requesters) const {

    std::scoped_lock its_lock {any_client_policies_mutex_, _policy->mutex_};
    for (const auto &o : _policy->offers_) {
        for (const auto &p : any_client_policies_) {
            if (p == _policy)
                continue;

            std::lock_guard<std::mutex> its_lock(p->mutex_);

            auto its_policy = std::make_shared<policy>();
            its_policy->credentials_ = p->credentials_;

            for (const auto &r : p->requests_) {
                // o represents an offer by a service interval and its instances
                // (a set of intervals)
                // r represents a request by a service interval and its instances
                // and methods (instance intervals mapped to interval sets of methods)
                //
                // Thus, r matches o if their service identifiers as well as their
                // instances overlap. If r and o match, a new policy must be
                // created that contains the overlapping services/instances mapping
                // of r and o together with the methods from r
                service_t its_o_lower, its_o_upper, its_r_lower, its_r_upper;
                get_bounds(o.first, its_o_lower, its_o_upper);
                get_bounds(r.first, its_r_lower, its_r_upper);

                if (its_o_lower <= its_r_upper && its_r_lower <= its_o_upper) {
                    auto its_service_min = std::max(its_o_lower, its_r_lower);
                    auto its_service_max = std::min(its_r_upper, its_o_upper);

                    for (const auto &i : o.second) {
                        for (const auto &j : r.second) {
                            for (const auto &k : j.second) {
                                instance_t its_i_lower, its_i_upper, its_k_lower, its_k_upper;
                                get_bounds(i, its_i_lower, its_i_upper);
                                get_bounds(k, its_k_lower, its_k_upper);

                                if (its_i_lower <= its_k_upper && its_k_lower <= its_i_upper) {
                                    auto its_instance_min = std::max(its_i_lower, its_k_lower);
                                    auto its_instance_max = std::min(its_i_upper, its_k_upper);

                                    boost::icl::interval_map<instance_t,
                                        boost::icl::interval_set<method_t> > its_instances_methods;
                                    its_instances_methods += std::make_pair(
                                            boost::icl::interval<instance_t>::closed(
                                                    its_instance_min, its_instance_max),
                                            j.second);

                                    its_policy->requests_ += std::make_pair(
                                            boost::icl::interval<instance_t>::closed(
                                                    its_service_min, its_service_max),
                                            its_instances_methods);
                                }
                            }
                        }
                    }
                }
            }

            if (!its_policy->requests_.empty()) {
                _requesters.insert(its_policy);
            }
        }
    }
}

void
policy_manager_impl::get_clients(uid_t _uid, gid_t _gid,
        std::unordered_set<client_t> &_clients) const {

    std::lock_guard<std::mutex> its_lock(ids_mutex_);
    for (const auto &i : ids_) {
        if (i.second.port == VSOMEIP_SEC_PORT_UNUSED
                && i.second.user == _uid
                && i.second.group == _gid)
            _clients.insert(i.first);
    }
}

bool
policy_manager_impl::is_policy_extension(const std::string &_path) const {
    auto its_pos = _path.find("vsomeip_policy_extensions.json");
    if (its_pos != std::string::npos) {
        return true;
    }
    return false;
}

void
policy_manager_impl::set_policy_extension_base_path(const std::string &_path) {
    auto its_pos = _path.find("vsomeip_policy_extensions.json");
    std::lock_guard<std::mutex> its_lock(policy_base_path_mutex_);
    policy_base_path_ = _path.substr(0, its_pos);
}

std::string
policy_manager_impl::get_policy_extension_path(const std::string &_client_host) const {
    boost::shared_lock<boost::shared_mutex> lock(policy_extension_paths_mutex_);
    return get_policy_extension_path_unlocked(_client_host);
}
//only be called after loading of the mutex
std::string
policy_manager_impl::get_policy_extension_path_unlocked(const std::string &_client_host) const {
    std::string its_path("");

    auto found_host = policy_extension_paths_.find(_client_host);

    if (found_host != policy_extension_paths_.end()) {
        its_path = found_host->second.first;
    }
    return its_path;
}

policy_manager_impl::policy_loaded_e
policy_manager_impl::is_policy_extension_loaded(const std::string &_client_host) const {
    boost::shared_lock<boost::shared_mutex> lock(policy_extension_paths_mutex_);

    auto found_host = policy_extension_paths_.find(_client_host);
    if (found_host != policy_extension_paths_.end()) {

        auto found_complete_path = found_host->second.second.find(
                get_security_config_folder(found_host->second.first));
        if (found_complete_path != found_host->second.second.end()) {
            if (found_complete_path->second) {
                return policy_manager_impl::policy_loaded_e::POLICY_PATH_FOUND_AND_LOADED;
            } else {
                return policy_manager_impl::policy_loaded_e::POLICY_PATH_FOUND_AND_NOT_LOADED;
            }
        }
    }

    // we do not have a path to load
    return policy_manager_impl::policy_loaded_e::POLICY_PATH_INEXISTENT;
}

void
policy_manager_impl::set_is_policy_extension_loaded(const std::string &_client_host,
        const bool _loaded) {
    boost::unique_lock<boost::shared_mutex> lock(policy_extension_paths_mutex_);
    auto found_host = policy_extension_paths_.find(_client_host);

    if (found_host != policy_extension_paths_.end()) {
        std::string its_folder = get_policy_extension_path_unlocked(_client_host);
        std::string its_complete_folder = get_security_config_folder(its_folder);

        // if the map key of complete path folder exist, will be updated
        //  if not will create an new entry
        found_host->second.second[its_complete_folder] = _loaded;
    }
}

std::string
policy_manager_impl::get_security_config_folder(const std::string &its_folder) const
{
    std::stringstream its_security_config_folder;
    its_security_config_folder << its_folder;

#if defined(__linux__) || defined(ANDROID) || defined(__QNX__)
    its_security_config_folder << "/" << getuid() << "_" << getgid();
#endif

    if (utility::is_folder(its_security_config_folder.str())) {
        return its_security_config_folder.str();
    } else {
        VSOMEIP_INFO << __func__<< ": Invalid folder for " << its_security_config_folder.str();
    }
    return std::string("");
}

std::shared_ptr<policy>
policy_manager_impl::create_policy() const {
    return std::make_shared<policy>();
}

void
policy_manager_impl::print_policy(const std::shared_ptr<policy> &_policy) const {

    if (_policy)
        _policy->print();
}

bool
policy_manager_impl::parse_uid_gid(const byte_t* &_buffer,
        uint32_t &_buffer_size, uid_t &_uid, gid_t &_gid) const {

   const auto its_policy = std::make_shared<policy>();
   return (its_policy
           && its_policy->deserialize_uid_gid(_buffer, _buffer_size, _uid, _gid));
}

#endif // !VSOMEIP_DISABLE_SECURITY

bool
policy_manager_impl::store_client_to_sec_client_mapping(
        client_t _client, const vsomeip_sec_client_t *_sec_client) {

    if (_sec_client != nullptr && _sec_client->port == VSOMEIP_SEC_PORT_UNUSED) {
        // store the client -> sec_client mapping
        std::lock_guard<std::mutex> its_lock(ids_mutex_);
        auto found_client = ids_.find(_client);
        if (found_client != ids_.end()) {
            if (!utility::compare(found_client->second, *_sec_client)) {
                uid_t its_old_uid = found_client->second.user;
                gid_t its_old_gid = found_client->second.group;
                uid_t its_new_uid = _sec_client->user;
                gid_t its_new_gid = _sec_client->group;

                VSOMEIP_WARNING << "vSomeIP Security: Client 0x"
                        << std::hex << _client << " with UID/GID="
                        << std::dec << its_new_uid << "/" << its_new_gid
                        << " : Overwriting existing credentials UID/GID="
                        << std::dec << its_old_uid << "/" << its_old_gid;

                found_client->second = *_sec_client;
                return true;
            }
        } else {
            ids_[_client] = *_sec_client;
        }
        return true;
    }

    return false;
}

bool
policy_manager_impl::get_client_to_sec_client_mapping(client_t _client,
        vsomeip_sec_client_t &_sec_client) {
    {
        // get the UID / GID of the client
        std::lock_guard<std::mutex> its_lock(ids_mutex_);
        if (ids_.find(_client) != ids_.end()) {
            _sec_client = ids_[_client];
            return true;
        }
        return false;
    }
}

bool
policy_manager_impl::remove_client_to_sec_client_mapping(client_t _client) {

    vsomeip_sec_client_t its_sec_client;
    bool is_client_removed(false);
    bool is_sec_client_removed(false);
    {
        std::lock_guard<std::mutex> its_lock(ids_mutex_);
        auto found_client = ids_.find(_client);
        if (found_client != ids_.end()) {
            its_sec_client = found_client->second;
            ids_.erase(found_client);
            is_client_removed = true;
        }
    }
    {
        std::lock_guard<std::mutex> its_lock(sec_client_to_clients_mutex_);
        if (is_client_removed) {
            auto found_sec_client = sec_client_to_clients_.find(its_sec_client);
            if (found_sec_client != sec_client_to_clients_.end()) {
               auto its_client = found_sec_client->second.find(_client);
               if (its_client != found_sec_client->second.end()) {
                   found_sec_client->second.erase(its_client);
                   if (found_sec_client->second.empty()) {
                       sec_client_to_clients_.erase(found_sec_client);
                   }
                   is_sec_client_removed = true;
               }
            }
        } else {
            for (auto it = sec_client_to_clients_.begin();
                    it != sec_client_to_clients_.end(); ++it) {
                auto its_client = it->second.find(_client);
                if (its_client != it->second.end()) {
                    it->second.erase(its_client);
                    if (it->second.empty()) {
                        sec_client_to_clients_.erase(it);
                    }
                    is_sec_client_removed = true;
                    break;
                }
            }
        }
    }

    return (is_client_removed && is_sec_client_removed);
}

void
policy_manager_impl::store_sec_client_to_client_mapping(
        const vsomeip_sec_client_t *_sec_client, client_t _client) {

    if (_sec_client && _sec_client->port == VSOMEIP_SEC_PORT_UNUSED) {
        // store the uid gid to clients mapping
        std::lock_guard<std::mutex> its_lock(sec_client_to_clients_mutex_);
        auto found_sec_client = sec_client_to_clients_.find(*_sec_client);
        if (found_sec_client != sec_client_to_clients_.end()) {
            found_sec_client->second.insert(_client);
        } else {
            std::set<client_t> mapped_clients;
            mapped_clients.insert(_client);
            sec_client_to_clients_.insert(std::make_pair(*_sec_client, mapped_clients));
        }
    }
}

bool
policy_manager_impl::get_sec_client_to_clients_mapping(
        const vsomeip_sec_client_t *_sec_client,
        std::set<client_t> &_clients) {

    if (_sec_client && _sec_client->port == VSOMEIP_SEC_PORT_UNUSED) {
        // get the clients corresponding to uid, gid
        std::lock_guard<std::mutex> its_lock(sec_client_to_clients_mutex_);
        auto found_sec_client = sec_client_to_clients_.find(*_sec_client);
        if (found_sec_client != sec_client_to_clients_.end()) {
            _clients = found_sec_client->second;
            return true;
        }
    }
    return false;
}

} // namespace vsomeip_v3
