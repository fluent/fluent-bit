// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_SERVICEINFO_HPP_
#define VSOMEIP_V3_SERVICEINFO_HPP_

#include <atomic>
#include <memory>
#include <set>
#include <string>
#include <chrono>
#include <mutex>

#include <vsomeip/export.hpp>
#include <vsomeip/primitive_types.hpp>

namespace vsomeip_v3 {

class endpoint;

class serviceinfo {
public:
    VSOMEIP_EXPORT serviceinfo(service_t _service, instance_t _instance,
            major_version_t _major, minor_version_t _minor,
            ttl_t _ttl, bool _is_local);
    VSOMEIP_EXPORT serviceinfo(const serviceinfo& _other);
    VSOMEIP_EXPORT ~serviceinfo();

    VSOMEIP_EXPORT service_t get_service() const;
    VSOMEIP_EXPORT instance_t get_instance() const;

    VSOMEIP_EXPORT major_version_t get_major() const;
    VSOMEIP_EXPORT minor_version_t get_minor() const;

    VSOMEIP_EXPORT ttl_t get_ttl() const;
    VSOMEIP_EXPORT void set_ttl(ttl_t _ttl);

    VSOMEIP_EXPORT std::chrono::milliseconds get_precise_ttl() const;
    VSOMEIP_EXPORT void set_precise_ttl(std::chrono::milliseconds _precise_ttl);

    VSOMEIP_EXPORT std::shared_ptr<endpoint> get_endpoint(bool _reliable) const;
    VSOMEIP_EXPORT void set_endpoint(const std::shared_ptr<endpoint>& _endpoint,
            bool _reliable);

    VSOMEIP_EXPORT void add_client(client_t _client);
    VSOMEIP_EXPORT void remove_client(client_t _client);
    VSOMEIP_EXPORT uint32_t get_requesters_size();

    VSOMEIP_EXPORT bool is_local() const;

    VSOMEIP_EXPORT bool is_in_mainphase() const;
    VSOMEIP_EXPORT void set_is_in_mainphase(bool _in_mainphase);

    VSOMEIP_EXPORT bool is_accepting_remote_subscriptions() const;
    VSOMEIP_EXPORT void set_accepting_remote_subscriptions(bool _accepting_remote_subscriptions);

    VSOMEIP_EXPORT void add_remote_ip(std::string _remote_ip);
    VSOMEIP_EXPORT std::set<std::string, std::less<>> get_remote_ip_accepting_sub();

private:
    service_t service_;
    instance_t instance_;

    major_version_t major_;
    minor_version_t minor_;

    mutable std::mutex ttl_mutex_;
    std::chrono::milliseconds ttl_;

    std::shared_ptr<endpoint> reliable_;
    std::shared_ptr<endpoint> unreliable_;

    mutable std::mutex endpoint_mutex_;
    std::mutex requesters_mutex_;
    std::set<client_t> requesters_;

    std::atomic_bool is_local_;
    std::atomic_bool is_in_mainphase_;

    // Added flag, to ensure the lib only process subscriptions request
    // when at least one offer is sent from SD, otherwise will be sent a NACK
    // this is needed to avoid desynchronizations triggered by high CPU load
    std::atomic_bool accepting_remote_subscription_; // offers sent to multicast
    std::set<std::string, std::less<>>
            accepting_remote_subscription_from_; // offers sent by unicast
    std::mutex accepting_remote_mutex;
};

}  // namespace vsomeip_v3

#endif // VSOMEIP_V3_SERVICEINFO_HPP_
