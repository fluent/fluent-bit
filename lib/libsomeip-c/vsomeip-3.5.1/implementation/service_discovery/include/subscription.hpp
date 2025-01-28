// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_SD_SUBSCRIPTION_HPP_
#define VSOMEIP_V3_SD_SUBSCRIPTION_HPP_

#include <map>
#include <memory>
#include <mutex>
#include <set>

#include <vsomeip/primitive_types.hpp>
#include <vsomeip/enumeration_types.hpp>

namespace vsomeip_v3 {

class endpoint;
class eventgroupinfo;

namespace sd {

enum class subscription_state_e : uint8_t {
    ST_ACKNOWLEDGED = 0x00,
    ST_NOT_ACKNOWLEDGED = 0x01,
    ST_RESUBSCRIBING = 0x2,
    ST_RESUBSCRIBING_NOT_ACKNOWLEDGED = 0x3,
    ST_UNKNOWN = 0xFF
};

class subscription {
public:
    subscription() = default;
    ~subscription() = default;

    major_version_t get_major() const;
    void set_major(major_version_t _major);

    ttl_t get_ttl() const;
    void set_ttl(ttl_t _ttl);

    std::shared_ptr<endpoint> get_endpoint(bool _reliable) const;
    void set_endpoint(const std::shared_ptr<endpoint>& _endpoint, bool _reliable);

    bool is_selective() const;
    void set_selective(const bool _is_selective);

    subscription_state_e get_state(const client_t _client) const;
    void set_state(const client_t _client, subscription_state_e _state);

    bool is_tcp_connection_established() const;
    void set_tcp_connection_established(bool _is_established);

    bool is_udp_connection_established() const;
    void set_udp_connection_established(bool _is_established);

    bool add_client(const client_t _client);
    bool remove_client(const client_t _client);
    std::set<client_t> get_clients() const;
    bool has_client() const;
    bool has_client(const client_t _client) const;

    void set_eventgroupinfo(const std::shared_ptr<eventgroupinfo> _info);
    std::weak_ptr<eventgroupinfo> get_eventgroupinfo() const;

private:
    major_version_t major_;
    ttl_t ttl_;

    std::shared_ptr<endpoint> reliable_;
    std::shared_ptr<endpoint> unreliable_;

    bool is_selective_;

    bool tcp_connection_established_;
    bool udp_connection_established_;

    mutable std::mutex clients_mutex_;
    std::map<client_t, subscription_state_e> clients_; // client-> is acknowledged?

    std::weak_ptr<eventgroupinfo> eg_info_;
};

} // namespace sd
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_SD_SUBSCRIPTION_HPP_

