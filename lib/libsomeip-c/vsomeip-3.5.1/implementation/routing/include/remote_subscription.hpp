// Copyright (C) 2018-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_REMOTE_SUBSCRIPTION_HPP_
#define VSOMEIP_V3_REMOTE_SUBSCRIPTION_HPP_

#include <atomic>
#include <map>
#include <mutex>
#include <set>

#include <vsomeip/primitive_types.hpp>

#include "../../endpoints/include/endpoint_definition.hpp"
#include "types.hpp"
#include <vsomeip/export.hpp>

#if defined(__QNX__)
#include "../../utility/include/qnx_helper.hpp"
#endif

namespace vsomeip_v3 {

class eventgroupinfo;

const remote_subscription_id_t PENDING_SUBSCRIPTION_ID(0);

class remote_subscription {
public:
    VSOMEIP_EXPORT remote_subscription();
    VSOMEIP_EXPORT ~remote_subscription();

    bool operator==(const remote_subscription &_other) const;
    bool equals(const std::shared_ptr<remote_subscription> &_other) const;
    bool address_equals(const std::shared_ptr<remote_subscription> &_other) const;

    VSOMEIP_EXPORT void reset(const std::set<client_t> &_clients);

    VSOMEIP_EXPORT bool is_initial() const;
    VSOMEIP_EXPORT void set_initial(const bool _is_initial);

    VSOMEIP_EXPORT bool force_initial_events() const;
    VSOMEIP_EXPORT void set_force_initial_events(const bool _force_initial_events);

    remote_subscription_id_t get_id() const;
    void set_id(const remote_subscription_id_t _id);

    VSOMEIP_EXPORT std::shared_ptr<remote_subscription> get_parent() const;
    void set_parent(const std::shared_ptr<remote_subscription> &_parent);

    VSOMEIP_EXPORT std::shared_ptr<eventgroupinfo> get_eventgroupinfo() const;
    VSOMEIP_EXPORT void set_eventgroupinfo(const std::shared_ptr<eventgroupinfo> &_info);

    VSOMEIP_EXPORT ttl_t get_ttl() const;
    VSOMEIP_EXPORT void set_ttl(const ttl_t _ttl);

    uint16_t get_reserved() const;
    void set_reserved(const uint16_t _reserved);

    uint8_t get_counter() const;
    void set_counter(uint8_t _counter);

    VSOMEIP_EXPORT std::set<client_t> get_clients() const;
    bool has_client() const;
    bool has_client(const client_t _client) const;
    void remove_client(const client_t _client);

    VSOMEIP_EXPORT remote_subscription_state_e get_client_state(const client_t _client) const;
    void set_client_state(const client_t _client,
            remote_subscription_state_e _state);
    void set_all_client_states(remote_subscription_state_e _state);

    std::chrono::steady_clock::time_point get_expiration(const client_t _client) const;

    VSOMEIP_EXPORT std::shared_ptr<endpoint_definition> get_subscriber() const;
    VSOMEIP_EXPORT void set_subscriber(const std::shared_ptr<endpoint_definition> &_subscriber);

    VSOMEIP_EXPORT std::shared_ptr<endpoint_definition> get_reliable() const;
    VSOMEIP_EXPORT void set_reliable(const std::shared_ptr<endpoint_definition> &_reliable);

    VSOMEIP_EXPORT std::shared_ptr<endpoint_definition> get_unreliable() const;
    VSOMEIP_EXPORT void set_unreliable(const std::shared_ptr<endpoint_definition> &_unreliable);

    VSOMEIP_EXPORT bool is_pending() const;
    bool is_acknowledged() const;

    std::set<client_t> update(const std::set<client_t> &_clients,
            const std::chrono::steady_clock::time_point &_timepoint,
            const bool _is_subscribe);

    VSOMEIP_EXPORT std::uint32_t get_answers() const;
    VSOMEIP_EXPORT void set_answers(const std::uint32_t _answers);

    VSOMEIP_EXPORT bool get_ip_address(boost::asio::ip::address &_address) const;

    bool is_expired() const;
    void set_expired();
    bool is_forwarded() const;
    void set_forwarded();

private:
    std::atomic<remote_subscription_id_t> id_;
    std::atomic<bool> is_initial_;
    std::atomic<bool> force_initial_events_;
    std::weak_ptr<remote_subscription> parent_;

    std::weak_ptr<eventgroupinfo> eventgroupinfo_;

    ttl_t ttl_;
    std::uint16_t reserved_;
    std::uint8_t counter_;

    std::map<client_t,
        std::pair<remote_subscription_state_e,
            std::chrono::steady_clock::time_point
        >
    > clients_;

    // The endpoint that sent(!) the subscription
    std::shared_ptr<endpoint_definition> subscriber_;

    // The endpoints defined by the endpoint options
    std::shared_ptr<endpoint_definition> reliable_;
    std::shared_ptr<endpoint_definition> unreliable_;

    // Number of acknowledgements that must be sent
    // for the subscriptions. This is usally 1, but
    // may be larger if a matching subscription arrived
    // before the subscription could be acknowledged
    std::atomic<std::uint32_t> answers_;

    mutable std::mutex mutex_;

    /*
     * This flag specifies what the "winner" of the
     * expire_subscriptions()/on_remote_subscribe()
     * race shall have as destination:
     * - expiration, if expire_subscriptions() runs first
     * - forwarding, if on_remote_subscribe() runs first
     */
    enum struct destiny : std::uint8_t {
        none,
        expire,
        forward
    };
    std::atomic<destiny> final_destination_;
};

} // namespace vsomeip_v3

#endif // VSOMEIP_V3_REMOTE_SUBSCRIPTION_HPP_
