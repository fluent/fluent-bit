// Copyright (C) 2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_SD_REMOTE_SUBSCRIPTION_ACK_HPP_
#define VSOMEIP_V3_SD_REMOTE_SUBSCRIPTION_ACK_HPP_

#include <memory>
#include <mutex>
#include <set>

namespace vsomeip_v3 {

class remote_subscription;

namespace sd {

class message_impl;

class remote_subscription_ack {
public:
    remote_subscription_ack(const boost::asio::ip::address &_address);

    // The complete flag signals whether or not all subscribes
    // of a message have been inserted.
    bool is_complete() const;
    void complete();

    // The done flag signals whether or not all subscribes
    // have been processed.
    bool is_done() const;
    void done();

    std::vector<std::shared_ptr<message_impl> > get_messages() const;
    std::shared_ptr<message_impl> get_current_message() const;
    std::shared_ptr<message_impl> add_message();

    boost::asio::ip::address get_target_address() const;

    bool is_pending() const;

    std::set<std::shared_ptr<remote_subscription> > get_subscriptions() const;
    void add_subscription(
            const std::shared_ptr<remote_subscription> &_subscription);
    bool has_subscription() const;

    std::unique_lock<std::recursive_mutex> get_lock();

private:
    std::recursive_mutex mutex_;
    std::vector<std::shared_ptr<message_impl> > messages_;
    bool is_complete_;
    bool is_done_;

    const boost::asio::ip::address target_address_;

    std::set<std::shared_ptr<remote_subscription> > subscriptions_;
};

} // namespace sd
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_SD_REMOTE_SUBSCRIPTION_ACK_HPP_
