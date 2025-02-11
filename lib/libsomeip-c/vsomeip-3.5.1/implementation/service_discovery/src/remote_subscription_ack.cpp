// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "../include/message_impl.hpp"
#include "../include/remote_subscription_ack.hpp"
#include "../../routing/include/remote_subscription.hpp"

namespace vsomeip_v3 {
namespace sd {

remote_subscription_ack::remote_subscription_ack(const boost::asio::ip::address &_address)
    : is_complete_(false),
      is_done_(false),
      target_address_(_address) {
    messages_.push_back(std::make_shared<message_impl>());
}

bool
remote_subscription_ack::is_complete() const {
    return is_complete_;
}

void
remote_subscription_ack::complete() {
    is_complete_ = true;
}

bool
remote_subscription_ack::is_done() const {
    return is_done_;
}

void
remote_subscription_ack::done() {
    is_done_ = true;
}

std::vector<std::shared_ptr<message_impl> >
remote_subscription_ack::get_messages() const {
    return messages_;
}

std::shared_ptr<message_impl> remote_subscription_ack::get_current_message() const {
    return messages_.back();
}

std::shared_ptr<message_impl> remote_subscription_ack::add_message() {
    messages_.emplace_back(std::make_shared<message_impl>());
    return messages_.back();
}

boost::asio::ip::address
remote_subscription_ack::get_target_address() const {
    return target_address_;
}

bool
remote_subscription_ack::is_pending() const {
    for (const auto& its_subscription : subscriptions_) {
        if (its_subscription->is_pending()
                && its_subscription->get_answers() != 0) {
            return true;
        }
    }
    return false;
}

std::set<std::shared_ptr<remote_subscription> >
remote_subscription_ack::get_subscriptions() const {
    return subscriptions_;
}

void
remote_subscription_ack::add_subscription(
        const std::shared_ptr<remote_subscription> &_subscription) {
    subscriptions_.insert(_subscription);
}

bool
remote_subscription_ack::has_subscription() const {
    return (0 < subscriptions_.size());
}

std::unique_lock<std::recursive_mutex> remote_subscription_ack::get_lock() {
    return std::unique_lock<std::recursive_mutex>(mutex_);
}

} // namespace sd
} // namespace vsomeip_v3
