// Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_SERVICE_HPP
#define VSOMEIP_SERVICE_HPP

#include <future>
#include <list>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include <vsomeip/vsomeip.hpp>
#include <vsomeip/internal/logger.hpp>
#include <common/vsomeip_app_utilities.hpp>

/// @brief Wrapper for a vsomeip application that offers 2 services with a GET method
class service_t : public vsomeip_utilities::base_logger {
public:
    /// @brief Initializes vsomeip application and availability table
    service_t();

    /// @brief Stops vsomeip application
    ~service_t();

    /// @brief Initializes vsomeip application and registers message and availability handlers
    ///        Also requests own services to force the routing manager to offer them.
    ///
    /// @return true if vsomeip->init() was successful
    bool init();

    /// @brief Starts vsomeip application on a background thread. Non blocking call.
    void start();

    /// @brief Stops vsomeip application
    void stop();

    /// @brief Offers both services
    ///
    /// @return returns a future that will notify that the availability to this service was changed
    std::future<bool> offer();

    /// @brief Stops offering both services
    ///
    /// @return returns a future that will notify that the availability to this service was changed
    std::future<bool> stop_offer();

private:
    /// @brief handler for receiving requests. Will send a response back with a big payload and a
    ///        changing first byte
    ///
    /// @param message Request message received
    void on_message(const std::shared_ptr<vsomeip::message>& message);

    /// @brief handler for services availability.
    ///
    /// @param service Service that had its availability state changed
    /// @param instance Instance that had its availability state changed
    /// @param is_available New availability state
    void on_availability(vsomeip::service_t service, vsomeip::instance_t instance,
                         bool is_available);

    /// @brief vsomeip app interface
    std::shared_ptr<vsomeip::application> vsomeip_app;

    /// @brief payload sent in the responde of the requests
    std::vector<uint8_t> payload;

    /// @brief availability table containing the availability state of both services
    std::map<vsomeip::service_t, bool> availability_table;
    /// @brief availability table mutex
    std::mutex availability_mutex;

    /// @brief background thread that will serve as context for the vsomeip application
    std::thread worker;

    /// @brief application offer state for both services.
    bool is_offering;

    /// @brief promise which value shall be set once the availability is received
    std::promise<bool> promise_availability;
};

#endif // VSOMEIP_SERVICE_HPP
