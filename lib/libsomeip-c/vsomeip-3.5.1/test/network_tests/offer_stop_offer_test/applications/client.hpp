// Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_CLIENT_HPP
#define VSOMEIP_CLIENT_HPP

#include <future>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>

#include <vsomeip/vsomeip.hpp>
#include <vsomeip/internal/logger.hpp>
#include <common/vsomeip_app_utilities.hpp>

/// @brief Wrapper for a vsomeip application that requests 2 services with a GET method
class client_t : public vsomeip_utilities::base_logger {
public:
    /// @brief Initializes vsomeip application and availability table
    client_t();

    /// @brief Stops vsomeip application
    ~client_t();

    /// @brief Initializes vsomeip application and registers message and availability handlers
    ///        Also requests services.
    ///
    /// @return true if vsomeip->init() was successful
    bool init();
    void start();
    void stop();

    /// @brief Sends a someip request to the specified service. Will associate a promise with the
    ///        request, to later notify a future of the reception of its response.
    ///
    /// @param is_tcp If true the request will be sent via TCP. UDP will be used otherwise.
    /// @param service Service to send the request to.
    /// @param instance Instance to send the request to.
    /// @param method Method to send the request to.
    ///
    /// @return returns a future that will notify that responde to this requests was received
    std::future<bool> request(bool is_tcp, vsomeip::service_t service,
                                               vsomeip::instance_t instance,
                                               vsomeip::method_t method);

    /// @brief Check if both services are available
    ///
    /// @return true if both services are available; false if one or both were not available.
    bool is_available();

private:
    /// @brief handler for receiving responses. Will set the promise value of the received service.
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

    /// @brief availability table containing the availability state of both services
    std::map<vsomeip::service_t, bool> availability_table;

    /// @brief availability table mutex
    std::mutex availability_mutex;

    /// @brief background thread that will serve as context for the vsomeip application
    std::thread worker;

    /// @brief Struct to hold the information of requests awaiting reponses
    struct client_request_t {
        /// @brief Request service
        vsomeip::service_t service;

        /// @brief Request instance
        vsomeip::instance_t instance;

        /// @brief Request method
        vsomeip::method_t method;

        /// @brief promise which value shall be set once the response is received
        std::promise<bool> promise_response;
    };

    /// @brief List to hold the current client_request_t awaiting responses.
    ///        client_request_t are removed after the response is received and promise is set.
    std::list<client_request_t> pending_requests;

};

#endif // VSOMEIP_CLIENT_HPP
