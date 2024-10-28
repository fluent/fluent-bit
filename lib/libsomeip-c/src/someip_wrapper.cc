/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
#include <cstdlib>
#include <functional>
#include <future>
#include <iostream>
#include <map>
#include <mutex>
#include <queue>
#include <set>

#include <vsomeip/vsomeip.hpp>

#include "someip_api.h"

namespace {
    /**
     * Method used to retrieve the SOME/IP library mutex
     *
     * This mutex should be held when accessing/modifying the following:
     *
     * - Map of application client contexts
     *
     * @return Mutex instance
     */
    std::mutex& someip_mutex() {
        static std::mutex the_mutex;
        return the_mutex;
    }

    /**
     * Encapsulates a specific SOME/IP application context
     */
    class SomeIpContext {
    public:
        /**
         * Encapsulates a service instance
         */
        struct Service {
            vsomeip::service_t service_id;   /* Service identifier */
            vsomeip::instance_t instance_id; /* Service instance */

            bool operator==(const Service& other) const {
                return service_id == other.service_id && instance_id == other.instance_id;
            }

            bool operator<(const Service& other) const {
                if ((service_id < other.service_id) ||
                    (service_id == other.service_id && instance_id < other.instance_id)) {
                    return true;
                }
                return false;
            }
        };

        /**
         * Encapsulates a SOME/IP method
         */
        struct Method {
            Service service;
            vsomeip::method_t method_id;

            bool operator==(const Method& other) const {
                return service == other.service && method_id == other.method_id;
            }

            bool operator<(const Method& other) const {
                if ((service < other.service) ||
                    (service == other.service && method_id < other.method_id)) {
                    return true;
                }
                return false;
            }
        };

        /*
         * Encapsulates a SOME/IP event
         */
        struct Event {
            Service service;
            vsomeip::event_t event_id;
        };

        using NotifyHandler       = std::function<void()>;
        using ResponseHandler     = std::function<void(uint32_t)>;
        using AvailabilityHandler = std::function<void(bool)>;
        using RequestHandler      = std::function<void(uint32_t, uint8_t*, uint32_t)>;

        explicit SomeIpContext(std::shared_ptr<vsomeip::application> app) :
            application_(std::move(app)) {
        }

        void Start() {
            // Launch a thread that calls the start method on the application
            // Local mutex used to sync between this thread and the start thread
            std::mutex start_mutex;

            // Used by the start thread to indicated to this thread it has been started
            std::condition_variable start_thread_executing;
            auto thread_running{false};

            // Start up event handling thread
            auto app = application_;
            auto run{
                [&start_thread_executing, &thread_running, &start_mutex,
                 app_copy = app] {
                    // start() blocks, so notify the calling thread that we started
                    // executing
                    {
                        std::lock_guard<std::mutex> local_lock{
                            start_mutex};
                        thread_running = true;
                        start_thread_executing.notify_all();
                    }
                    // Blocks until application->stop() has been called
                    app_copy->start();
                }};

            // Launch the thread that blocks on start();
            start_future_ = std::async(std::launch::async, run);

            // Wait until the start thread has started executing
            std::unique_lock<std::mutex> start_lock{start_mutex};
            start_thread_executing.wait(start_lock, [&thread_running] {
                return thread_running;
            });
        }

        void Shutdown() {
            std::lock_guard<std::mutex> lock{context_mutex_};
            if (application_) {
                // Call stop and wait for the start thread to exit
                application_->stop();
                start_future_.wait();
                application_.reset();
            }
        }

        int GetNextEvent(some_ip_event* event_ptr) {
            std::shared_ptr<vsomeip::message> message;
            {
                std::lock_guard<std::mutex> lock{
                    context_mutex_};
                if (!event_queue_.empty()) {
                    message = event_queue_.front();
                    event_queue_.pop();
                }
            }

            if (!message) {
                return SOMEIP_RET_NO_EVENT_AVAILABLE;
            }

            auto&& payload{message->get_payload()};
            event_ptr->service_id  = message->get_service();
            event_ptr->instance_id = message->get_instance();
            event_ptr->event_id    = message->get_method();
            event_ptr->event_len   = payload->get_length();
            if (event_ptr->event_len > 0) {
                event_ptr->event_data =
                    (uint8_t*)malloc(event_ptr->event_len);
                if (event_ptr->event_data == nullptr) {
                    return SOMEIP_RET_FAILURE;
                }
                std::copy(payload->get_data(),
                          payload->get_data() + payload->get_length(),
                          event_ptr->event_data);
            }
            else {
                event_ptr->event_data = nullptr;
            }

            return SOMEIP_RET_SUCCESS;
        }

        void SubscribeForEvent(const Event& event,
                               const std::set<uint16_t>& groups,
                               NotifyHandler handler) {
            std::lock_guard<std::mutex> lock{context_mutex_};
            // Register message handler for the event
            auto message_handler{
                [this, handler =
                           std::move(handler)](const std::shared_ptr<
                                               vsomeip::message>& message) {
                    {
                        std::cout << "Received message for service " << message->get_service() << " event = " << message->get_method() << std::endl;
                        std::lock_guard<std::mutex> lock{context_mutex_};
                        event_queue_.push(message);
                    }
                    handler();
                }};
            application_->register_message_handler(event.service.service_id, event.service.instance_id,
                                                   event.event_id, std::move(message_handler));
            application_->request_event(event.service.service_id, event.service.instance_id,
                                        event.event_id, groups);
            for (auto&& event_group : groups) {
                application_->subscribe(event.service.service_id,
                                        event.service.instance_id,
                                        event_group);
            }

            // Make sure we have requested this service
            CheckAndRequestService(event.service);
        }

        void RequestService(const Service& service,
                            AvailabilityHandler cb) {
            std::lock_guard<std::mutex> lock(context_mutex_);
            CheckAndRequestService(service);
            availability_handlers_[service].emplace_back(std::move(cb));
        }

        int SendRequest(some_ip_request* parameters,
                        ResponseHandler response_handler) {
            std::lock_guard<std::mutex> lock(context_mutex_);
            // Make sure we have requested the service
            const Service service{
                parameters->request_id.service_id,
                parameters->request_id.instance_id};

            CheckAndRequestService(service);

            // There really is no need to send request if the service is not available
            // yet. Fail and let the client retry
            if (!requested_services_[service]) {
                return SOMEIP_RET_SERVICE_NOT_AVAILABLE;
            }

            // We can't have a single handler for the response (unfortunately) we need to
            // register a handler just for this method
            const Method method{
                service,
                parameters->method_id};
            auto&& method_entry(registered_methods_.find(method));
            if (method_entry == registered_methods_.end()) {
                auto method_message_handler{
                    [this](const std::shared_ptr<vsomeip::message>& message) {
                        HandleResponse(message);
                    }};
                application_->register_message_handler(service.service_id,
                                                       service.instance_id,
                                                       method.method_id,
                                                       std::move(method_message_handler));
            }

            auto request{vsomeip::runtime::get()->create_request()};
            request->set_service(service.service_id);
            request->set_instance(service.instance_id);
            request->set_method(method.method_id);
            if (!response_handler) {
                // No response callback specified. Setting message type to fire and forget.
                request->set_message_type(vsomeip_v3::message_type_e::
                                              MT_REQUEST_NO_RETURN);
            }

            auto request_payload{
                vsomeip::runtime::get()->create_payload(parameters->payload,
                                                        parameters->payload_len)};
            request->set_payload(request_payload);
            application_->send(request);
            parameters->request_id.client_request_id =
                request->get_request();
            if (response_handler) {
                auto&& service_map{pending_requests_[service]};
                service_map[parameters->request_id.client_request_id] =
                    std::move(response_handler);
            }
            return SOMEIP_RET_SUCCESS;
        }

        int GetResponse(some_ip_response* response_ptr) {
            std::lock_guard<std::mutex> lock(context_mutex_);
            // See if we can find the response
            const Service service{
                response_ptr->request_id.service_id,
                response_ptr->request_id.instance_id};
            auto&& service_response_entry{
                responses_.find(service)};
            if (service_response_entry == responses_.end()) {
                return SOMEIP_RET_REQUEST_NOT_FOUND;
            }

            auto&& service_responses(service_response_entry->second);
            auto&& request_entry(service_responses.find(response_ptr->request_id.client_request_id));
            if (request_entry == service_responses.end()) {
                return SOMEIP_RET_REQUEST_NOT_FOUND;
            }

            auto&& response_message(request_entry->second);
            auto&& payload(response_message->get_payload());
            response_ptr->payload_len = payload->get_length();
            if (response_ptr->payload_len > 0) {
                response_ptr->payload =
                    (uint8_t*)malloc(response_ptr->payload_len);
                if (response_ptr->payload == nullptr) {
                    return SOMEIP_RET_FAILURE;
                }
                std::copy(payload->get_data(),
                          payload->get_data() + payload->get_length(),
                          response_ptr->payload);
            }
            else {
                response_ptr->payload = nullptr;
            }

            // Clean up
            service_responses.erase(request_entry);
            if (service_responses.empty()) {
                responses_.erase(service_response_entry);
            }
            return SOMEIP_RET_SUCCESS;
        }

        void OfferEvent(const Event& event,
                        const std::set<uint16_t>& event_groups) {
            std::lock_guard<std::mutex> lock(context_mutex_);
            application_->offer_event(event.service.service_id,
                                      event.service.instance_id,
                                      event.event_id, event_groups);
        }

        void OfferService(const Service& service) {
            std::lock_guard<std::mutex> lock{context_mutex_};
            application_->offer_service(service.service_id,
                                        service.instance_id);
        }

        void SendNotification(const Event& event,
                              std::shared_ptr<vsomeip::payload> payload) {
            std::lock_guard<std::mutex> lock(context_mutex_);
            application_->notify(event.service.service_id,
                                 event.service.instance_id,
                                 event.event_id, payload, true);
            std::cout << "Sent notification for service " << event.service.service_id << ", event " << event.event_id << std::endl;
        }

        void AddRequestHandler(const Method& method,
                               RequestHandler handler) {
            auto message_handler{
                [this, handler =
                           std::move(handler)](const std::shared_ptr<vsomeip::message>& message) {
                    // Create the pending response
                    const auto request_id{message->get_request()};
                    auto pending_response{
                        ::vsomeip::runtime::get()->create_response(message)};
                    {
                        std::lock_guard<std::mutex> callback_lock{
                            context_mutex_};
                        pending_responses_[request_id] =
                            std::move(pending_response);
                    }
                    auto payload(message->get_payload());
                    uint8_t* payload_bytes{nullptr};
                    uint32_t payload_size{0};
                    if (payload && payload->get_length() > 0) {
                        payload_bytes = payload->get_data();
                        payload_size  = payload->get_length();
                    }
                    handler(request_id, payload_bytes, payload_size);
                }};
            std::lock_guard<std::mutex> lock(context_mutex_);
            application_->register_message_handler(method.service.service_id,
                                                   method.service.instance_id,
                                                   method.method_id,
                                                   std::move(message_handler));
        }

        void SendResponse(const uint32_t request_id,
                          const std::vector<uint8_t>& payload) {
            std::lock_guard<std::mutex> lock(context_mutex_);
            auto&& pending_response(pending_responses_.find(request_id));
            if (pending_response == pending_responses_.end()) {
                return;
            }
            auto response_message(pending_response->second);
            auto response_payload(vsomeip::runtime::get()->create_payload(payload));
            response_message->set_payload(response_payload);
            application_->send(response_message);
            pending_responses_.erase(pending_response);
        }

    private:
        std::shared_ptr<vsomeip::application> application_;
        std::mutex context_mutex_;
        std::future<void> start_future_;
        std::queue<std::shared_ptr<vsomeip::message>> event_queue_;
        std::map<Service, bool> requested_services_;
        std::map<Service,
                 std::vector<AvailabilityHandler>>
            availability_handlers_;
        std::set<Method> registered_methods_;
        std::map<Service, std::map<vsomeip::request_t,
                                   ResponseHandler>>
            pending_requests_;
        std::map<Service, std::map<vsomeip::request_t,
                                   std::shared_ptr<vsomeip::message>>>
            responses_;
        std::map<vsomeip::request_t,
                 std::shared_ptr<vsomeip::message>>
            pending_responses_;
        /**
         * Function to check if the specified service instance has been requested. If it
         * hasn't been requested, then request it and add to the requested service list.
         *
         * @param Service SOME/IP Service
         */
        void CheckAndRequestService(const Service& service) {
            auto&& service_entry{requested_services_.find(service)};
            if (service_entry == requested_services_.end()) {
                // Handler called by vsomeip to inform of service availability
                auto availability_handler{
                    [this](vsomeip::service_t service_id,
                           vsomeip::instance_t instance_id,
                           const bool avail) {
                        // Need to let any registered clients of the service availability
                        std::vector<AvailabilityHandler> to_inform;
                        const Service service{service_id, instance_id};
                        std::unique_lock<std::mutex> avail_lock(context_mutex_);
                        requested_services_[service] = avail;
                        auto&& service_entry{availability_handlers_.find(service)};
                        if (service_entry == availability_handlers_.end()) {
                            return;
                        }
                        to_inform = service_entry->second;
                        avail_lock.unlock();
                        for (auto&& client : to_inform) {
                            client(avail);
                        }
                    }};
                application_->register_availability_handler(service.service_id,
                                                            service.instance_id,
                                                            std::
                                                                move(availability_handler));
                application_->request_service(service.service_id,
                                              service.instance_id);
                requested_services_[service] = false;
            }
        }

        /**
         * Function to process a RPC response message
         * @param message Message (from vsomeip) with RPC response
         */
        void HandleResponse(const std::shared_ptr<vsomeip::message>& message) {
            const Service service{message->get_service(), message->get_instance()};
            const auto request_id{message->get_request()};
            std::unique_lock<std::mutex> response_lock{context_mutex_};
            // Find the pending request
            auto&& service_requests_entry{pending_requests_.find(service)};
            if (service_requests_entry == pending_requests_.end()) {
                return;
            }
            auto&& service_requests{service_requests_entry->second};
            auto&& request_entry{service_requests.find(request_id)};
            if (request_entry == service_requests.end()) {
                return;
            }

            // Pull out the callback to inform the client that a response was received
            auto handler{std::move(request_entry->second)};

            // Clean up the entry for this specific request
            service_requests.erase(request_entry);

            // Clean up the service entry to the pending map if there are no more requests
            // for that specific service
            if (service_requests.empty()) {
                pending_requests_.erase(service_requests_entry);
            }

            // Add the response message to the cached responses
            auto&& service_entry{responses_[service]};
            service_entry[request_id] = message;
            response_lock.unlock();
            // Inform the client that the response was received
            handler(request_id);
        }
    };
    std::map<uint16_t, std::shared_ptr<SomeIpContext>>& context_map() {
        static std::map<uint16_t,
                        std::shared_ptr<SomeIpContext>>
            map;
        return map;
    }

} // namespace

int someip_initialize(const char* app_name,
                      uint16_t* client_id) {
    if (client_id == nullptr) {
        return SOMEIP_RET_FAILURE;
    }
    auto application{
        ::vsomeip::runtime::get()->create_application(app_name)};
    if (!application || !application->init()) {
        application.reset();
        return SOMEIP_RET_FAILURE;
    }

    // Create the application context
    auto app_context{
        std::make_shared<SomeIpContext>(application)};
    app_context->Start();
    // Record the client_id
    *client_id = application->get_client();
    // Save off the context
    std::lock_guard<std::mutex> lock{
        someip_mutex()};
    auto&& contexts{
        context_map()};
    contexts.emplace(*client_id, app_context);
    return SOMEIP_RET_SUCCESS;
}

void someip_shutdown(const uint16_t client_id) {
    std::lock_guard<std::mutex> lock{
        someip_mutex()};
    auto&& contexts{
        context_map()};
    auto&& context{
        contexts.find(client_id)};
    if (context != contexts.end()) {
        context->second->Shutdown();
    }
    contexts.erase(context);
}

int someip_get_next_event(const uint16_t client_id,
                          some_ip_event* event_ptr) {
    // Validate the input parameter
    if (event_ptr == nullptr) {
        return SOMEIP_RET_FAILURE;
    }

    // Get the context
    std::lock_guard<std::mutex> lock{
        someip_mutex()};
    auto&& contexts{
        context_map()};
    auto&& context_entry{
        contexts.find(client_id)};
    if (context_entry == contexts.end()) {
        return SOMEIP_RET_FAILURE;
    }

    return context_entry->second->GetNextEvent(event_ptr);
}

int someip_subscribe_event(uint16_t client_id,
                           uint16_t service,
                           uint16_t instance,
                           uint16_t event,
                           uint16_t event_groups[],
                           size_t num_event_groups,
                           void* cookie,
                           void (*notify_cb)(void*)) {
    std::lock_guard<std::mutex> lock{
        someip_mutex()};
    auto&& contexts{
        context_map()};
    auto&& context_entry{
        contexts.find(client_id)};
    if (context_entry == contexts.end()) {
        return SOMEIP_RET_FAILURE;
    }

    if (event_groups == nullptr) {
        return SOMEIP_RET_FAILURE;
    }

    std::set<uint16_t> groups;
    for (auto i = 0; i < num_event_groups; ++i) {
        groups.insert(event_groups[i]);
    }

    auto notify_handler{[cookie, notify_cb]() {
        notify_cb(cookie);
    }};
    context_entry->second->SubscribeForEvent(
        {{service, instance},
         event},
        groups, std::move(notify_handler));
    return SOMEIP_RET_SUCCESS;
}

int someip_request_service(uint16_t client_id,
                           uint16_t service, uint16_t instance, void* cookie,
                           void (*avail_cb)(void*, uint16_t, uint16_t, int)) {
    std::lock_guard<std::mutex> request_serv_lock(someip_mutex());
    auto&& contexts{context_map()};
    auto&& context_entry{contexts.find(client_id)};
    if (context_entry == contexts.end()) {
        return SOMEIP_RET_FAILURE;
    }

    auto client_cb{[service, instance, cookie, avail_cb](const bool available) {
        if (avail_cb == nullptr) {
            return;
        }
        const auto avail_flag{available ? SOMEIP_SERVICE_AVAILABLE : SOMEIP_SERVICE_NOT_AVAILABLE};
        avail_cb(cookie, service, instance, avail_flag);
    }};
    context_entry->second->RequestService({service, instance},
                                          std::move(client_cb));
    return SOMEIP_RET_SUCCESS;
}

int someip_send_request(uint16_t client_id, struct some_ip_request* parameters,
                        void* cookie,
                        void (*response_cb)(void*, const struct some_ip_request_id*)) {
    // Check the parameters
    if (parameters == nullptr) {
        return SOMEIP_RET_FAILURE;
    }

    if (parameters->payload_len > 0 && parameters->payload == nullptr) {
        return SOMEIP_RET_FAILURE;
    }

    std::lock_guard<std::mutex>
        lock{
            someip_mutex()};
    auto&& contexts{
        context_map()};
    auto&& context_entry{
        contexts.find(client_id)};
    if (context_entry ==
        contexts.end()) {
        return SOMEIP_RET_FAILURE;
    }

    SomeIpContext::
        ResponseHandler
            response_handler;
    if (response_cb != nullptr) {
        response_handler =
            {[cookie, response_cb,
              request_id =
                  parameters->request_id](const uint32_t
                                              client_request) mutable {

                 request_id.
                 client_request_id =
                 client_request;
                 response_cb(cookie,
                             &request_id); }};
    }
    return context_entry->second->SendRequest(parameters,
                                              std::
                                                  move(response_handler));
}

int someip_get_response(uint16_t client_id,
                        struct
                        some_ip_response* response) {
    // Check the parameters
    if (response ==
        nullptr) {
        return SOMEIP_RET_FAILURE;
    }

    std::lock_guard<
        std::mutex>
        lock{
            someip_mutex()};
    auto&& contexts{
        context_map()};
    auto&& context_entry{
        contexts.find(client_id)};
    if (context_entry ==
        contexts.end()) {
        return SOMEIP_RET_FAILURE;
    }

    return context_entry->second->GetResponse(response);
}

int someip_offer_event(uint16_t client_id,
                       uint16_t service,
                       uint16_t instance,
                       uint16_t event,
                       uint16_t
                           event_groups[],
                       size_t
                           num_event_grps) {
    std::lock_guard<
        std::mutex>
        lock{
            someip_mutex()};
    auto&& contexts{
        context_map()};
    auto&& context_entry{
        contexts.find(client_id)};
    if (context_entry ==
        contexts.end()) {
        return SOMEIP_RET_FAILURE;
    }

    if (event_groups ==
        NULL) {
        return SOMEIP_RET_FAILURE;
    }

    std::set<uint16_t>
        groups;
    for (auto i = 0;
         i <
         num_event_grps;
         ++i) {
        groups.insert(event_groups
                          [i]);
    }

    context_entry->second->OfferEvent({{service,
                                        instance},
                                       event},
                                      groups);
    return SOMEIP_RET_SUCCESS;
}

int someip_offer_service(uint16_t client_id,
                         uint16_t service,
                         uint16_t instance) {
    std::lock_guard<
        std::mutex>
        lock{
            someip_mutex()};
    auto&& contexts{
        context_map()};
    auto&& context_entry{
        contexts.find(client_id)};
    if (context_entry ==
        contexts.end()) {
        return SOMEIP_RET_FAILURE;
    }

    context_entry->second->OfferService({service,
                                         instance});
    return SOMEIP_RET_SUCCESS;
}

int someip_send_event(uint16_t client_id,
                      uint16_t service,
                      uint16_t instance,
                      uint16_t event,
                      const void* payload_ptr,
                      uint32_t
                          payload_size) {
    std::lock_guard<
        std::mutex>
        lock{
            someip_mutex()};
    auto&& contexts{
        context_map()};
    auto&& context_entry{
        contexts.find(client_id)};
    if (context_entry ==
        contexts.end()) {
        return SOMEIP_RET_FAILURE;
    }

    std::shared_ptr<
        vsomeip::payload>
        payload;
    if (payload_ptr !=
            nullptr &&
        payload_size >
            0) {
        payload =
            vsomeip::runtime::
                get()
                    ->create_payload(static_cast<
                                         const uint8_t*>(payload_ptr),
                                     payload_size);
    }
    else {
        payload =
            vsomeip::runtime::
                get()
                    ->create_payload();
    }

    context_entry->second->SendNotification({{service,
                                              instance},
                                             event},
                                            payload);
    return SOMEIP_RET_SUCCESS;
}

int someip_register_request_handler(uint16_t client_id,
                                    uint16_t service,
                                    uint16_t instance,
                                    uint16_t method,
                                    void* cookie,
                                    void (*request_cb)(void*, struct
                                                       some_ip_request*)) {
    std::lock_guard<std::mutex>lock{someip_mutex()};
    auto&& contexts{context_map()};
    auto&& context_entry{contexts.find(client_id)};
    if (context_entry == contexts.end()) {
        return SOMEIP_RET_FAILURE;
    }

    if (request_cb == nullptr) {
        return SOMEIP_RET_FAILURE;
    }

    auto request_handler{[request_cb, service, instance, method, cookie]
    (const uint32_t request_id, uint8_t* payload_ptr, const uint32_t payload_size) {
        struct some_ip_request request {{service, instance, request_id},
        method, payload_size, payload_ptr};
        request_cb(cookie, &request); 
        }
    };
    context_entry->second->AddRequestHandler({{service,
                                               instance},
                                              method},
                                             std::
                                                 move(request_handler));
    return SOMEIP_RET_SUCCESS;
}

int someip_send_response(uint16_t client_id, uint32_t request_id,
                         void* payload, uint32_t payload_len) {
    std::lock_guard<std::mutex> lock{someip_mutex()};
    auto&& contexts{context_map()};
    auto&& context_entry{contexts.find(client_id)};
    if (context_entry == contexts.end()) {
        return SOMEIP_RET_FAILURE;
    }

    std::vector<uint8_t> payload_buffer;
    if (payload != nullptr && payload_len > 0) {
        payload_buffer = std::vector<
            uint8_t>{(uint8_t*)payload,
                     ((uint8_t*)payload) + payload_len};
    }

    context_entry->second->SendResponse(request_id,
                                        payload_buffer);
    return SOMEIP_RET_SUCCESS;
}
