#include "server.hpp"

#include <chrono>
#include <iostream>
#include <thread>

#include <vsomeip/enumeration_types.hpp>
#include <vsomeip/message.hpp>
#include <vsomeip/payload.hpp>
#include <vsomeip/runtime.hpp>
#include <vsomeip/internal/logger.hpp>

#include "config.hpp"

server::server() : applet{"server"}, counter_event_sent{}, counter_method_request{}, counter_method_response{}
{
}

void
server::init() {
    applet::init();

    std::weak_ptr<server> its_me
        = std::dynamic_pointer_cast<server>(shared_from_this());

    this->application->register_message_handler(
        config::SERVICE_ID,
        config::INSTANCE_ID,
        config::METHOD_ID,
        [its_me](const std::shared_ptr<vsomeip_v3::message>& message){
            auto me = its_me.lock();
            if (me) {
                std::shared_ptr runtime = vsomeip_v3::runtime::get();
                std::shared_ptr payload = message->get_payload();

                switch(message->get_message_type())
                {
                case vsomeip_v3::message_type_e::MT_REQUEST:
                    VSOMEIP_INFO << "GOT REQUEST";
                    me->counter_method_request++;
                    {
                        std::shared_ptr response = runtime->create_response(message);
                        response->set_payload(payload);

                        me->application->send(response);
                        me->counter_method_response++;

                        me->application->notify(
                            config::SERVICE_ID,
                            config::INSTANCE_ID,
                            config::EVENT_ID,
                            payload,
                            true
                        );
                        me->counter_event_sent++;
                    }
                    break;

                default:
                    VSOMEIP_ERROR << "unhandled message type: "
                                  << unsigned(message->get_message_type());
                }
            }
        }
    );

    this->application->offer_event(
        config::SERVICE_ID,
        config::INSTANCE_ID,
        config::EVENT_ID,
        {config::EVENTGROUP_ID},
        vsomeip_v3::event_type_e::ET_FIELD,
        {},
        false,
        true,
        nullptr,
        vsomeip_v3::reliability_type_e::RT_UNRELIABLE
    );

    std::thread{
        [its_me]{
            using namespace std::chrono_literals;
            std::this_thread::sleep_for(1s);

            auto me = its_me.lock();
            std::shared_ptr runtime = vsomeip_v3::runtime::get();
            std::shared_ptr payload = runtime->create_payload();
            for(int i = 0; i < 10; i++)
            {
                int j = i | 0x30;
                payload->set_data(reinterpret_cast<vsomeip_v3::byte_t*>(&j), sizeof(j));
                me->application->notify(
                    config::SERVICE_ID,
                    config::INSTANCE_ID,
                    config::EVENT_ID,
                    payload,
                    true
                );
                me->counter_event_sent++;

                std::this_thread::sleep_for(1s);
            }
        }
    }.detach();

}

server::~server()
{
    this->application->stop_offer_event(
        config::SERVICE_ID,
        config::INSTANCE_ID,
        config::EVENT_ID
    );

    this->application->stop_offer_service(
        config::SERVICE_ID,
        config::INSTANCE_ID
    );
}

std::size_t server::get_event_count() noexcept
{
    return this->counter_event_sent;
}

std::size_t server::get_method_request_count() noexcept
{
    return this->counter_method_request;
}

std::size_t server::get_method_response_count() noexcept
{
    return this->counter_method_response;
}

void server::on_state_registered()
{
    this->application->offer_service(
        config::SERVICE_ID,
        config::INSTANCE_ID
    );
}

void server::on_state_deregistered()
{
    VSOMEIP_WARNING << "Server is deregistered!!! Probably could not be registered!!!";
}
