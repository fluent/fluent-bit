#include "client.hpp"

#include <chrono>
#include <iostream>
#include <thread>

#include <vsomeip/constants.hpp>
#include <vsomeip/enumeration_types.hpp>
#include <vsomeip/message.hpp>
#include <vsomeip/payload.hpp>
#include <vsomeip/primitive_types.hpp>
#include <vsomeip/runtime.hpp>
#include <vsomeip/internal/logger.hpp>

#include "config.hpp"

client::client() : applet{"client"}, counter_event_received{}, counter_method_request{}, counter_method_response{}
{
}

void
client::init() {
    applet::init();

    std::weak_ptr<client> its_me
        = std::dynamic_pointer_cast<client>(shared_from_this());

    this->application->register_message_handler(
        config::SERVICE_ID,
        config::INSTANCE_ID,
        vsomeip_v3::ANY_METHOD,
        [its_me](const std::shared_ptr<vsomeip_v3::message>& message){
            auto me = its_me.lock();
            if (me) {
                std::shared_ptr runtime = vsomeip_v3::runtime::get();
                std::shared_ptr payload = message->get_payload();

                switch(message->get_message_type())
                {
                case vsomeip_v3::message_type_e::MT_RESPONSE:
                    VSOMEIP_INFO << "received:\n"
                                 << "\tservice:  " << std::hex << message->get_service() << '\n'
                                 << "\tinstance: " << std::hex << message->get_instance() << '\n'
                                 << "\tmethod:   " << std::hex << message->get_method() << '\n'
                                 << "\tpayload:  " << payload->get_data();
                    me->counter_method_response++;
                    break;

                case vsomeip_v3::message_type_e::MT_NOTIFICATION:
                    VSOMEIP_INFO << "GOT NOTIFICATION";
                    me->counter_event_received++;
                    [[fallthrough]];

                default:
                    VSOMEIP_ERROR << "unhandled message type: "
                                  << unsigned(message->get_message_type());
                }
            }
        }
    );

    this->application->register_availability_handler(
        config::SERVICE_ID,
        config::INSTANCE_ID,
        [its_me](vsomeip_v3::service_t service, vsomeip_v3::instance_t instance, bool available){
            auto me = its_me.lock();
            if (me) {
                VSOMEIP_INFO << __func__ << '('<< std::hex << service << ", " << std::hex
                             << instance << ", " << std::boolalpha << available << ")";

                if(service != config::SERVICE_ID)
                    return;
                if(instance != config::INSTANCE_ID)
                    return;
                if(!available)
                    return;

                std::shared_ptr runtime = vsomeip_v3::runtime::get();

                std::shared_ptr payload = runtime->create_payload();
                constexpr vsomeip_v3::byte_t str[]{"hello world"};
                payload->set_data(str, sizeof(str));

                std::shared_ptr request = runtime->create_request();
                request->set_service(config::SERVICE_ID);
                request->set_instance(config::INSTANCE_ID);
                request->set_method(config::METHOD_ID);
                request->set_payload(payload);

                for(int i = 0; i < 10; i++)
                {
                    VSOMEIP_INFO << "sending: " << str;
                    me->application->send(request);
                    me->counter_method_request++;

                    using namespace std::chrono_literals;
                    std::this_thread::sleep_for(1s);
                }
            }
        }
    );

    this->application->request_event(
        config::SERVICE_ID,
        config::INSTANCE_ID,
        config::EVENT_ID,
        {config::EVENTGROUP_ID},
        vsomeip_v3::event_type_e::ET_FIELD,
        vsomeip_v3::reliability_type_e::RT_UNRELIABLE
    );

    this->application->subscribe(
        config::SERVICE_ID,
        config::INSTANCE_ID,
        config::EVENTGROUP_ID
    );
}

client::~client()
{
    this->application->unsubscribe(
        config::SERVICE_ID,
        config::INSTANCE_ID,
        config::EVENTGROUP_ID
    );

    this->application->release_event(
        config::SERVICE_ID,
        config::INSTANCE_ID,
        config::EVENT_ID
    );

    this->application->release_service(
        config::SERVICE_ID,
        config::INSTANCE_ID
    );

    this->application->unregister_availability_handler(
        config::SERVICE_ID,
        config::INSTANCE_ID
    );

    this->application->unregister_message_handler(
        config::SERVICE_ID,
        config::INSTANCE_ID,
        vsomeip_v3::ANY_METHOD
    );
}

std::size_t client::get_event_count() noexcept
{
    return this->counter_event_received;
}

std::size_t client::get_method_request_count() noexcept
{
    return this->counter_method_request;
}

std::size_t client::get_method_response_count() noexcept
{
    return this->counter_method_response;
}

void client::on_state_registered()
{
    this->application->request_service(
        config::SERVICE_ID,
        config::INSTANCE_ID
    );
}

void client::on_state_deregistered()
{
    VSOMEIP_WARNING << "Client is deregistered!!! Probably could not be registered!!!";
}
