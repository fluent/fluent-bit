#include "applet.hpp"

#include <stdexcept>
#include <string>

#include <vsomeip/enumeration_types.hpp>
#include <vsomeip/runtime.hpp>

applet::applet(std::string_view name)
    : application{vsomeip_v3::runtime::get()->create_application(std::string{name})}
{

}

applet::~applet()
{
    this->application->clear_all_handler();
    this->application->stop();
    this->async_start.wait();
}

void
applet::init() {

    std::weak_ptr<applet> its_me = shared_from_this();

    if(!this->application->init())
    {
        using namespace std::string_literals;
        throw std::runtime_error{__func__ + "(): vSomeIP application init failure"s};
    }

    this->async_start = std::async(
        std::launch::async,
        &vsomeip_v3::application::start,
        this->application
    );

    this->application->register_state_handler(
        [its_me](vsomeip_v3::state_type_e state) {
            auto me = its_me.lock();
            if (me) {
                switch(state)
                {
                case vsomeip_v3::state_type_e::ST_REGISTERED:
                    return me->on_state_registered();
                case vsomeip_v3::state_type_e::ST_DEREGISTERED:
                    return me->on_state_deregistered();
                }
            }
        }
    );
}

void applet::on_state_registered() {}
void applet::on_state_deregistered() {}
