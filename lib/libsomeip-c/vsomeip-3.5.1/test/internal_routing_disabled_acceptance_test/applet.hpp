#pragma once

#include <future>
#include <memory>
#include <string_view>

#include <vsomeip/application.hpp>

struct applet : public std::enable_shared_from_this<applet>
{
protected:
    std::shared_ptr<vsomeip_v3::application> application;

    applet(std::string_view name);
    virtual ~applet();

    void init();

private:
    std::future<void> async_start;

    virtual void on_state_registered();
    virtual void on_state_deregistered();
};
