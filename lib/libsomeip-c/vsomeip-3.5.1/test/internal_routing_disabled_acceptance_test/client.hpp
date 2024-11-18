#pragma once

#include <atomic>
#include <cstddef>
#include <memory>

#include "applet.hpp"

struct client final : applet
{
    client();
    ~client();

    void init();

    std::size_t get_event_count() noexcept;
    std::size_t get_method_request_count() noexcept;
    std::size_t get_method_response_count() noexcept;

private:
    void on_state_registered() override;
    void on_state_deregistered() override;

    std::atomic_size_t counter_event_received;
    std::atomic_size_t counter_method_request;
    std::atomic_size_t counter_method_response;
};
