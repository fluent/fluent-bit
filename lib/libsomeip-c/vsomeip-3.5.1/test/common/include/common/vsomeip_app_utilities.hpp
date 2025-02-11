// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_BASE_APP
#define VSOMEIP_BASE_APP
#include <vsomeip/vsomeip.hpp>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <vsomeip/vsomeip.hpp>
#include <vsomeip/internal/logger.hpp>

#ifdef USE_DLT
#ifndef ANDROID
#include <dlt/dlt.h>
#endif
#endif

namespace vsomeip_utilities {

std::shared_ptr<vsomeip_v3::message> create_standard_vsip_request(
        vsomeip::service_t _service, vsomeip::instance_t _instance, vsomeip_v3::method_t _method,
        vsomeip_v3::interface_version_t _interface, vsomeip_v3::message_type_e _message_type);

class base_logger
{
public:
    const char *_dlt_application_id = nullptr;
    const char *_dlt_application_name = nullptr;

    base_logger(const char *dlt_application_id, const char *dlt_application_name);

    ~base_logger();
};

class base_vsip_app: public base_logger
{
protected:
    std::shared_ptr<vsomeip::application> _app;
    std::thread _run_thread;

    void run();

public:
    base_vsip_app(const char *app_name_, const char *app_id_);
    ~base_vsip_app();
};
}
#endif // VSOMEIP_BASE_APP
