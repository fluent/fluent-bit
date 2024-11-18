// Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <common/vsomeip_app_utilities.hpp>

namespace vsomeip_utilities {

std::shared_ptr<vsomeip_v3::message> create_standard_vsip_request(
    vsomeip::service_t _service, vsomeip::instance_t _instance, vsomeip_v3::method_t _method,
    vsomeip_v3::interface_version_t _interface, vsomeip_v3::message_type_e _message_type)
{
    auto its_runtime = vsomeip::runtime::get();
    auto its_payload = its_runtime->create_payload();
    auto its_message = its_runtime->create_request(false);
    its_message->set_service(_service);
    its_message->set_instance(_instance);
    its_message->set_method(_method);
    its_message->set_interface_version(_interface);
    its_message->set_message_type(_message_type);
    its_message->set_payload(its_payload);

    return its_message;
}

base_logger::base_logger(const char *dlt_application_id, const char *dlt_application_name)
        : _dlt_application_id(dlt_application_id),
          _dlt_application_name(dlt_application_name)
{
#ifdef USE_DLT
#ifndef ANDROID
        DLT_REGISTER_APP(_dlt_application_id, _dlt_application_name);
#endif
#endif
}

base_logger::~base_logger()
{
#ifdef USE_DLT
#ifndef ANDROID
    DLT_UNREGISTER_APP();
#endif
#endif
}

base_vsip_app::base_vsip_app(const char *app_name_, const char *app_id_) : base_logger( app_name_, app_id_)
{
    _app = vsomeip::runtime::get()->create_application(app_name_);
    _app->init();
    _run_thread = std::thread(std::bind(&base_vsip_app::run, this));
}

void base_vsip_app::run()
{
    _app->start();
}

base_vsip_app::~base_vsip_app()
{
    _app->stop();
    _run_thread.join();
}
}
