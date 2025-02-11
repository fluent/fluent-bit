// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <vsomeip/constants.hpp>
#include <vsomeip/internal/logger.hpp>
#include <vsomeip/runtime.hpp>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>

#include "../include/channel_impl.hpp"
#include "../include/connector_impl.hpp"
#include "../include/defines.hpp"
#include "../../configuration/include/trace.hpp"
#include "../../utility/include/bithelper.hpp"

#ifdef ANDROID
#include <utils/Log.h>

#ifdef ALOGI
#undef ALOGI
#endif

#define ALOGI(LOG_TAG, ...) ((void)ALOG(LOG_INFO, LOG_TAG, __VA_ARGS__))
#ifndef LOGI
#define LOGI ALOGI
#endif

#endif

namespace vsomeip_v3 {
namespace trace {

const char *VSOMEIP_TC_DEFAULT_CHANNEL_ID = "TC";

static std::mutex connector_impl_get;

std::shared_ptr<connector_impl> connector_impl::get() {
    std::scoped_lock lk {connector_impl_get};
    static std::shared_ptr<connector_impl> instance = std::make_shared<connector_impl>();
    return instance;
}

connector_impl::connector_impl() :
    is_enabled_(false),
    is_sd_enabled_(false) {

    channels_[VSOMEIP_TC_DEFAULT_CHANNEL_ID]
        = std::make_shared<channel_impl>(VSOMEIP_TC_DEFAULT_CHANNEL_ID,
                                         VSOMEIP_TC_DEFAULT_CHANNEL_NAME);
#ifdef USE_DLT
#ifndef ANDROID
    std::shared_ptr<DltContext> its_default_context
        = std::make_shared<DltContext>();

    contexts_[VSOMEIP_TC_DEFAULT_CHANNEL_ID] = its_default_context;
    DLT_REGISTER_CONTEXT_LL_TS(*(its_default_context.get()),
            VSOMEIP_TC_DEFAULT_CHANNEL_ID, VSOMEIP_TC_DEFAULT_CHANNEL_NAME,
            DLT_LOG_INFO, DLT_TRACE_STATUS_ON);
#endif
#endif
}

connector_impl::~connector_impl() {
    reset();
}

void connector_impl::configure(const std::shared_ptr<cfg::trace> &_configuration) {
    std::scoped_lock lk {configure_mutex_};
    if (_configuration) {
        is_enabled_ = _configuration->is_enabled_;
        is_sd_enabled_ = _configuration->is_sd_enabled_;
    }

    if (is_enabled_) { // No need to create filters if tracing is disabled!
        for (auto &its_channel : _configuration->channels_) {
            if (!add_channel(its_channel->id_, its_channel->name_)) {
                VSOMEIP_ERROR << "Channel " << its_channel->id_
                                << " has multiple definitions.";
            }
        }

        for (auto &its_filter : _configuration->filters_) {
            for (auto &its_channel : its_filter->channels_) {
                auto its_channel_ptr = get_channel_impl(its_channel);
                if (its_channel_ptr) {
                    if (its_filter->is_range_) {
                        its_channel_ptr->add_filter(its_filter->matches_[0],
                                its_filter->matches_[1], its_filter->ftype_);
                    } else {
                        its_channel_ptr->add_filter(its_filter->matches_,
                                its_filter->ftype_);
                    }
                }
            }
        }
    }

    VSOMEIP_INFO << "vsomeip tracing "
        << (is_enabled_ ? "enabled." : "not enabled.")
        << " vsomeip service discovery tracing "
        << (is_sd_enabled_ ? "enabled." : "not enabled.");
}

void connector_impl::reset() {
    // reset to default
    {
        std::scoped_lock its_lock_channels(channels_mutex_);
        channels_.clear();
    }
#ifdef USE_DLT
#ifndef ANDROID
    {
        std::scoped_lock its_contexts_lock(contexts_mutex_);
        contexts_.clear();
    }
#endif
#endif
}

void connector_impl::set_enabled(const bool _enabled) {
    is_enabled_ = _enabled;
}

bool connector_impl::is_enabled() const {
    return is_enabled_;
}

void connector_impl::set_sd_enabled(const bool _sd_enabled) {
    is_sd_enabled_ = _sd_enabled;
}

bool connector_impl::is_sd_enabled() const {
    return is_sd_enabled_;
}

bool connector_impl::is_sd_message(const byte_t *_data, uint16_t _data_size) const {
    if (VSOMEIP_METHOD_POS_MAX < _data_size) {
        return (_data[VSOMEIP_SERVICE_POS_MIN] == 0xFF && _data[VSOMEIP_SERVICE_POS_MAX] == 0xFF &&
                _data[VSOMEIP_METHOD_POS_MIN] == 0x81 && _data[VSOMEIP_METHOD_POS_MAX] == 0x00);
    }
    return false;
}

std::shared_ptr<channel> connector_impl::add_channel(const trace_channel_t& _id,
                                                     const std::string& _name) {

    std::shared_ptr<channel_impl> its_channel;
    {
        std::scoped_lock its_channels_lock(channels_mutex_);

        // check whether we already know the requested channel
        if (channels_.find(_id) != channels_.end())
            return nullptr;

        // create new channel
        its_channel = std::make_shared<channel_impl>(_id, _name);

        // add channel
        channels_[_id] = its_channel;
    }

    // register context
#ifdef USE_DLT
#ifndef ANDROID
    {
        std::scoped_lock its_contexts_lock(contexts_mutex_);
        std::shared_ptr<DltContext> its_context = std::make_shared<DltContext>();
        contexts_[_id] = its_context;
        DLT_REGISTER_CONTEXT_LL_TS(*(its_context.get()), _id.c_str(), _name.c_str(), DLT_LOG_INFO,
                                   DLT_TRACE_STATUS_ON);
    }
#endif
#endif

    return its_channel;
}

bool connector_impl::remove_channel(const trace_channel_t &_id) {

    if (_id == VSOMEIP_TC_DEFAULT_CHANNEL_ID) {
        // the default channel can not be removed
        return false;
    }

    bool has_removed {false};
    {
        std::scoped_lock its_channels_lock(channels_mutex_);
        has_removed = (channels_.erase(_id) == 1);
    }

    if (has_removed) {
        // unregister context
#ifdef USE_DLT
#ifndef ANDROID
        {
            std::scoped_lock its_contexts_lock(contexts_mutex_);
            auto its_context = contexts_.find(_id);
            if (its_context != contexts_.end()) {
                DLT_UNREGISTER_CONTEXT(*(its_context->second.get()));
            }
        }
#endif
#endif
    }

    return true;
}

std::shared_ptr<channel> connector_impl::get_channel(const std::string &_id) const {
    std::scoped_lock its_channels_lock(channels_mutex_);
    auto its_channel = channels_.find(_id);
    return (its_channel != channels_.end() ? its_channel->second : nullptr);
}

std::shared_ptr<channel_impl> connector_impl::get_channel_impl(const std::string &_id) const {
    std::scoped_lock its_channels_lock(channels_mutex_);
    auto its_channel = channels_.find(_id);
    return (its_channel != channels_.end() ? its_channel->second : nullptr);
}

void connector_impl::trace(const byte_t *_header, uint16_t _header_size,
        const byte_t *_data, uint32_t _data_size) {

#if USE_DLT
    if (!is_enabled_)
        return;

    if (_data_size == 0)
        return; // no data

    // Clip
    uint16_t its_data_size = uint16_t(_data_size > USHRT_MAX ? USHRT_MAX : _data_size);

    if (is_sd_message(_data, its_data_size) && !is_sd_enabled_)
        return; // tracing of service discovery messages is disabled!

    service_t its_service = bithelper::read_uint16_be(&_data[VSOMEIP_SERVICE_POS_MIN]);

    // Instance is not part of the SOME/IP header, read it from the trace
    // header
    instance_t its_instance = bithelper::read_uint16_be(&_header[VSOMEIP_TC_INSTANCE_POS_MIN]);
    method_t its_method     = bithelper::read_uint16_be(&_data[VSOMEIP_METHOD_POS_MIN]);

// Forward to channel if the filter set of the channel allows
#ifndef ANDROID
    std::scoped_lock its_lock(channels_mutex_, contexts_mutex_);
#else
    std::scoped_lock its_lock(channels_mutex_);
#endif
    for (auto its_channel : channels_) {
        auto ftype = its_channel.second->matches(its_service, its_instance, its_method);
        if (ftype.first) {
            #ifndef ANDROID
                auto its_context = contexts_.find(its_channel.second->get_id());
                if (its_context != contexts_.end()) {
                    try {
                        if (ftype.second) {
                            //Positive Filter
                            DLT_TRACE_NETWORK_SEGMENTED(*(its_context->second.get()),
                                DLT_NW_TRACE_IPC,
                                _header_size, static_cast<void *>(const_cast<byte_t *>(_header)),
                                its_data_size, static_cast<void *>(const_cast<byte_t *>(_data)));
                        } else {
                            //Header-Only Filter
                            DLT_TRACE_NETWORK_TRUNCATED(*(its_context->second.get()),
                                DLT_NW_TRACE_IPC,
                                _header_size, static_cast<void *>(const_cast<byte_t *>(_header)),
                                VSOMEIP_FULL_HEADER_SIZE,
                                static_cast<void *>(const_cast<byte_t *>(_data)));
                        }
                    } catch (const std::exception& e) {
                        VSOMEIP_INFO << "connector_impl::trace: "
                            << "Exception caught when trying to log a trace with DLT. "
                            << e.what();
                    }
                } else {
                    // This should never happen!
                    VSOMEIP_ERROR << "tracing: found channel without DLT context!";
                }
            #else
                std::stringstream ss;
                ss << "TC:";
                for(int i = 0; i < _header_size; i++) {
                    ss << ' ' << std::setfill('0') << std::setw(2) << std::hex << int(_header[i]);
                }
                if (ftype.second)
                    its_data_size = VSOMEIP_FULL_HEADER_SIZE;
                for(int i = 0; i < its_data_size; i++) {
                    ss << ' ' << std::setfill('0') << std::setw(2) << std::hex << int(_data[i]);
                }
                std::string app = runtime::get_property("LogApplication");

                ALOGI(app.c_str(), ss.str().c_str());
            #endif
        }
    }
#else
    (void)_header;
    (void)_header_size;
    (void)_data;
    (void)_data_size;
#endif
}

} // namespace trace
} // namespace vsomeip_v3
