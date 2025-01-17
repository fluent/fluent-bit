// Copyright (C) 2014-2021 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_V3_TRACE_CONNECTOR_HPP_
#define VSOMEIP_V3_TRACE_CONNECTOR_HPP_

#ifdef USE_DLT
#ifndef ANDROID
#include <dlt/dlt.h>
#endif
#endif

#include <mutex>
#include <vector>
#include <map>

#include <boost/shared_ptr.hpp>

#include <vsomeip/primitive_types.hpp>
#include <vsomeip/export.hpp>
#include <vsomeip/trace.hpp>

#include "enumeration_types.hpp"
#include "header.hpp"
#include "../../endpoints/include/buffer.hpp"

namespace vsomeip_v3 {

namespace cfg {
    struct trace;
}

namespace trace {

class channel_impl;

class connector_impl : public connector {
public:
    VSOMEIP_EXPORT static std::shared_ptr<connector_impl> get();

    VSOMEIP_EXPORT connector_impl();
    VSOMEIP_EXPORT virtual ~connector_impl();

    VSOMEIP_EXPORT void configure(const std::shared_ptr<cfg::trace> &_configuration);
    VSOMEIP_EXPORT void reset();

    VSOMEIP_EXPORT void set_enabled(const bool _enabled);
    VSOMEIP_EXPORT bool is_enabled() const;

    VSOMEIP_EXPORT void set_sd_enabled(const bool _sd_enabled);
    VSOMEIP_EXPORT bool is_sd_enabled() const;

    VSOMEIP_EXPORT bool is_sd_message(const byte_t *_data, uint16_t _data_size) const;

    VSOMEIP_EXPORT std::shared_ptr<channel> add_channel(const std::string &_id,
            const std::string &_description);
    VSOMEIP_EXPORT bool remove_channel(const std::string &_id);
    VSOMEIP_EXPORT std::shared_ptr<channel> get_channel(const std::string &_id) const;

    VSOMEIP_EXPORT void trace(const byte_t *_header, uint16_t _header_size,
            const byte_t *_data, uint32_t _data_size);

private:
    bool is_enabled_;
    bool is_sd_enabled_;

    std::map<std::string, std::shared_ptr<channel_impl>> channels_;
    mutable std::mutex channels_mutex_;

    std::shared_ptr<channel_impl> get_channel_impl(const std::string &_id) const;

    std::mutex configure_mutex_;

#ifdef USE_DLT
#ifndef ANDROID
    std::map<std::string, std::shared_ptr<DltContext>> contexts_;
    mutable std::mutex contexts_mutex_;
#endif
#endif

};

} // namespace trace
} // namespace vsomeip_v3

#endif // VSOMEIP_TC_TRACE_CONNECTOR_HPP
