// Copyright (C) 2019 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_COMPAT_RUNTIME_IMPL_HPP_
#define VSOMEIP_COMPAT_RUNTIME_IMPL_HPP_

#include <map>
#include <mutex>

#include <compat/vsomeip/runtime.hpp>

namespace vsomeip {

class runtime_impl
        : public runtime {
public:
    static std::string get_property(const std::string &_name);
    static void set_property(const std::string &_name, const std::string &_value);

    static std::shared_ptr<runtime> get();

    ~runtime_impl();

    std::shared_ptr<application> create_application(
            const std::string &_name = "");

    std::shared_ptr<message> create_message(bool _reliable = false) const;

    std::shared_ptr<message> create_request(bool _reliable = false) const;

    std::shared_ptr<message> create_response(
            const std::shared_ptr<message> &_request) const;

    std::shared_ptr<message> create_notification(
            bool _reliable = false) const;

    std::shared_ptr<payload> create_payload() const;
    std::shared_ptr<payload> create_payload(
            const byte_t *_data, uint32_t _size) const;
    virtual std::shared_ptr<payload> create_payload(
            const std::vector<byte_t> &_data) const;

    std::shared_ptr<application> get_application(
            const std::string &_name) const;
    void remove_application( const std::string &_name);

private:
    static std::shared_ptr<runtime> the_runtime_;

    std::map<std::string, std::weak_ptr<application> > applications_;
    mutable std::mutex applications_mutex_;
};

} // namespace vsomeip

#endif // VSOMEIP_COMPAT_RUNTIME_IMPL_HPP_
