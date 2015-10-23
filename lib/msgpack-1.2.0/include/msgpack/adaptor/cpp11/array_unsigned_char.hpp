//
// MessagePack for C++ static resolution routine
//
// Copyright (C) 2014-2015 KONDO Takatoshi
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
//
#ifndef MSGPACK_TYPE_ARRAY_UNSIGNED_CHAR_HPP
#define MSGPACK_TYPE_ARRAY_UNSIGNED_CHAR_HPP

#include "msgpack/versioning.hpp"
#include "msgpack/adaptor/adaptor_base.hpp"
#include "msgpack/adaptor/check_container_size.hpp"

#include <array>

namespace msgpack {

/// @cond
MSGPACK_API_VERSION_NAMESPACE(v1) {
/// @endcond

namespace adaptor {

template <std::size_t N>
struct convert<std::array<unsigned char, N>> {
    msgpack::object const& operator()(msgpack::object const& o, std::array<unsigned char, N>& v) const {
        switch (o.type) {
        case msgpack::type::BIN:
            if(o.via.bin.size != N) { throw msgpack::type_error(); }
            std::memcpy(v.data(), o.via.bin.ptr, o.via.bin.size);
            break;
        case msgpack::type::STR:
            if(o.via.str.size != N) { throw msgpack::type_error(); }
            std::memcpy(v.data(), o.via.str.ptr, N);
            break;
        default:
            throw msgpack::type_error();
            break;
        }
        return o;
    }
};

template <std::size_t N>
struct pack<std::array<unsigned char, N>> {
    template <typename Stream>
    msgpack::packer<Stream>& operator()(msgpack::packer<Stream>& o, const std::array<unsigned char, N>& v) const {
        uint32_t size = checked_get_container_size(v.size());
        o.pack_bin(size);
        o.pack_bin_body(reinterpret_cast<char const*>(v.data()), size);

        return o;
    }
};

template <std::size_t N>
struct object<std::array<unsigned char, N>> {
    void operator()(msgpack::object& o, const std::array<unsigned char, N>& v) const {
        uint32_t size = checked_get_container_size(v.size());
        o.type = msgpack::type::BIN;
        o.via.bin.ptr = reinterpret_cast<char const*>(v.data());
        o.via.bin.size = size;
    }
};

template <std::size_t N>
struct object_with_zone<std::array<unsigned char, N>> {
    void operator()(msgpack::object::with_zone& o, const std::array<unsigned char, N>& v) const {
        uint32_t size = checked_get_container_size(v.size());
        o.type = msgpack::type::BIN;
        char* ptr = static_cast<char*>(o.zone.allocate_align(size));
        o.via.bin.ptr = ptr;
        o.via.bin.size = size;
        std::memcpy(ptr, v.data(), size);
    }
};

} // namespace adaptor

/// @cond
} // MSGPACK_API_VERSION_NAMESPACE(v1)
/// @endcond

} // namespace msgpack

#endif // MSGPACK_TYPE_ARRAY_UNSIGNED_CHAR_HPP
