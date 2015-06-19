//
// MessagePack for C++ static resolution routine
//
// Copyright (C) 2015 KONDO Takatoshi
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
#ifndef MSGPACK_ADAPTOR_BASE_HPP
#define MSGPACK_ADAPTOR_BASE_HPP

#include "msgpack/object_fwd.hpp"

namespace msgpack {

/// @cond
MSGPACK_API_VERSION_NAMESPACE(v1) {
/// @endcond

template <typename Stream>
class packer;

namespace adaptor {

// Adaptor functors

template <typename T>
struct convert {
    msgpack::object const& operator()(msgpack::object const& o, T& v) const;
};

template <typename T>
struct pack {
    template <typename Stream>
    msgpack::packer<Stream>& operator()(msgpack::packer<Stream>& o, T const& v) const;
};

template <typename T>
struct object {
    void operator()(msgpack::object& o, T const& v) const;
};

template <typename T>
struct object_with_zone {
    void operator()(msgpack::object::with_zone& o, T const& v) const;
};

} // namespace adaptor

// operators

template <typename T>
inline
msgpack::object const& operator>> (msgpack::object const& o, T& v) {
    return adaptor::convert<T>()(o, v);
}

template <typename Stream, typename T>
inline
msgpack::packer<Stream>& operator<< (msgpack::packer<Stream>& o, T const& v) {
    return adaptor::pack<T>()(o, v);
}

template <typename T>
inline
void operator<< (msgpack::object& o, T const& v) {
    adaptor::object<T>()(o, v);
}

template <typename T>
inline
void operator<< (msgpack::object::with_zone& o, T const& v) {
    adaptor::object_with_zone<T>()(o, v);
}

/// @cond
} // MSGPACK_API_VERSION_NAMESPACE(v1)
/// @endcond

} // namespace msgpack


#endif // MSGPACK_ADAPTOR_BASE_HPP
