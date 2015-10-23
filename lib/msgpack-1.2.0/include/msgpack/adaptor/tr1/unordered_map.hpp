//
// MessagePack for C++ static resolution routine
//
// Copyright (C) 2008-2015 FURUHASHI Sadayuki
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
#ifndef MSGPACK_TYPE_TR1_UNORDERED_MAP_HPP
#define MSGPACK_TYPE_TR1_UNORDERED_MAP_HPP

#include "msgpack/versioning.hpp"
#include "msgpack/adaptor/adaptor_base.hpp"
#include "msgpack/adaptor/check_container_size.hpp"

#if defined(_LIBCPP_VERSION) || (_MSC_VER >= 1700)

#define MSGPACK_HAS_STD_UNORDERED_MAP
#include <unordered_map>
#define MSGPACK_STD_TR1 std

#else   // defined(_LIBCPP_VERSION) || (_MSC_VER >= 1700)

#if __GNUC__ >= 4

#define MSGPACK_HAS_STD_TR1_UNORDERED_MAP

#include <tr1/unordered_map>
#define MSGPACK_STD_TR1 std::tr1

#endif // __GNUC__ >= 4

#endif  // defined(_LIBCPP_VERSION) || (_MSC_VER >= 1700)

#if defined(MSGPACK_STD_TR1)

namespace msgpack {

/// @cond
MSGPACK_API_VERSION_NAMESPACE(v1) {
/// @endcond

namespace adaptor {

template <typename K, typename V, typename Hash, typename Pred, typename Alloc>
struct convert<MSGPACK_STD_TR1::unordered_map<K, V, Hash, Pred, Alloc> > {
    msgpack::object const& operator()(msgpack::object const& o, MSGPACK_STD_TR1::unordered_map<K, V, Hash, Pred, Alloc>& v) const {
        if(o.type != msgpack::type::MAP) { throw msgpack::type_error(); }
        msgpack::object_kv* p(o.via.map.ptr);
        msgpack::object_kv* const pend(o.via.map.ptr + o.via.map.size);
        MSGPACK_STD_TR1::unordered_map<K, V, Hash, Pred, Alloc> tmp;
        for(; p != pend; ++p) {
            K key;
            p->key.convert(key);
            p->val.convert(tmp[key]);
        }
        tmp.swap(v);
        return o;
    }
};

template <typename K, typename V, typename Hash, typename Pred, typename Alloc>
struct pack<MSGPACK_STD_TR1::unordered_map<K, V, Hash, Pred, Alloc> > {
    template <typename Stream>
    msgpack::packer<Stream>& operator()(msgpack::packer<Stream>& o, const MSGPACK_STD_TR1::unordered_map<K, V, Hash, Pred, Alloc>& v) const {
        uint32_t size = checked_get_container_size(v.size());
        o.pack_map(size);
        for(typename MSGPACK_STD_TR1::unordered_map<K, V, Hash, Pred, Alloc>::const_iterator it(v.begin()), it_end(v.end());
            it != it_end; ++it) {
            o.pack(it->first);
            o.pack(it->second);
        }
        return o;
    }
};

template <typename K, typename V, typename Hash, typename Pred, typename Alloc>
struct object_with_zone<MSGPACK_STD_TR1::unordered_map<K, V, Hash, Pred, Alloc> > {
    void operator()(msgpack::object::with_zone& o, const MSGPACK_STD_TR1::unordered_map<K, V, Hash, Pred, Alloc>& v) const {
        o.type = msgpack::type::MAP;
        if(v.empty()) {
            o.via.map.ptr  = nullptr;
            o.via.map.size = 0;
        } else {
            uint32_t size = checked_get_container_size(v.size());
            msgpack::object_kv* p = static_cast<msgpack::object_kv*>(o.zone.allocate_align(sizeof(msgpack::object_kv)*size));
            msgpack::object_kv* const pend = p + size;
            o.via.map.ptr  = p;
            o.via.map.size = size;
            typename MSGPACK_STD_TR1::unordered_map<K, V, Hash, Pred, Alloc>::const_iterator it(v.begin());
            do {
                p->key = msgpack::object(it->first, o.zone);
                p->val = msgpack::object(it->second, o.zone);
                ++p;
                ++it;
            } while(p < pend);
        }
    }
};

template <typename K, typename V, typename Hash, typename Pred, typename Alloc>
struct convert<MSGPACK_STD_TR1::unordered_multimap<K, V, Hash, Pred, Alloc> > {
    msgpack::object const& operator()(msgpack::object const& o, MSGPACK_STD_TR1::unordered_multimap<K, V, Hash, Pred, Alloc>& v) const {
        if(o.type != msgpack::type::MAP) { throw msgpack::type_error(); }
        msgpack::object_kv* p(o.via.map.ptr);
        msgpack::object_kv* const pend(o.via.map.ptr + o.via.map.size);
        MSGPACK_STD_TR1::unordered_multimap<K, V, Hash, Pred, Alloc> tmp;
        for(; p != pend; ++p) {
            std::pair<K, V> value;
            p->key.convert(value.first);
            p->val.convert(value.second);
            tmp.insert(value);
        }
        tmp.swap(v);
        return o;
    }
};

template <typename K, typename V, typename Hash, typename Pred, typename Alloc>
struct pack<MSGPACK_STD_TR1::unordered_multimap<K, V, Hash, Pred, Alloc> > {
    template <typename Stream>
    msgpack::packer<Stream>& operator()(msgpack::packer<Stream>& o, const MSGPACK_STD_TR1::unordered_multimap<K, V, Hash, Pred, Alloc>& v) const {
        uint32_t size = checked_get_container_size(v.size());
        o.pack_map(size);
        for(typename MSGPACK_STD_TR1::unordered_multimap<K, V, Hash, Pred, Alloc>::const_iterator it(v.begin()), it_end(v.end());
            it != it_end; ++it) {
            o.pack(it->first);
            o.pack(it->second);
        }
        return o;
    }
};

template <typename K, typename V, typename Hash, typename Pred, typename Alloc>
struct object_with_zone<MSGPACK_STD_TR1::unordered_multimap<K, V, Hash, Pred, Alloc> > {
    void operator()(msgpack::object::with_zone& o, const MSGPACK_STD_TR1::unordered_multimap<K, V, Hash, Pred, Alloc>& v) const {
        o.type = msgpack::type::MAP;
        if(v.empty()) {
            o.via.map.ptr  = nullptr;
            o.via.map.size = 0;
        } else {
            uint32_t size = checked_get_container_size(v.size());
            msgpack::object_kv* p = static_cast<msgpack::object_kv*>(o.zone.allocate_align(sizeof(msgpack::object_kv)*size));
            msgpack::object_kv* const pend = p + size;
            o.via.map.ptr  = p;
            o.via.map.size = size;
            typename MSGPACK_STD_TR1::unordered_multimap<K, V, Hash, Pred, Alloc>::const_iterator it(v.begin());
            do {
                p->key = msgpack::object(it->first, o.zone);
                p->val = msgpack::object(it->second, o.zone);
                ++p;
                ++it;
            } while(p < pend);
        }
    }
};

} // namespace adaptor

/// @cond
} // MSGPACK_API_VERSION_NAMESPACE(v1)
/// @endcond

} // namespace msgpack

#undef MSGPACK_STD_TR1

#endif // MSGPACK_STD_TR1

#endif // MSGPACK_TYPE_TR1_UNORDERED_MAP_HPP
