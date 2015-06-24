//
// MessagePack for C++ static resolution routine
//
// Copyright (C) 2008-2014 FURUHASHI Sadayuki and KONDO Takatoshi
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
#ifndef MSGPACK_OBJECT_HPP
#define MSGPACK_OBJECT_HPP

#include "msgpack/versioning.hpp"
#include "msgpack/pack.hpp"
#include "msgpack/zone.hpp"
#include "msgpack/adaptor/adaptor_base.hpp"

#include <cstring>
#include <stdexcept>
#include <typeinfo>
#include <limits>
#include <ostream>
#include <typeinfo>

namespace msgpack {

/// @cond
MSGPACK_API_VERSION_NAMESPACE(v1) {
/// @endcond

struct object::implicit_type {
    implicit_type(object const& o) : obj(o) { }
    ~implicit_type() { }

    template <typename T>
    operator T() { return obj.as<T>(); }

private:
    msgpack::object const& obj;
};

namespace detail {
template <typename Stream, typename T>
struct packer_serializer {
    static msgpack::packer<Stream>& pack(msgpack::packer<Stream>& o, const T& v) {
        v.msgpack_pack(o);
        return o;
    }
};
} // namespace detail

// Adaptor functors' member functions definitions.
template <typename T>
inline
msgpack::object const&
msgpack::adaptor::convert<T>::operator()(msgpack::object const& o, T& v) const {
    v.msgpack_unpack(o.convert());
    return o;
}

template <typename T>
template <typename Stream>
inline
msgpack::packer<Stream>&
msgpack::adaptor::pack<T>::operator()(msgpack::packer<Stream>& o, T const& v) const {
    return detail::packer_serializer<Stream, T>::pack(o, v);
}

template <typename T>
inline
void
msgpack::adaptor::object_with_zone<T>::operator()(msgpack::object::with_zone& o, T const& v) const {
    v.msgpack_object(static_cast<msgpack::object*>(&o), o.zone);
}

// Adaptor functor specialization to object
namespace adaptor {

template <>
struct convert<msgpack::object> {
    msgpack::object const& operator()(msgpack::object const& o, msgpack::object& v) const {
        v = o;
        return o;
    }
};

template <>
struct pack<msgpack::object> {
    template <typename Stream>
    msgpack::packer<Stream>& operator()(msgpack::packer<Stream>& o, msgpack::object const& v) const {
        switch(v.type) {
        case msgpack::type::NIL:
            o.pack_nil();
            return o;

        case msgpack::type::BOOLEAN:
            if(v.via.boolean) {
                o.pack_true();
            } else {
                o.pack_false();
            }
            return o;

        case msgpack::type::POSITIVE_INTEGER:
            o.pack_uint64(v.via.u64);
            return o;

        case msgpack::type::NEGATIVE_INTEGER:
            o.pack_int64(v.via.i64);
            return o;

        case msgpack::type::FLOAT:
            o.pack_double(v.via.f64);
            return o;

        case msgpack::type::STR:
            o.pack_str(v.via.str.size);
            o.pack_str_body(v.via.str.ptr, v.via.str.size);
            return o;

        case msgpack::type::BIN:
            o.pack_bin(v.via.bin.size);
            o.pack_bin_body(v.via.bin.ptr, v.via.bin.size);
            return o;

        case msgpack::type::EXT:
            o.pack_ext(v.via.ext.size, v.via.ext.type());
            o.pack_ext_body(v.via.ext.data(), v.via.ext.size);
            return o;

        case msgpack::type::ARRAY:
            o.pack_array(v.via.array.size);
            for(msgpack::object* p(v.via.array.ptr),
                    * const pend(v.via.array.ptr + v.via.array.size);
                p < pend; ++p) {
                msgpack::operator<<(o, *p);
            }
            return o;

        case msgpack::type::MAP:
            o.pack_map(v.via.map.size);
            for(msgpack::object_kv* p(v.via.map.ptr),
                    * const pend(v.via.map.ptr + v.via.map.size);
                p < pend; ++p) {
                msgpack::operator<<(o, p->key);
                msgpack::operator<<(o, p->val);
            }
            return o;

        default:
            throw msgpack::type_error();
        }
    }
};

template <>
struct object_with_zone<msgpack::object> {
    void operator()(msgpack::object::with_zone& o, msgpack::object const& v) const {
        o.type = v.type;

        switch(v.type) {
        case msgpack::type::NIL:
        case msgpack::type::BOOLEAN:
        case msgpack::type::POSITIVE_INTEGER:
        case msgpack::type::NEGATIVE_INTEGER:
        case msgpack::type::FLOAT:
            std::memcpy(&o.via, &v.via, sizeof(v.via));
            return;

        case msgpack::type::STR: {
            char* ptr = static_cast<char*>(o.zone.allocate_align(v.via.str.size));
            o.via.str.ptr = ptr;
            o.via.str.size = v.via.str.size;
            std::memcpy(ptr, v.via.str.ptr, v.via.str.size);
            return;
        }

        case msgpack::type::BIN: {
            char* ptr = static_cast<char*>(o.zone.allocate_align(v.via.bin.size));
            o.via.bin.ptr = ptr;
            o.via.bin.size = v.via.bin.size;
            std::memcpy(ptr, v.via.bin.ptr, v.via.bin.size);
            return;
        }

        case msgpack::type::EXT: {
            char* ptr = static_cast<char*>(o.zone.allocate_align(v.via.ext.size + 1));
            o.via.ext.ptr = ptr;
            o.via.ext.size = v.via.ext.size;
            std::memcpy(ptr, v.via.ext.ptr, v.via.ext.size + 1);
            return;
        }

        case msgpack::type::ARRAY:
            o.via.array.ptr = static_cast<msgpack::object*>(o.zone.allocate_align(sizeof(msgpack::object) * v.via.array.size));
            o.via.array.size = v.via.array.size;
            for (msgpack::object
                     * po(o.via.array.ptr),
                     * pv(v.via.array.ptr),
                     * const pvend(v.via.array.ptr + v.via.array.size);
                 pv < pvend;
                 ++po, ++pv) {
                new (po) msgpack::object(*pv, o.zone);
            }
            return;

        case msgpack::type::MAP:
            o.via.map.ptr = (msgpack::object_kv*)o.zone.allocate_align(sizeof(msgpack::object_kv) * v.via.map.size);
            o.via.map.size = v.via.map.size;
            for(msgpack::object_kv
                    * po(o.via.map.ptr),
                    * pv(v.via.map.ptr),
                    * const pvend(v.via.map.ptr + v.via.map.size);
                pv < pvend;
                ++po, ++pv) {
                msgpack::object_kv* kv = new (po) msgpack::object_kv;
                new (&kv->key) msgpack::object(pv->key, o.zone);
                new (&kv->val) msgpack::object(pv->val, o.zone);
            }
            return;

        default:
            throw msgpack::type_error();
        }

    }
};

// Adaptor functor specialization to object::with_zone

template <>
struct object_with_zone<msgpack::object::with_zone> {
    void operator()(
        msgpack::object::with_zone& o,
        msgpack::object::with_zone const& v) const {
        o << static_cast<msgpack::object const&>(v);
    }
};


} // namespace adaptor


// obsolete
template <typename Type>
class define : public Type {
public:
    typedef Type msgpack_type;
    typedef define<Type> define_type;

    define() {}
    define(const msgpack_type& v) : msgpack_type(v) {}

    template <typename Packer>
    void msgpack_pack(Packer& o) const
    {
        msgpack::operator<<(o, static_cast<const msgpack_type&>(*this));
    }

    void msgpack_unpack(object const& o)
    {
        msgpack::operator>>(o, static_cast<msgpack_type&>(*this));
    }
};

// deconvert operator

template <typename Stream>
template <typename T>
inline msgpack::packer<Stream>& packer<Stream>::pack(const T& v)
{
    msgpack::operator<<(*this, v);
    return *this;
}

inline bool operator==(const msgpack::object& x, const msgpack::object& y)
{
    if(x.type != y.type) { return false; }

    switch(x.type) {
    case msgpack::type::NIL:
        return true;

    case msgpack::type::BOOLEAN:
        return x.via.boolean == y.via.boolean;

    case msgpack::type::POSITIVE_INTEGER:
        return x.via.u64 == y.via.u64;

    case msgpack::type::NEGATIVE_INTEGER:
        return x.via.i64 == y.via.i64;

    case msgpack::type::FLOAT:
        return x.via.f64 == y.via.f64;

    case msgpack::type::STR:
        return x.via.str.size == y.via.str.size &&
            std::memcmp(x.via.str.ptr, y.via.str.ptr, x.via.str.size) == 0;

    case msgpack::type::BIN:
        return x.via.bin.size == y.via.bin.size &&
            std::memcmp(x.via.bin.ptr, y.via.bin.ptr, x.via.bin.size) == 0;

    case msgpack::type::EXT:
        return x.via.ext.size == y.via.ext.size &&
            std::memcmp(x.via.ext.ptr, y.via.ext.ptr, x.via.ext.size) == 0;

    case msgpack::type::ARRAY:
        if(x.via.array.size != y.via.array.size) {
            return false;
        } else if(x.via.array.size == 0) {
            return true;
        } else {
            msgpack::object* px = x.via.array.ptr;
            msgpack::object* const pxend = x.via.array.ptr + x.via.array.size;
            msgpack::object* py = y.via.array.ptr;
            do {
                if(!(*px == *py)) {
                    return false;
                }
                ++px;
                ++py;
            } while(px < pxend);
            return true;
        }

    case msgpack::type::MAP:
        if(x.via.map.size != y.via.map.size) {
            return false;
        } else if(x.via.map.size == 0) {
            return true;
        } else {
            msgpack::object_kv* px = x.via.map.ptr;
            msgpack::object_kv* const pxend = x.via.map.ptr + x.via.map.size;
            msgpack::object_kv* py = y.via.map.ptr;
            do {
                if(!(px->key == py->key) || !(px->val == py->val)) {
                    return false;
                }
                ++px;
                ++py;
            } while(px < pxend);
            return true;
        }

    default:
        return false;
    }
}

template <typename T>
inline bool operator==(const msgpack::object& x, const T& y)
try {
    return x == msgpack::object(y);
} catch (msgpack::type_error&) {
    return false;
}

inline bool operator!=(const msgpack::object& x, const msgpack::object& y)
{ return !(x == y); }

template <typename T>
inline bool operator==(const T& y, const msgpack::object x)
{ return x == y; }

template <typename T>
inline bool operator!=(const msgpack::object& x, const T& y)
{ return !(x == y); }

template <typename T>
inline bool operator!=(const T& y, const msgpack::object& x)
{ return x != y; }


inline msgpack::object::implicit_type object::convert() const
{
    return msgpack::object::implicit_type(*this);
}

template <typename T>
inline void object::convert(T& v) const
{
    msgpack::operator>>(*this, v);
}

template <typename T>
inline void object::convert(T* v) const
{
    convert(*v);
}

template <typename T>
inline T object::as() const
{
    T v;
    convert(v);
    return v;
}


inline object::object()
{
    type = msgpack::type::NIL;
}

template <typename T>
inline object::object(const T& v)
{
    msgpack::operator<<(*this, v);
}

template <typename T>
inline object& object::operator=(const T& v)
{
    *this = object(v);
    return *this;
}

template <typename T>
object::object(const T& v, msgpack::zone& z)
{
    with_zone oz(z);
    msgpack::operator<<(oz, v);
    type = oz.type;
    via = oz.via;
}

template <typename T>
object::object(const T& v, msgpack::zone* z)
{
    with_zone oz(*z);
    msgpack::operator<<(oz, v);
    type = oz.type;
    via = oz.via;
}


inline object::object(const msgpack_object& o)
{
    // FIXME beter way?
    std::memcpy(this, &o, sizeof(o));
}

inline void operator<< (msgpack::object& o, const msgpack_object& v)
{
    // FIXME beter way?
    std::memcpy(&o, &v, sizeof(v));
}

inline object::operator msgpack_object() const
{
    // FIXME beter way?
    msgpack_object obj;
    std::memcpy(&obj, this, sizeof(obj));
    return obj;
}


// obsolete
template <typename T>
inline void convert(T& v, msgpack::object const& o)
{
    o.convert(v);
}

// obsolete
template <typename Stream, typename T>
inline void pack(msgpack::packer<Stream>& o, const T& v)
{
    o.pack(v);
}

// obsolete
template <typename Stream, typename T>
inline void pack_copy(msgpack::packer<Stream>& o, T v)
{
    pack(o, v);
}


template <typename Stream>
inline msgpack::packer<Stream>& operator<< (msgpack::packer<Stream>& o, const msgpack::object& v)
{
    switch(v.type) {
    case msgpack::type::NIL:
        o.pack_nil();
        return o;

    case msgpack::type::BOOLEAN:
        if(v.via.boolean) {
            o.pack_true();
        } else {
            o.pack_false();
        }
        return o;

    case msgpack::type::POSITIVE_INTEGER:
        o.pack_uint64(v.via.u64);
        return o;

    case msgpack::type::NEGATIVE_INTEGER:
        o.pack_int64(v.via.i64);
        return o;

    case msgpack::type::FLOAT:
        o.pack_double(v.via.f64);
        return o;

    case msgpack::type::STR:
        o.pack_str(v.via.str.size);
        o.pack_str_body(v.via.str.ptr, v.via.str.size);
        return o;

    case msgpack::type::BIN:
        o.pack_bin(v.via.bin.size);
        o.pack_bin_body(v.via.bin.ptr, v.via.bin.size);
        return o;

    case msgpack::type::EXT:
        o.pack_ext(v.via.ext.size, v.via.ext.type());
        o.pack_ext_body(v.via.ext.data(), v.via.ext.size);
        return o;

    case msgpack::type::ARRAY:
        o.pack_array(v.via.array.size);
        for(msgpack::object* p(v.via.array.ptr),
                * const pend(v.via.array.ptr + v.via.array.size);
                p < pend; ++p) {
            msgpack::operator<<(o, *p);
        }
        return o;

    case msgpack::type::MAP:
        o.pack_map(v.via.map.size);
        for(msgpack::object_kv* p(v.via.map.ptr),
                * const pend(v.via.map.ptr + v.via.map.size);
                p < pend; ++p) {
            msgpack::operator<<(o, p->key);
            msgpack::operator<<(o, p->val);
        }
        return o;

    default:
        throw msgpack::type_error();
    }
}

template <typename Stream>
msgpack::packer<Stream>& operator<< (msgpack::packer<Stream>& o, const msgpack::object::with_zone& v)
{
    return o << static_cast<msgpack::object>(v);
}

inline std::ostream& operator<< (std::ostream& s, const msgpack::object& o)
{
    switch(o.type) {
    case msgpack::type::NIL:
        s << "nil";
        break;

    case msgpack::type::BOOLEAN:
        s << (o.via.boolean ? "true" : "false");
        break;

    case msgpack::type::POSITIVE_INTEGER:
        s << o.via.u64;
        break;

    case msgpack::type::NEGATIVE_INTEGER:
        s << o.via.i64;
        break;

    case msgpack::type::FLOAT:
        s << o.via.f64;
        break;

    case msgpack::type::STR:
        (s << '"').write(o.via.str.ptr, o.via.str.size) << '"';
        break;

    case msgpack::type::BIN:
        (s << '"').write(o.via.bin.ptr, o.via.bin.size) << '"';
        break;

    case msgpack::type::EXT:
        s << "EXT";
        break;

    case msgpack::type::ARRAY:
        s << "[";
        if(o.via.array.size != 0) {
            msgpack::object* p(o.via.array.ptr);
            s << *p;
            ++p;
            for(msgpack::object* const pend(o.via.array.ptr + o.via.array.size);
                    p < pend; ++p) {
                s << ", " << *p;
            }
        }
        s << "]";
        break;

    case msgpack::type::MAP:
        s << "{";
        if(o.via.map.size != 0) {
            msgpack::object_kv* p(o.via.map.ptr);
            s << p->key << "=>" << p->val;
            ++p;
            for(msgpack::object_kv* const pend(o.via.map.ptr + o.via.map.size);
                    p < pend; ++p) {
                s << ", " << p->key << "=>" << p->val;
            }
        }
        s << "}";
        break;

    default:
        // FIXME
        s << "#<UNKNOWN " << static_cast<uint16_t>(o.type) << ">";
    }
    return s;
}

/// @cond
}  // MSGPACK_API_VERSION_NAMESPACE(v1)
/// @endcond

}  // namespace msgpack

#include "msgpack/type.hpp"

#endif /* msgpack/object.hpp */
