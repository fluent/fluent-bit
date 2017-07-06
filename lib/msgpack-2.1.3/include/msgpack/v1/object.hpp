//
// MessagePack for C++ static resolution routine
//
// Copyright (C) 2008-2014 FURUHASHI Sadayuki and KONDO Takatoshi
//
//    Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//    http://www.boost.org/LICENSE_1_0.txt)
//
#ifndef MSGPACK_V1_OBJECT_HPP
#define MSGPACK_V1_OBJECT_HPP

#include "msgpack/object_decl.hpp"

#include <cstring>
#include <stdexcept>
#include <typeinfo>
#include <limits>
#include <ostream>
#include <typeinfo>
#include <iomanip>

namespace msgpack {

/// @cond
MSGPACK_API_VERSION_NAMESPACE(v1) {
/// @endcond

struct object_kv {
    msgpack::object key;
    msgpack::object val;
};

struct object::with_zone : msgpack::object {
    with_zone(msgpack::zone& z) : zone(z) { }
    msgpack::zone& zone;
private:
    with_zone();
};


/// The class holds object and zone
class object_handle {
public:
    /// Constructor that creates nil object and null zone.
    object_handle() {}

    /// Constructor that creates an object_handle holding object `obj` and zone `z`.
    /**
     * @param obj object
     * @param z zone
     */
    object_handle(
        msgpack::object const& obj,
#if defined(MSGPACK_USE_CPP03)
        msgpack::unique_ptr<msgpack::zone> z
#else  // defined(MSGPACK_USE_CPP03)
        msgpack::unique_ptr<msgpack::zone>&& z
#endif // defined(MSGPACK_USE_CPP03)
    ) :
        m_obj(obj), m_zone(msgpack::move(z)) { }

    void set(msgpack::object const& obj)
        { m_obj = obj; }

    /// Get object reference
    /**
     * @return object
     */
    const msgpack::object& get() const
        { return m_obj; }

    /// Get unique_ptr reference of zone.
    /**
     * @return unique_ptr reference of zone
     */
    msgpack::unique_ptr<msgpack::zone>& zone()
        { return m_zone; }

    /// Get unique_ptr const reference of zone.
    /**
     * @return unique_ptr const reference of zone
     */
    const msgpack::unique_ptr<msgpack::zone>& zone() const
        { return m_zone; }

#if defined(MSGPACK_USE_CPP03)
    struct object_handle_ref {
        object_handle_ref(object_handle* oh):m_oh(oh) {}
        object_handle* m_oh;
    };

    object_handle(object_handle& other):
        m_obj(other.m_obj),
        m_zone(msgpack::move(other.m_zone)) {
    }

    object_handle(object_handle_ref ref):
        m_obj(ref.m_oh->m_obj),
        m_zone(msgpack::move(ref.m_oh->m_zone)) {
    }

    object_handle& operator=(object_handle& other) {
        m_obj = other.m_obj;
        m_zone = msgpack::move(other.m_zone);
        return *this;
    }

    object_handle& operator=(object_handle_ref ref) {
        m_obj = ref.m_oh->m_obj;
        m_zone = msgpack::move(ref.m_oh->m_zone);
        return *this;
    }

    operator object_handle_ref() {
        return object_handle_ref(this);
    }
#endif // defined(MSGPACK_USE_CPP03)

private:
    msgpack::object m_obj;
    msgpack::unique_ptr<msgpack::zone> m_zone;
};

namespace detail {

template <std::size_t N>
inline std::size_t add_ext_type_size(std::size_t size) {
    return size + 1;
}

template <>
inline std::size_t add_ext_type_size<4>(std::size_t size) {
    return size == 0xffffffff ? size : size + 1;
}

} // namespace detail

inline std::size_t aligned_zone_size(msgpack::object const& obj) {
    std::size_t s = 0;
    switch (obj.type) {
    case msgpack::type::ARRAY:
        s += sizeof(msgpack::object) * obj.via.array.size;
        for (uint32_t i = 0; i < obj.via.array.size; ++i) {
            s += msgpack::aligned_zone_size(obj.via.array.ptr[i]);
        }
        break;
    case msgpack::type::MAP:
        s += sizeof(msgpack::object_kv) * obj.via.map.size;
        for (uint32_t i = 0; i < obj.via.map.size; ++i) {
            s += msgpack::aligned_zone_size(obj.via.map.ptr[i].key);
            s += msgpack::aligned_zone_size(obj.via.map.ptr[i].val);
        }
        break;
    case msgpack::type::EXT:
        s += msgpack::aligned_size(
            detail::add_ext_type_size<sizeof(std::size_t)>(obj.via.ext.size));
        break;
    case msgpack::type::STR:
        s += msgpack::aligned_size(obj.via.str.size);
        break;
    case msgpack::type::BIN:
        s += msgpack::aligned_size(obj.via.bin.size);
        break;
    default:
        break;
    }
    return s;
}

/// clone object
/**
 * Clone (deep copy) object.
 * The copied object is located on newly allocated zone.
 * @param obj copy source object
 *
 * @return object_handle that holds deep copied object and zone.
 */
inline object_handle clone(msgpack::object const& obj) {
    std::size_t size = msgpack::aligned_zone_size(obj);
    msgpack::unique_ptr<msgpack::zone> z(size == 0 ? MSGPACK_NULLPTR : new msgpack::zone(size));
    msgpack::object newobj = z.get() ? msgpack::object(obj, *z) : obj;
    return object_handle(newobj, msgpack::move(z));
}

template <typename T>
inline object::implicit_type::operator T() { return obj.as<T>(); }

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
template <typename T, typename Enabler>
inline
msgpack::object const&
adaptor::convert<T, Enabler>::operator()(msgpack::object const& o, T& v) const {
    v.msgpack_unpack(o.convert());
    return o;
}

template <typename T, typename Enabler>
template <typename Stream>
inline
msgpack::packer<Stream>&
adaptor::pack<T, Enabler>::operator()(msgpack::packer<Stream>& o, T const& v) const {
    return msgpack::detail::packer_serializer<Stream, T>::pack(o, v);
}

template <typename T, typename Enabler>
inline
void
adaptor::object_with_zone<T, Enabler>::operator()(msgpack::object::with_zone& o, T const& v) const {
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

        case msgpack::type::FLOAT32:
            o.pack_float(static_cast<float>(v.via.f64));
            return o;

        case msgpack::type::FLOAT64:
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
        case msgpack::type::FLOAT32:
        case msgpack::type::FLOAT64:
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

    case msgpack::type::FLOAT32:
    case msgpack::type::FLOAT64:
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
inline bool operator==(const T& y, const msgpack::object& x)
{ return x == y; }

template <typename T>
inline bool operator!=(const msgpack::object& x, const T& y)
{ return !(x == y); }

template <typename T>
inline bool operator!=(const T& y, const msgpack::object& x)
{ return x != y; }


inline object::implicit_type object::convert() const
{
    return object::implicit_type(*this);
}

template <typename T>
inline
typename msgpack::enable_if<
    !msgpack::is_array<T>::value && !msgpack::is_pointer<T>::value,
    T&
>::type
object::convert(T& v) const
{
    msgpack::operator>>(*this, v);
    return v;
}

template <typename T, std::size_t N>
inline T(&object::convert(T(&v)[N]) const)[N]
{
    msgpack::operator>>(*this, v);
    return v;
}

#if !defined(MSGPACK_DISABLE_LEGACY_CONVERT)
template <typename T>
inline
typename msgpack::enable_if<
    msgpack::is_pointer<T>::value,
    T
>::type
object::convert(T v) const
{
    convert(*v);
    return v;
}
#endif // !defined(MSGPACK_DISABLE_LEGACY_CONVERT)

template <typename T>
inline bool object::convert_if_not_nil(T& v) const
{
    if (is_nil()) {
        return false;
    }
    convert(v);
    return true;
}

#if defined(MSGPACK_USE_CPP03)

template <typename T>
inline T object::as() const
{
    T v;
    convert(v);
    return v;
}

#else  // defined(MSGPACK_USE_CPP03)

template <typename T>
inline typename std::enable_if<msgpack::has_as<T>::value, T>::type object::as() const {
    return msgpack::adaptor::as<T>()(*this);
}

template <typename T>
inline typename std::enable_if<!msgpack::has_as<T>::value, T>::type object::as() const {
    T v;
    convert(v);
    return v;
}

#endif // defined(MSGPACK_USE_CPP03)

inline object::object()
{
    type = msgpack::type::NIL;
}

template <typename T>
inline object::object(const T& v)
{
    *this << v;
}

template <typename T>
inline object& object::operator=(const T& v)
{
    *this = object(v);
    return *this;
}

template <typename T>
inline object::object(const T& v, msgpack::zone& z)
{
    with_zone oz(z);
    msgpack::operator<<(oz, v);
    type = oz.type;
    via = oz.via;
}

template <typename T>
inline object::object(const T& v, msgpack::zone* z)
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

    case msgpack::type::FLOAT32:
        o.pack_float(v.via.f64);
        return o;

    case msgpack::type::FLOAT64:
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
inline msgpack::packer<Stream>& operator<< (msgpack::packer<Stream>& o, const msgpack::object::with_zone& v)
{
    return o << static_cast<msgpack::object>(v);
}

inline std::ostream& operator<< (std::ostream& s, const msgpack::object& o)
{
    switch(o.type) {
    case msgpack::type::NIL:
        s << "null";
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

    case msgpack::type::FLOAT32:
    case msgpack::type::FLOAT64:
        s << o.via.f64;
        break;

    case msgpack::type::STR:
        s << '"';
        for (uint32_t i = 0; i < o.via.str.size; ++i) {
            char c = o.via.str.ptr[i];
            switch (c) {
            case '\\':
                s << "\\\\";
                break;
            case '"':
                s << "\\\"";
                break;
            case '/':
                s << "\\/";
                break;
            case '\b':
                s << "\\b";
                break;
            case '\f':
                s << "\\f";
                break;
            case '\n':
                s << "\\n";
                break;
            case '\r':
                s << "\\r";
                break;
            case '\t':
                s << "\\t";
                break;
            default: {
                unsigned int code = static_cast<unsigned int>(c);
                if (code < 0x20 || code == 0x7f) {
                    std::ios::fmtflags flags(s.flags());
                    s << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (code & 0xff);
                    s.flags(flags);
                }
                else {
                    s << c;
                }
            } break;
            }
        }
        s << '"';
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
            s << p->key << ':' << p->val;
            ++p;
            for(msgpack::object_kv* const pend(o.via.map.ptr + o.via.map.size);
                    p < pend; ++p) {
                s << ", " << p->key << ':' << p->val;
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

#endif // MSGPACK_V1_OBJECT_HPP
