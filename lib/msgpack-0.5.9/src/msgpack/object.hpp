//
// MessagePack for C++ static resolution routine
//
// Copyright (C) 2008-2010 FURUHASHI Sadayuki
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
#ifndef MSGPACK_OBJECT_HPP__
#define MSGPACK_OBJECT_HPP__

#include "object.h"
#include "pack.hpp"
#include "zone.hpp"
#include <string.h>
#include <stdexcept>
#include <typeinfo>
#include <limits>
#include <ostream>

namespace msgpack {


class type_error : public std::bad_cast { };


namespace type {
	enum object_type {
		NIL					= MSGPACK_OBJECT_NIL,
		BOOLEAN				= MSGPACK_OBJECT_BOOLEAN,
		POSITIVE_INTEGER	= MSGPACK_OBJECT_POSITIVE_INTEGER,
		NEGATIVE_INTEGER	= MSGPACK_OBJECT_NEGATIVE_INTEGER,
		DOUBLE				= MSGPACK_OBJECT_DOUBLE,
		RAW					= MSGPACK_OBJECT_RAW,
		ARRAY				= MSGPACK_OBJECT_ARRAY,
		MAP					= MSGPACK_OBJECT_MAP,
	};
}


struct object;
struct object_kv;

struct object_array {
	uint32_t size;
	object* ptr;
};

struct object_map {
	uint32_t size;
	object_kv* ptr;
};

struct object_raw {
	uint32_t size;
	const char* ptr;
};

struct object {
	union union_type {
		bool boolean;
		uint64_t u64;
		int64_t  i64;
		double   dec;
		object_array array;
		object_map map;
		object_raw raw;
		object_raw ref;  // obsolete
	};

	type::object_type type;
	union_type via;

	bool is_nil() const { return type == type::NIL; }

	template <typename T>
	T as() const;

	template <typename T>
	void convert(T* v) const;

	object();

	object(msgpack_object o);

	template <typename T>
	explicit object(const T& v);

	template <typename T>
	object(const T& v, zone* z);

	template <typename T>
	object& operator=(const T& v);

	operator msgpack_object() const;

	struct with_zone;

private:
	struct implicit_type;

public:
	implicit_type convert() const;
};

struct object_kv {
	object key;
	object val;
};

struct object::with_zone : object {
	with_zone(msgpack::zone* zone) : zone(zone) { }
	msgpack::zone* zone;
private:
	with_zone();
};


bool operator==(const object x, const object y);
bool operator!=(const object x, const object y);

template <typename T>
bool operator==(const object x, const T& y);

template <typename T>
bool operator==(const T& y, const object x);

template <typename T>
bool operator!=(const object x, const T& y);

template <typename T>
bool operator!=(const T& y, const object x);

std::ostream& operator<< (std::ostream& s, const object o);


// serialize operator
template <typename Stream, typename T>
packer<Stream>& operator<< (packer<Stream>& o, const T& v);

// convert operator
template <typename T>
T& operator>> (object o, T& v);

// deconvert operator
template <typename T>
void operator<< (object::with_zone& o, const T& v);


struct object::implicit_type {
	implicit_type(object o) : obj(o) { }
	~implicit_type() { }

	template <typename T>
	operator T() { return obj.as<T>(); }

private:
	object obj;
};


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
		o << static_cast<const msgpack_type&>(*this);
	}

	void msgpack_unpack(object o)
	{
		o >> static_cast<msgpack_type&>(*this);
	}
};


template <typename Stream>
template <typename T>
inline packer<Stream>& packer<Stream>::pack(const T& v)
{
	*this << v;
	return *this;
}

inline object& operator>> (object o, object& v)
{
	v = o;
	return v;
}

template <typename T>
inline T& operator>> (object o, T& v)
{
	v.msgpack_unpack(o.convert());
	return v;
}

namespace detail {
template <typename Stream, typename T>
struct packer_serializer {
	static packer<Stream>& pack(packer<Stream>& o, const T& v) {
		v.msgpack_pack(o);
		return o;
	}
};
}

template <typename Stream, typename T>
inline packer<Stream>& operator<< (packer<Stream>& o, const T& v)
{
	return detail::packer_serializer<Stream, T>::pack(o, v);
}

template <typename T>
void operator<< (object::with_zone& o, const T& v)
{
	v.msgpack_object(static_cast<object*>(&o), o.zone);
}


inline bool operator==(const object x, const object y)
{
	return msgpack_object_equal(x, y);
}

template <typename T>
inline bool operator==(const object x, const T& y)
try {
	return x == object(y);
} catch (msgpack::type_error&) {
	return false;
}

inline bool operator!=(const object x, const object y)
{ return !(x == y); }

template <typename T>
inline bool operator==(const T& y, const object x)
{ return x == y; }

template <typename T>
inline bool operator!=(const object x, const T& y)
{ return !(x == y); }

template <typename T>
inline bool operator!=(const T& y, const object x)
{ return x != y; }


inline object::implicit_type object::convert() const
{
	return implicit_type(*this);
}

template <typename T>
inline void object::convert(T* v) const
{
	*this >> *v;
}

template <typename T>
inline T object::as() const
{
	T v;
	convert(&v);
	return v;
}


inline object::object()
{
	type = type::NIL;
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
object::object(const T& v, zone* z)
{
	with_zone oz(z);
	oz << v;
	type = oz.type;
	via = oz.via;
}


inline object::object(msgpack_object o)
{
	// FIXME beter way?
	::memcpy(this, &o, sizeof(o));
}

inline void operator<< (object& o, msgpack_object v)
{
	// FIXME beter way?
	::memcpy(&o, &v, sizeof(v));
}

inline object::operator msgpack_object() const
{
	// FIXME beter way?
	msgpack_object obj;
	::memcpy(&obj, this, sizeof(obj));
	return obj;
}


// obsolete
template <typename T>
inline void convert(T& v, object o)
{
	o.convert(&v);
}

// obsolete
template <typename Stream, typename T>
inline void pack(packer<Stream>& o, const T& v)
{
	o.pack(v);
}

// obsolete
template <typename Stream, typename T>
inline void pack_copy(packer<Stream>& o, T v)
{
	pack(o, v);
}


template <typename Stream>
packer<Stream>& operator<< (packer<Stream>& o, const object& v)
{
	switch(v.type) {
	case type::NIL:
		o.pack_nil();
		return o;

	case type::BOOLEAN:
		if(v.via.boolean) {
			o.pack_true();
		} else {
			o.pack_false();
		}
		return o;

	case type::POSITIVE_INTEGER:
		o.pack_uint64(v.via.u64);
		return o;

	case type::NEGATIVE_INTEGER:
		o.pack_int64(v.via.i64);
		return o;

	case type::DOUBLE:
		o.pack_double(v.via.dec);
		return o;

	case type::RAW:
		o.pack_raw(v.via.raw.size);
		o.pack_raw_body(v.via.raw.ptr, v.via.raw.size);
		return o;

	case type::ARRAY:
		o.pack_array(v.via.array.size);
		for(object* p(v.via.array.ptr),
				* const pend(v.via.array.ptr + v.via.array.size);
				p < pend; ++p) {
			o << *p;
		}
		return o;

	case type::MAP:
		o.pack_map(v.via.map.size);
		for(object_kv* p(v.via.map.ptr),
				* const pend(v.via.map.ptr + v.via.map.size);
				p < pend; ++p) {
			o << p->key;
			o << p->val;
		}
		return o;

	default:
		throw type_error();
	}
}


}  // namespace msgpack

#include "msgpack/type.hpp"

#endif /* msgpack/object.hpp */

