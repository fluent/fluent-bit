//
// MessagePack for C++ static resolution routine
//
// Copyright (C) 2020 FURUHASHI Sadayuki
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
#ifndef MSGPACK_TYPE_FIXINT_HPP__
#define MSGPACK_TYPE_FIXINT_HPP__

#include "msgpack/object.hpp"
#include "msgpack/type/int.hpp"

namespace msgpack {

namespace type {


template <typename T>
struct fix_int {
	fix_int() : value(0) { }
	fix_int(T value) : value(value) { }

	operator T() const { return value; }

	T get() const { return value; }

private:
	T value;
};


typedef fix_int<uint8_t>  fix_uint8;
typedef fix_int<uint16_t> fix_uint16;
typedef fix_int<uint32_t> fix_uint32;
typedef fix_int<uint64_t> fix_uint64;

typedef fix_int<int8_t>  fix_int8;
typedef fix_int<int16_t> fix_int16;
typedef fix_int<int32_t> fix_int32;
typedef fix_int<int64_t> fix_int64;


}  // namespace type


inline type::fix_int8& operator>> (object o, type::fix_int8& v)
	{ v = type::detail::convert_integer<int8_t>(o); return v; }

inline type::fix_int16& operator>> (object o, type::fix_int16& v)
	{ v = type::detail::convert_integer<int16_t>(o); return v; }

inline type::fix_int32& operator>> (object o, type::fix_int32& v)
	{ v = type::detail::convert_integer<int32_t>(o); return v; }

inline type::fix_int64& operator>> (object o, type::fix_int64& v)
	{ v = type::detail::convert_integer<int64_t>(o); return v; }


inline type::fix_uint8& operator>> (object o, type::fix_uint8& v)
	{ v = type::detail::convert_integer<uint8_t>(o); return v; }

inline type::fix_uint16& operator>> (object o, type::fix_uint16& v)
	{ v = type::detail::convert_integer<uint16_t>(o); return v; }

inline type::fix_uint32& operator>> (object o, type::fix_uint32& v)
	{ v = type::detail::convert_integer<uint32_t>(o); return v; }

inline type::fix_uint64& operator>> (object o, type::fix_uint64& v)
	{ v = type::detail::convert_integer<uint64_t>(o); return v; }


template <typename Stream>
inline packer<Stream>& operator<< (packer<Stream>& o, const type::fix_int8& v)
	{ o.pack_fix_int8(v); return o; }

template <typename Stream>
inline packer<Stream>& operator<< (packer<Stream>& o, const type::fix_int16& v)
	{ o.pack_fix_int16(v); return o; }

template <typename Stream>
inline packer<Stream>& operator<< (packer<Stream>& o, const type::fix_int32& v)
	{ o.pack_fix_int32(v); return o; }

template <typename Stream>
inline packer<Stream>& operator<< (packer<Stream>& o, const type::fix_int64& v)
	{ o.pack_fix_int64(v); return o; }


template <typename Stream>
inline packer<Stream>& operator<< (packer<Stream>& o, const type::fix_uint8& v)
	{ o.pack_fix_uint8(v); return o; }

template <typename Stream>
inline packer<Stream>& operator<< (packer<Stream>& o, const type::fix_uint16& v)
	{ o.pack_fix_uint16(v); return o; }

template <typename Stream>
inline packer<Stream>& operator<< (packer<Stream>& o, const type::fix_uint32& v)
	{ o.pack_fix_uint32(v); return o; }

template <typename Stream>
inline packer<Stream>& operator<< (packer<Stream>& o, const type::fix_uint64& v)
	{ o.pack_fix_uint64(v); return o; }


inline void operator<< (object& o, type::fix_int8 v)
	{ v.get() < 0 ? o.type = type::NEGATIVE_INTEGER, o.via.i64 = v.get() : o.type = type::POSITIVE_INTEGER, o.via.u64 = v.get(); }

inline void operator<< (object& o, type::fix_int16 v)
	{ v.get() < 0 ? o.type = type::NEGATIVE_INTEGER, o.via.i64 = v.get() : o.type = type::POSITIVE_INTEGER, o.via.u64 = v.get(); }

inline void operator<< (object& o, type::fix_int32 v)
	{ v.get() < 0 ? o.type = type::NEGATIVE_INTEGER, o.via.i64 = v.get() : o.type = type::POSITIVE_INTEGER, o.via.u64 = v.get(); }

inline void operator<< (object& o, type::fix_int64 v)
	{ v.get() < 0 ? o.type = type::NEGATIVE_INTEGER, o.via.i64 = v.get() : o.type = type::POSITIVE_INTEGER, o.via.u64 = v.get(); }


inline void operator<< (object& o, type::fix_uint8 v)
	{ o.type = type::POSITIVE_INTEGER, o.via.u64 = v.get(); }

inline void operator<< (object& o, type::fix_uint16 v)
	{ o.type = type::POSITIVE_INTEGER, o.via.u64 = v.get(); }

inline void operator<< (object& o, type::fix_uint32 v)
	{ o.type = type::POSITIVE_INTEGER, o.via.u64 = v.get(); }

inline void operator<< (object& o, type::fix_uint64 v)
	{ o.type = type::POSITIVE_INTEGER, o.via.u64 = v.get(); }


inline void operator<< (object::with_zone& o, type::fix_int8 v)
	{ static_cast<object&>(o) << v; }

inline void operator<< (object::with_zone& o, type::fix_int16 v)
	{ static_cast<object&>(o) << v; }

inline void operator<< (object::with_zone& o, type::fix_int32 v)
	{ static_cast<object&>(o) << v; }

inline void operator<< (object::with_zone& o, type::fix_int64 v)
	{ static_cast<object&>(o) << v; }


inline void operator<< (object::with_zone& o, type::fix_uint8 v)
	{ static_cast<object&>(o) << v; }

inline void operator<< (object::with_zone& o, type::fix_uint16 v)
	{ static_cast<object&>(o) << v; }

inline void operator<< (object::with_zone& o, type::fix_uint32 v)
	{ static_cast<object&>(o) << v; }

inline void operator<< (object::with_zone& o, type::fix_uint64 v)
	{ static_cast<object&>(o) << v; }


}  // namespace msgpack

#endif /* msgpack/type/fixint.hpp */

