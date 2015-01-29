//
// MessagePack for C++ serializing routine
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
#ifndef MSGPACK_PACK_HPP__
#define MSGPACK_PACK_HPP__

#include "pack_define.h"
#include <stdexcept>
#include <limits.h>

namespace msgpack {


template <typename Stream>
class packer {
public:
	packer(Stream* s);
	packer(Stream& s);
	~packer();

public:
	template <typename T>
	packer<Stream>& pack(const T& v);

	packer<Stream>& pack_uint8(uint8_t d);
	packer<Stream>& pack_uint16(uint16_t d);
	packer<Stream>& pack_uint32(uint32_t d);
	packer<Stream>& pack_uint64(uint64_t d);
	packer<Stream>& pack_int8(int8_t d);
	packer<Stream>& pack_int16(int16_t d);
	packer<Stream>& pack_int32(int32_t d);
	packer<Stream>& pack_int64(int64_t d);

	packer<Stream>& pack_fix_uint8(uint8_t d);
	packer<Stream>& pack_fix_uint16(uint16_t d);
	packer<Stream>& pack_fix_uint32(uint32_t d);
	packer<Stream>& pack_fix_uint64(uint64_t d);
	packer<Stream>& pack_fix_int8(int8_t d);
	packer<Stream>& pack_fix_int16(int16_t d);
	packer<Stream>& pack_fix_int32(int32_t d);
	packer<Stream>& pack_fix_int64(int64_t d);

	packer<Stream>& pack_char(char d);
	packer<Stream>& pack_signed_char(signed char d);
	packer<Stream>& pack_short(short d);
	packer<Stream>& pack_int(int d);
	packer<Stream>& pack_long(long d);
	packer<Stream>& pack_long_long(long long d);
	packer<Stream>& pack_unsigned_char(unsigned char d);
	packer<Stream>& pack_unsigned_short(unsigned short d);
	packer<Stream>& pack_unsigned_int(unsigned int d);
	packer<Stream>& pack_unsigned_long(unsigned long d);
	packer<Stream>& pack_unsigned_long_long(unsigned long long d);

	packer<Stream>& pack_float(float d);
	packer<Stream>& pack_double(double d);

	packer<Stream>& pack_nil();
	packer<Stream>& pack_true();
	packer<Stream>& pack_false();

	packer<Stream>& pack_array(size_t n);

	packer<Stream>& pack_map(size_t n);

	packer<Stream>& pack_raw(size_t l);
	packer<Stream>& pack_raw_body(const char* b, size_t l);

private:
	static void _pack_uint8(Stream& x, uint8_t d);
	static void _pack_uint16(Stream& x, uint16_t d);
	static void _pack_uint32(Stream& x, uint32_t d);
	static void _pack_uint64(Stream& x, uint64_t d);
	static void _pack_int8(Stream& x, int8_t d);
	static void _pack_int16(Stream& x, int16_t d);
	static void _pack_int32(Stream& x, int32_t d);
	static void _pack_int64(Stream& x, int64_t d);

	static void _pack_fix_uint8(Stream& x, uint8_t d);
	static void _pack_fix_uint16(Stream& x, uint16_t d);
	static void _pack_fix_uint32(Stream& x, uint32_t d);
	static void _pack_fix_uint64(Stream& x, uint64_t d);
	static void _pack_fix_int8(Stream& x, int8_t d);
	static void _pack_fix_int16(Stream& x, int16_t d);
	static void _pack_fix_int32(Stream& x, int32_t d);
	static void _pack_fix_int64(Stream& x, int64_t d);

	static void _pack_char(Stream& x, char d);

	static void _pack_signed_char(Stream& x, signed char d);
	static void _pack_short(Stream& x, short d);
	static void _pack_int(Stream& x, int d);
	static void _pack_long(Stream& x, long d);
	static void _pack_long_long(Stream& x, long long d);
	static void _pack_unsigned_char(Stream& x, unsigned char d);
	static void _pack_unsigned_short(Stream& x, unsigned short d);
	static void _pack_unsigned_int(Stream& x, unsigned int d);
	static void _pack_unsigned_long(Stream& x, unsigned long d);
	static void _pack_unsigned_long_long(Stream& x, unsigned long long d);

	static void _pack_float(Stream& x, float d);
	static void _pack_double(Stream& x, double d);

	static void _pack_nil(Stream& x);
	static void _pack_true(Stream& x);
	static void _pack_false(Stream& x);

	static void _pack_array(Stream& x, size_t n);

	static void _pack_map(Stream& x, size_t n);

	static void _pack_raw(Stream& x, size_t l);
	static void _pack_raw_body(Stream& x, const void* b, size_t l);

	static void append_buffer(Stream& x, const unsigned char* buf, size_t len)
		{ x.write((const char*)buf, len); }

private:
	Stream& m_stream;

private:
	packer();
};


template <typename Stream, typename T>
inline void pack(Stream* s, const T& v)
{
	packer<Stream>(s).pack(v);
}

template <typename Stream, typename T>
inline void pack(Stream& s, const T& v)
{
	packer<Stream>(s).pack(v);
}


#define msgpack_pack_inline_func(name) \
	template <typename Stream> \
	inline void packer<Stream>::_pack ## name

#define msgpack_pack_inline_func_cint(name) \
	template <typename Stream> \
	inline void packer<Stream>::_pack ## name

#define msgpack_pack_inline_func_fixint(name) \
	template <typename Stream> \
	inline void packer<Stream>::_pack_fix ## name

#define msgpack_pack_user Stream&

#define msgpack_pack_append_buffer append_buffer

#include "pack_template.h"


template <typename Stream>
packer<Stream>::packer(Stream* s) : m_stream(*s) { }

template <typename Stream>
packer<Stream>::packer(Stream& s) : m_stream(s) { }

template <typename Stream>
packer<Stream>::~packer() { }


template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_uint8(uint8_t d)
{ _pack_uint8(m_stream, d); return *this; }

template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_uint16(uint16_t d)
{ _pack_uint16(m_stream, d); return *this; }

template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_uint32(uint32_t d)
{ _pack_uint32(m_stream, d); return *this; }

template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_uint64(uint64_t d)
{ _pack_uint64(m_stream, d); return *this; }

template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_int8(int8_t d)
{ _pack_int8(m_stream, d); return *this; }

template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_int16(int16_t d)
{ _pack_int16(m_stream, d); return *this; }

template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_int32(int32_t d)
{ _pack_int32(m_stream, d); return *this; }

template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_int64(int64_t d)
{ _pack_int64(m_stream, d); return *this;}


template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_fix_uint8(uint8_t d)
{ _pack_fix_uint8(m_stream, d); return *this; }

template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_fix_uint16(uint16_t d)
{ _pack_fix_uint16(m_stream, d); return *this; }

template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_fix_uint32(uint32_t d)
{ _pack_fix_uint32(m_stream, d); return *this; }

template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_fix_uint64(uint64_t d)
{ _pack_fix_uint64(m_stream, d); return *this; }

template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_fix_int8(int8_t d)
{ _pack_fix_int8(m_stream, d); return *this; }

template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_fix_int16(int16_t d)
{ _pack_fix_int16(m_stream, d); return *this; }

template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_fix_int32(int32_t d)
{ _pack_fix_int32(m_stream, d); return *this; }

template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_fix_int64(int64_t d)
{ _pack_fix_int64(m_stream, d); return *this;}


template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_char(char d)
{ _pack_char(m_stream, d); return *this; }

template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_signed_char(signed char d)
{ _pack_signed_char(m_stream, d); return *this; }

template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_short(short d)
{ _pack_short(m_stream, d); return *this; }

template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_int(int d)
{ _pack_int(m_stream, d); return *this; }

template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_long(long d)
{ _pack_long(m_stream, d); return *this; }

template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_long_long(long long d)
{ _pack_long_long(m_stream, d); return *this; }

template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_unsigned_char(unsigned char d)
{ _pack_unsigned_char(m_stream, d); return *this; }

template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_unsigned_short(unsigned short d)
{ _pack_unsigned_short(m_stream, d); return *this; }

template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_unsigned_int(unsigned int d)
{ _pack_unsigned_int(m_stream, d); return *this; }

template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_unsigned_long(unsigned long d)
{ _pack_unsigned_long(m_stream, d); return *this; }

template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_unsigned_long_long(unsigned long long d)
{ _pack_unsigned_long_long(m_stream, d); return *this; }


template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_float(float d)
{ _pack_float(m_stream, d); return *this; }

template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_double(double d)
{ _pack_double(m_stream, d); return *this; }


template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_nil()
{ _pack_nil(m_stream); return *this; }

template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_true()
{ _pack_true(m_stream); return *this; }

template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_false()
{ _pack_false(m_stream); return *this; }


template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_array(size_t n)
{ _pack_array(m_stream, n); return *this; }


template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_map(size_t n)
{ _pack_map(m_stream, n); return *this; }


template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_raw(size_t l)
{ _pack_raw(m_stream, l); return *this; }

template <typename Stream>
inline packer<Stream>& packer<Stream>::pack_raw_body(const char* b, size_t l)
{ _pack_raw_body(m_stream, b, l); return *this; }


}  // namespace msgpack

#endif /* msgpack/pack.hpp */

