//
// MessagePack for C++ deserializing routine
//
// Copyright (C) 2008-2009 FURUHASHI Sadayuki
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
#ifndef MSGPACK_UNPACK_HPP__
#define MSGPACK_UNPACK_HPP__

#include "unpack.h"
#include "object.hpp"
#include "zone.hpp"
#include <memory>
#include <stdexcept>

// backward compatibility
#ifndef MSGPACK_UNPACKER_DEFAULT_INITIAL_BUFFER_SIZE
#define MSGPACK_UNPACKER_DEFAULT_INITIAL_BUFFER_SIZE MSGPACK_UNPACKER_INIT_BUFFER_SIZE
#endif

namespace msgpack {


struct unpack_error : public std::runtime_error {
	unpack_error(const std::string& msg) :
		std::runtime_error(msg) { }
};


class unpacked {
public:
	unpacked() { }

	unpacked(object obj, std::auto_ptr<msgpack::zone> z) :
		m_obj(obj), m_zone(z) { }

	object& get()
		{ return m_obj; }

	const object& get() const
		{ return m_obj; }

	std::auto_ptr<msgpack::zone>& zone()
		{ return m_zone; }

	const std::auto_ptr<msgpack::zone>& zone() const
		{ return m_zone; }

private:
	object m_obj;
	std::auto_ptr<msgpack::zone> m_zone;
};


class unpacker : public msgpack_unpacker {
public:
	unpacker(size_t init_buffer_size = MSGPACK_UNPACKER_INIT_BUFFER_SIZE);
	~unpacker();

public:
	/*! 1. reserve buffer. at least `size' bytes of capacity will be ready */
	void reserve_buffer(size_t size = MSGPACK_UNPACKER_RESERVE_SIZE);

	/*! 2. read data to the buffer() up to buffer_capacity() bytes */
	char* buffer();
	size_t buffer_capacity() const;

	/*! 3. specify the number of bytes actually copied */
	void buffer_consumed(size_t size);

	/*! 4. repeat next() until it retunrs false */
	bool next(unpacked* result);

	/*! 5. check if the size of message doesn't exceed assumption. */
	size_t message_size() const;

	// Basic usage of the unpacker is as following:
	//
	// msgpack::unpacker pac;
	// while( /* input is readable */ ) {
	//
	//     // 1.
	//     pac.reserve_buffer(32*1024);
	//
	//     // 2.
	//     size_t bytes = input.readsome(pac.buffer(), pac.buffer_capacity());
	//
	//     // error handling ...
	//
	//     // 3.
	//     pac.buffer_consumed(bytes);
	//
	//     // 4.
	//     msgpack::unpacked result;
	//     while(pac.next(&result)) {
	//         // do some with the object with the zone.
	//         msgpack::object obj = result.get();
	//         std::auto_ptr<msgpack:zone> z = result.zone();
	//         on_message(obj, z);
	//
	//         //// boost::shared_ptr is also usable:
	//         // boost::shared_ptr<msgpack::zone> life(z.release());
	//         // on_message(result.get(), life);
	//     }
	//
	//     // 5.
	//     if(pac.message_size() > 10*1024*1024) {
	//         throw std::runtime_error("message is too large");
	//     }
	// }
	//

	/*! for backward compatibility */
	bool execute();

	/*! for backward compatibility */
	object data();

	/*! for backward compatibility */
	zone* release_zone();

	/*! for backward compatibility */
	void reset_zone();

	/*! for backward compatibility */
	void reset();

public:
	// These functions are usable when non-MessagePack message follows after
	// MessagePack message.
	size_t parsed_size() const;

	/*! get address of the buffer that is not parsed */
	char* nonparsed_buffer();
	size_t nonparsed_size() const;

	/*! skip specified size of non-parsed buffer, leaving the buffer */
	// Note that the `size' argument must be smaller than nonparsed_size()
	void skip_nonparsed_buffer(size_t size);

	/*! remove unparsed buffer from unpacker */
	// Note that reset() leaves non-parsed buffer.
	void remove_nonparsed_buffer();

private:
	typedef msgpack_unpacker base;

private:
	unpacker(const unpacker&);
};


static void unpack(unpacked* result,
		const char* data, size_t len, size_t* offset = NULL);


// obsolete
typedef enum {
	UNPACK_SUCCESS				=  2,
	UNPACK_EXTRA_BYTES			=  1,
	UNPACK_CONTINUE				=  0,
	UNPACK_PARSE_ERROR			= -1,
} unpack_return;

// obsolete
static unpack_return unpack(const char* data, size_t len, size_t* off,
		zone* z, object* result);


// obsolete
static object unpack(const char* data, size_t len, zone& z, size_t* off = NULL);


inline unpacker::unpacker(size_t initial_buffer_size)
{
	if(!msgpack_unpacker_init(this, initial_buffer_size)) {
		throw std::bad_alloc();
	}
}

inline unpacker::~unpacker()
{
	msgpack_unpacker_destroy(this);
}


inline void unpacker::reserve_buffer(size_t size)
{
	if(!msgpack_unpacker_reserve_buffer(this, size)) {
		throw std::bad_alloc();
	}
}

inline char* unpacker::buffer()
{
	return msgpack_unpacker_buffer(this);
}

inline size_t unpacker::buffer_capacity() const
{
	return msgpack_unpacker_buffer_capacity(this);
}

inline void unpacker::buffer_consumed(size_t size)
{
	return msgpack_unpacker_buffer_consumed(this, size);
}

inline bool unpacker::next(unpacked* result)
{
	int ret = msgpack_unpacker_execute(this);

	if(ret < 0) {
		throw unpack_error("parse error");
	}

	if(ret == 0) {
		result->zone().reset();
		result->get() = object();
		return false;

	} else {
		result->zone().reset( release_zone() );
		result->get() = data();
		reset();
		return true;
	}
}


inline bool unpacker::execute()
{
	int ret = msgpack_unpacker_execute(this);
	if(ret < 0) {
		throw unpack_error("parse error");
	} else if(ret == 0) {
		return false;
	} else {
		return true;
	}
}

inline object unpacker::data()
{
	return msgpack_unpacker_data(this);
}

inline zone* unpacker::release_zone()
{
	return static_cast<msgpack::zone*>(msgpack_unpacker_release_zone(static_cast<msgpack_unpacker*>(this)));
}

inline void unpacker::reset_zone()
{
	msgpack_unpacker_reset_zone(this);
}

inline void unpacker::reset()
{
	msgpack_unpacker_reset(this);
}


inline size_t unpacker::message_size() const
{
	return msgpack_unpacker_message_size(this);
}

inline size_t unpacker::parsed_size() const
{
	return msgpack_unpacker_parsed_size(this);
}

inline char* unpacker::nonparsed_buffer()
{
	return base::buffer + base::off;
}

inline size_t unpacker::nonparsed_size() const
{
	return base::used - base::off;
}

inline void unpacker::skip_nonparsed_buffer(size_t size)
{
	base::off += size;
}

inline void unpacker::remove_nonparsed_buffer()
{
	base::used = base::off;
}


inline void unpack(unpacked* result,
		const char* data, size_t len, size_t* offset)
{
	msgpack::object obj;
	std::auto_ptr<msgpack::zone> z(new zone());

	unpack_return ret = (unpack_return)msgpack_unpack(
			data, len, offset, z.get(),
			reinterpret_cast<msgpack_object*>(&obj));

	switch(ret) {
	case UNPACK_SUCCESS:
		result->get() = obj;
		result->zone() = z;
		return;

	case UNPACK_EXTRA_BYTES:
		result->get() = obj;
		result->zone() = z;
		return;

	case UNPACK_CONTINUE:
		throw unpack_error("insufficient bytes");

	case UNPACK_PARSE_ERROR:
	default:
		throw unpack_error("parse error");
	}
}


// obsolete
inline unpack_return unpack(const char* data, size_t len, size_t* off,
		zone* z, object* result)
{
	return (unpack_return)msgpack_unpack(data, len, off,
			z, reinterpret_cast<msgpack_object*>(result));
}

// obsolete
inline object unpack(const char* data, size_t len, zone& z, size_t* off)
{
	object result;

	switch( msgpack::unpack(data, len, off, &z, &result) ) {
	case UNPACK_SUCCESS:
		return result;

	case UNPACK_EXTRA_BYTES:
		if(off) {
			return result;
		} else {
			throw unpack_error("extra bytes");
		}

	case UNPACK_CONTINUE:
		throw unpack_error("insufficient bytes");

	case UNPACK_PARSE_ERROR:
	default:
		throw unpack_error("parse error");
	}
}


}  // namespace msgpack

#endif /* msgpack/unpack.hpp */

