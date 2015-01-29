//
// MessagePack for C++ deflate buffer implementation
//
// Copyright (C) 2010 FURUHASHI Sadayuki
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
#ifndef MSGPACK_ZBUFFER_HPP__
#define MSGPACK_ZBUFFER_HPP__

#include "zbuffer.h"
#include <stdexcept>

namespace msgpack {


class zbuffer : public msgpack_zbuffer {
public:
	zbuffer(int level = Z_DEFAULT_COMPRESSION,
			size_t init_size = MSGPACK_ZBUFFER_INIT_SIZE)
	{
		if (!msgpack_zbuffer_init(this, level, init_size)) {
			throw std::bad_alloc();
		}
	}

	~zbuffer()
	{
		msgpack_zbuffer_destroy(this);
	}

public:
	void write(const char* buf, size_t len)
	{
		if(msgpack_zbuffer_write(this, buf, len) < 0) {
			throw std::bad_alloc();
		}
	}

	char* flush()
	{
		char* buf = msgpack_zbuffer_flush(this);
		if(!buf) {
			throw std::bad_alloc();
		}
		return buf;
	}

	char* data()
	{
		return base::data;
	}

	const char* data() const
	{
		return base::data;
	}

	size_t size() const
	{
		return msgpack_zbuffer_size(this);
	}

	void reset()
	{
		if(!msgpack_zbuffer_reset(this)) {
			throw std::bad_alloc();
		}
	}

	void reset_buffer()
	{
		msgpack_zbuffer_reset_buffer(this);
	}

	char* release_buffer()
	{
		return msgpack_zbuffer_release_buffer(this);
	}

private:
	typedef msgpack_zbuffer base;

private:
	zbuffer(const zbuffer&);
};


}  // namespace msgpack

#endif /* msgpack/zbuffer.hpp */

