//
// MessagePack for C++ zero-copy buffer implementation
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
#ifndef MSGPACK_VREFBUFFER_HPP__
#define MSGPACK_VREFBUFFER_HPP__

#include "vrefbuffer.h"
#include <stdexcept>

namespace msgpack {


class vrefbuffer : public msgpack_vrefbuffer {
public:
	vrefbuffer(size_t ref_size = MSGPACK_VREFBUFFER_REF_SIZE,
			size_t chunk_size = MSGPACK_VREFBUFFER_CHUNK_SIZE)
	{
		if (!msgpack_vrefbuffer_init(this, ref_size, chunk_size)) {
			throw std::bad_alloc();
		}
	}

	~vrefbuffer()
	{
		msgpack_vrefbuffer_destroy(this);
	}

public:
	void write(const char* buf, size_t len)
	{
		if(len < base::ref_size) {
			append_copy(buf, len);
		} else {
			append_ref(buf, len);
		}
	}

	void append_ref(const char* buf, size_t len)
	{
		if(msgpack_vrefbuffer_append_ref(this, buf, len) < 0) {
			throw std::bad_alloc();
		}
	}

	void append_copy(const char* buf, size_t len)
	{
		if(msgpack_vrefbuffer_append_copy(this, buf, len) < 0) {
			throw std::bad_alloc();
		}
	}

	const struct iovec* vector() const
	{
		return msgpack_vrefbuffer_vec(this);
	}

	size_t vector_size() const
	{
		return msgpack_vrefbuffer_veclen(this);
	}

	void migrate(vrefbuffer* to)
	{
		if(msgpack_vrefbuffer_migrate(this, to) < 0) {
			throw std::bad_alloc();
		}
	}

	void clear()
	{
		msgpack_vrefbuffer_clear(this);
	}

private:
	typedef msgpack_vrefbuffer base;

private:
	vrefbuffer(const vrefbuffer&);
};


}  // namespace msgpack

#endif /* msgpack/vrefbuffer.hpp */

