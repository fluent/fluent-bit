//
// MessagePack for C++ simple buffer implementation
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
#ifndef MSGPACK_SBUFFER_HPP__
#define MSGPACK_SBUFFER_HPP__

#include "sbuffer.h"
#include <stdexcept>

namespace msgpack {


class sbuffer : public msgpack_sbuffer {
public:
	sbuffer(size_t initsz = MSGPACK_SBUFFER_INIT_SIZE)
	{
		if(initsz == 0) {
			base::data = NULL;
		} else {
			base::data = (char*)::malloc(initsz);
			if(!base::data) {
				throw std::bad_alloc();
			}
		}

		base::size = 0;
		base::alloc = initsz;
	}

	~sbuffer()
	{
		::free(base::data);
	}

public:
	void write(const char* buf, size_t len)
	{
		if(base::alloc - base::size < len) {
			expand_buffer(len);
		}
		memcpy(base::data + base::size, buf, len);
		base::size += len;
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
		return base::size;
	}

	char* release()
	{
		return msgpack_sbuffer_release(this);
	}

	void clear()
	{
		msgpack_sbuffer_clear(this);
	}

private:
	void expand_buffer(size_t len)
	{
		size_t nsize = (base::alloc > 0) ?
				base::alloc * 2 : MSGPACK_SBUFFER_INIT_SIZE;
	
		while(nsize < base::size + len) { nsize *= 2; }
	
		void* tmp = realloc(base::data, nsize);
		if(!tmp) {
			throw std::bad_alloc();
		}
	
		base::data = (char*)tmp;
		base::alloc = nsize;
	}

private:
	typedef msgpack_sbuffer base;

private:
	sbuffer(const sbuffer&);
};


}  // namespace msgpack

#endif /* msgpack/sbuffer.hpp */

