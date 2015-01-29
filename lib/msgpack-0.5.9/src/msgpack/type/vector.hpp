//
// MessagePack for C++ static resolution routine
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
#ifndef MSGPACK_TYPE_VECTOR_HPP__
#define MSGPACK_TYPE_VECTOR_HPP__

#include "msgpack/object.hpp"
#include <vector>

namespace msgpack {


template <typename T>
inline std::vector<T>& operator>> (object o, std::vector<T>& v)
{
	if(o.type != type::ARRAY) { throw type_error(); }
	v.resize(o.via.array.size);
	if(o.via.array.size > 0) {
		object* p = o.via.array.ptr;
		object* const pend = o.via.array.ptr + o.via.array.size;
		T* it = &v[0];
		do {
			p->convert(it);
			++p;
			++it;
		} while(p < pend);
	}
	return v;
}

template <typename Stream, typename T>
inline packer<Stream>& operator<< (packer<Stream>& o, const std::vector<T>& v)
{
	o.pack_array(v.size());
	for(typename std::vector<T>::const_iterator it(v.begin()), it_end(v.end());
			it != it_end; ++it) {
		o.pack(*it);
	}
	return o;
}

template <typename T>
inline void operator<< (object::with_zone& o, const std::vector<T>& v)
{
	o.type = type::ARRAY;
	if(v.empty()) {
		o.via.array.ptr = NULL;
		o.via.array.size = 0;
	} else {
		object* p = (object*)o.zone->malloc(sizeof(object)*v.size());
		object* const pend = p + v.size();
		o.via.array.ptr = p;
		o.via.array.size = v.size();
		typename std::vector<T>::const_iterator it(v.begin());
		do {
			*p = object(*it, o.zone);
			++p;
			++it;
		} while(p < pend);
	}
}


}  // namespace msgpack

#endif /* msgpack/type/vector.hpp */

