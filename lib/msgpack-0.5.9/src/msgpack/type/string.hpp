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
#ifndef MSGPACK_TYPE_STRING_HPP__
#define MSGPACK_TYPE_STRING_HPP__

#include "msgpack/object.hpp"
#include <string>

namespace msgpack {


inline std::string& operator>> (object o, std::string& v)
{
	if(o.type != type::RAW) { throw type_error(); }
	v.assign(o.via.raw.ptr, o.via.raw.size);
	return v;
}

template <typename Stream>
inline packer<Stream>& operator<< (packer<Stream>& o, const std::string& v)
{
	o.pack_raw(v.size());
	o.pack_raw_body(v.data(), v.size());
	return o;
}

inline void operator<< (object::with_zone& o, const std::string& v)
{
	o.type = type::RAW;
	char* ptr = (char*)o.zone->malloc(v.size());
	o.via.raw.ptr = ptr;
	o.via.raw.size = (uint32_t)v.size();
	memcpy(ptr, v.data(), v.size());
}

inline void operator<< (object& o, const std::string& v)
{
	o.type = type::RAW;
	o.via.raw.ptr = v.data();
	o.via.raw.size = (uint32_t)v.size();
}


}  // namespace msgpack

#endif /* msgpack/type/string.hpp */

