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
#ifndef MSGPACK_TYPE_BOOL_HPP__
#define MSGPACK_TYPE_BOOL_HPP__

#include "msgpack/object.hpp"
#include <vector>

namespace msgpack {


inline bool& operator>> (object o, bool& v)
{
	if(o.type != type::BOOLEAN) { throw type_error(); }
	v = o.via.boolean;
	return v;
}

template <typename Stream>
inline packer<Stream>& operator<< (packer<Stream>& o, const bool& v)
{
	if(v) { o.pack_true(); }
	else { o.pack_false(); }
	return o;
}

inline void operator<< (object& o, bool v)
{
	o.type = type::BOOLEAN;
	o.via.boolean = v;
}

inline void operator<< (object::with_zone& o, bool v)
	{ static_cast<object&>(o) << v; }


}  // namespace msgpack

#endif /* msgpack/type/bool.hpp */

