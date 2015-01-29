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
#ifndef MSGPACK_TYPE_FLOAT_HPP__
#define MSGPACK_TYPE_FLOAT_HPP__

#include "msgpack/object.hpp"
#include <vector>

namespace msgpack {


// FIXME check overflow, underflow


inline float& operator>> (object o, float& v)
{
	if(o.type == type::DOUBLE) {
		v = (float)o.via.dec;
	}
	else if (o.type == type::POSITIVE_INTEGER) {
		v = (float)o.via.u64;
	}
	else if (o.type == type::NEGATIVE_INTEGER) {
		v = (float)o.via.i64;
	}
	else {
		throw type_error();
	}
	return v;
}

template <typename Stream>
inline packer<Stream>& operator<< (packer<Stream>& o, const float& v)
{
	o.pack_float(v);
	return o;
}


inline double& operator>> (object o, double& v)
{
	if(o.type == type::DOUBLE) {
		v = o.via.dec;
	}
	else if (o.type == type::POSITIVE_INTEGER) {
		v = (double)o.via.u64;
	}
	else if (o.type == type::NEGATIVE_INTEGER) {
		v = (double)o.via.i64;
	}
	else {
		throw type_error();
	}
	return v;
}

template <typename Stream>
inline packer<Stream>& operator<< (packer<Stream>& o, const double& v)
{
	o.pack_double(v);
	return o;
}


inline void operator<< (object& o, float v)
{
	o.type = type::DOUBLE;
	o.via.dec = (double)v;
}

inline void operator<< (object& o, double v)
{
	o.type = type::DOUBLE;
	o.via.dec = v;
}

inline void operator<< (object::with_zone& o, float v)
	{ static_cast<object&>(o) << v; }

inline void operator<< (object::with_zone& o, double v)
	{ static_cast<object&>(o) << v; }


}  // namespace msgpack

#endif /* msgpack/type/float.hpp */

