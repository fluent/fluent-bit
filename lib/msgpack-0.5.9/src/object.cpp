//
// MessagePack for C++ dynamic typed objects
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
#include "msgpack/object.hpp"

namespace msgpack {


std::ostream& operator<< (std::ostream& s, const object o)
{
	switch(o.type) {
	case type::NIL:
		s << "nil";
		break;

	case type::BOOLEAN:
		s << (o.via.boolean ? "true" : "false");
		break;

	case type::POSITIVE_INTEGER:
		s << o.via.u64;
		break;

	case type::NEGATIVE_INTEGER:
		s << o.via.i64;
		break;

	case type::DOUBLE:
		s << o.via.dec;
		break;

	case type::RAW:
		(s << '"').write(o.via.raw.ptr, o.via.raw.size) << '"';
		break;

	case type::ARRAY:
		s << "[";
		if(o.via.array.size != 0) {
			object* p(o.via.array.ptr);
			s << *p;
			++p;
			for(object* const pend(o.via.array.ptr + o.via.array.size);
					p < pend; ++p) {
				s << ", " << *p;
			}
		}
		s << "]";
		break;

	case type::MAP:
		s << "{";
		if(o.via.map.size != 0) {
			object_kv* p(o.via.map.ptr);
			s << p->key << "=>" << p->val;
			++p;
			for(object_kv* const pend(o.via.map.ptr + o.via.map.size);
					p < pend; ++p) {
				s << ", " << p->key << "=>" << p->val;
			}
		}
		s << "}";
		break;

	default:
		// FIXME
		s << "#<UNKNOWN " << (uint16_t)o.type << ">";
	}
	return s;
}


}  // namespace msgpack

