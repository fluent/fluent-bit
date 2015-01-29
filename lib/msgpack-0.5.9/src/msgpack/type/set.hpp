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
#ifndef MSGPACK_TYPE_SET_HPP__
#define MSGPACK_TYPE_SET_HPP__

#include "msgpack/object.hpp"
#include <set>

namespace msgpack {


template <typename T>
inline std::set<T>& operator>> (object o, std::set<T>& v)
{
	if(o.type != type::ARRAY) { throw type_error(); }
	object* p = o.via.array.ptr + o.via.array.size;
	object* const pbegin = o.via.array.ptr;
	while(p > pbegin) {
		--p;
		v.insert(p->as<T>());
	}
	return v;
}

template <typename Stream, typename T>
inline packer<Stream>& operator<< (packer<Stream>& o, const std::set<T>& v)
{
	o.pack_array(v.size());
	for(typename std::set<T>::const_iterator it(v.begin()), it_end(v.end());
			it != it_end; ++it) {
		o.pack(*it);
	}
	return o;
}

template <typename T>
inline void operator<< (object::with_zone& o, const std::set<T>& v)
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
		typename std::set<T>::const_iterator it(v.begin());
		do {
			*p = object(*it, o.zone);
			++p;
			++it;
		} while(p < pend);
	}
}


template <typename T>
inline std::multiset<T>& operator>> (object o, std::multiset<T>& v)
{
	if(o.type != type::ARRAY) { throw type_error(); }
	object* p = o.via.array.ptr + o.via.array.size;
	object* const pbegin = o.via.array.ptr;
	while(p > pbegin) {
		--p;
		v.insert(p->as<T>());
	}
	return v;
}

template <typename Stream, typename T>
inline packer<Stream>& operator<< (packer<Stream>& o, const std::multiset<T>& v)
{
	o.pack_array(v.size());
	for(typename std::multiset<T>::const_iterator it(v.begin()), it_end(v.end());
			it != it_end; ++it) {
		o.pack(*it);
	}
	return o;
}

template <typename T>
inline void operator<< (object::with_zone& o, const std::multiset<T>& v)
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
		typename std::multiset<T>::const_iterator it(v.begin());
		do {
			*p = object(*it, o.zone);
			++p;
			++it;
		} while(p < pend);
	}
}


}  // namespace msgpack

#endif /* msgpack/type/set.hpp */

