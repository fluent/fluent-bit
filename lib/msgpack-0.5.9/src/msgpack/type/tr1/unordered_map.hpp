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
#ifndef MSGPACK_TYPE_TR1_UNORDERED_MAP_HPP__
#define MSGPACK_TYPE_TR1_UNORDERED_MAP_HPP__

#include "msgpack/object.hpp"

#if defined(_LIBCPP_VERSION) || (_MSC_VER >= 1700)

#define MSGPACK_HAS_STD_UNOURDERED_MAP
#include <unordered_map>
#define MSGPACK_STD_TR1 std

#else   // defined(_LIBCPP_VERSION) || (_MSC_VER >= 1700)

#if __GNUC__ >= 4

#define MSGPACK_HAS_STD_TR1_UNOURDERED_MAP

#include <tr1/unordered_map>
#define MSGPACK_STD_TR1 std::tr1

#endif // __GNUC__ >= 4

#endif  // defined(_LIBCPP_VERSION) || (_MSC_VER >= 1700)


namespace msgpack {


template <typename K, typename V>
inline MSGPACK_STD_TR1::unordered_map<K, V> operator>> (object o, MSGPACK_STD_TR1::unordered_map<K, V>& v)
{
	if(o.type != type::MAP) { throw type_error(); }
	object_kv* p(o.via.map.ptr);
	object_kv* const pend(o.via.map.ptr + o.via.map.size);
	for(; p != pend; ++p) {
		K key;
		p->key.convert(&key);
		p->val.convert(&v[key]);
	}
	return v;
}

template <typename Stream, typename K, typename V>
inline packer<Stream>& operator<< (packer<Stream>& o, const MSGPACK_STD_TR1::unordered_map<K,V>& v)
{
	o.pack_map(v.size());
	for(typename MSGPACK_STD_TR1::unordered_map<K,V>::const_iterator it(v.begin()), it_end(v.end());
			it != it_end; ++it) {
		o.pack(it->first);
		o.pack(it->second);
	}
	return o;
}

template <typename K, typename V>
inline void operator<< (object::with_zone& o, const MSGPACK_STD_TR1::unordered_map<K,V>& v)
{
	o.type = type::MAP;
	if(v.empty()) {
		o.via.map.ptr  = NULL;
		o.via.map.size = 0;
	} else {
		object_kv* p = (object_kv*)o.zone->malloc(sizeof(object_kv)*v.size());
		object_kv* const pend = p + v.size();
		o.via.map.ptr  = p;
		o.via.map.size = v.size();
		typename MSGPACK_STD_TR1::unordered_map<K,V>::const_iterator it(v.begin());
		do {
			p->key = object(it->first, o.zone);
			p->val = object(it->second, o.zone);
			++p;
			++it;
		} while(p < pend);
	}
}


template <typename K, typename V>
inline MSGPACK_STD_TR1::unordered_multimap<K, V> operator>> (object o, MSGPACK_STD_TR1::unordered_multimap<K, V>& v)
{
	if(o.type != type::MAP) { throw type_error(); }
	object_kv* p(o.via.map.ptr);
	object_kv* const pend(o.via.map.ptr + o.via.map.size);
	for(; p != pend; ++p) {
		std::pair<K, V> value;
		p->key.convert(&value.first);
		p->val.convert(&value.second);
		v.insert(value);
	}
	return v;
}

template <typename Stream, typename K, typename V>
inline packer<Stream>& operator<< (packer<Stream>& o, const MSGPACK_STD_TR1::unordered_multimap<K,V>& v)
{
	o.pack_map(v.size());
	for(typename MSGPACK_STD_TR1::unordered_multimap<K,V>::const_iterator it(v.begin()), it_end(v.end());
			it != it_end; ++it) {
		o.pack(it->first);
		o.pack(it->second);
	}
	return o;
}

template <typename K, typename V>
inline void operator<< (object::with_zone& o, const MSGPACK_STD_TR1::unordered_multimap<K,V>& v)
{
	o.type = type::MAP;
	if(v.empty()) {
		o.via.map.ptr  = NULL;
		o.via.map.size = 0;
	} else {
		object_kv* p = (object_kv*)o.zone->malloc(sizeof(object_kv)*v.size());
		object_kv* const pend = p + v.size();
		o.via.map.ptr  = p;
		o.via.map.size = v.size();
		typename MSGPACK_STD_TR1::unordered_multimap<K,V>::const_iterator it(v.begin());
		do {
			p->key = object(it->first, o.zone);
			p->val = object(it->second, o.zone);
			++p;
			++it;
		} while(p < pend);
	}
}


}  // namespace msgpack

#undef MSGPACK_STD_TR1

#endif /* msgpack/type/map.hpp */

