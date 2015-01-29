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
#ifndef MSGPACK_TYPE_MAP_HPP__
#define MSGPACK_TYPE_MAP_HPP__

#include "msgpack/object.hpp"
#include <map>
#include <vector>
#include <algorithm>

namespace msgpack {


namespace type {

template <typename K, typename V>
class assoc_vector : public std::vector< std::pair<K, V> > {};

namespace detail {
	template <typename K, typename V>
	struct pair_first_less {
		bool operator() (const std::pair<K, V>& x, const std::pair<K, V>& y) const
			{ return x.first < y.first; }
	};
}

}  //namespace type


template <typename K, typename V>
inline type::assoc_vector<K,V>& operator>> (object o, type::assoc_vector<K,V>& v)
{
	if(o.type != type::MAP) { throw type_error(); }
	v.resize(o.via.map.size);
	object_kv* p = o.via.map.ptr;
	object_kv* const pend = o.via.map.ptr + o.via.map.size;
	std::pair<K, V>* it(&v.front());
	for(; p < pend; ++p, ++it) {
		p->key.convert(&it->first);
		p->val.convert(&it->second);
	}
	std::sort(v.begin(), v.end(), type::detail::pair_first_less<K,V>());
	return v;
}

template <typename Stream, typename K, typename V>
inline packer<Stream>& operator<< (packer<Stream>& o, const type::assoc_vector<K,V>& v)
{
	o.pack_map(v.size());
	for(typename type::assoc_vector<K,V>::const_iterator it(v.begin()), it_end(v.end());
			it != it_end; ++it) {
		o.pack(it->first);
		o.pack(it->second);
	}
	return o;
}

template <typename K, typename V>
inline void operator<< (object::with_zone& o, const type::assoc_vector<K,V>& v)
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
		typename type::assoc_vector<K,V>::const_iterator it(v.begin());
		do {
			p->key = object(it->first, o.zone);
			p->val = object(it->second, o.zone);
			++p;
			++it;
		} while(p < pend);
	}
}


template <typename K, typename V>
inline std::map<K, V> operator>> (object o, std::map<K, V>& v)
{
	if(o.type != type::MAP) { throw type_error(); }
	object_kv* p(o.via.map.ptr);
	object_kv* const pend(o.via.map.ptr + o.via.map.size);
	for(; p != pend; ++p) {
		K key;
		p->key.convert(&key);
		typename std::map<K,V>::iterator it(v.lower_bound(key));
		if(it != v.end() && !(key < it->first)) {
			p->val.convert(&it->second);
		} else {
			V val;
			p->val.convert(&val);
			v.insert(it, std::pair<K,V>(key, val));
		}
	}
	return v;
}

template <typename Stream, typename K, typename V>
inline packer<Stream>& operator<< (packer<Stream>& o, const std::map<K,V>& v)
{
	o.pack_map(v.size());
	for(typename std::map<K,V>::const_iterator it(v.begin()), it_end(v.end());
			it != it_end; ++it) {
		o.pack(it->first);
		o.pack(it->second);
	}
	return o;
}

template <typename K, typename V>
inline void operator<< (object::with_zone& o, const std::map<K,V>& v)
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
		typename std::map<K,V>::const_iterator it(v.begin());
		do {
			p->key = object(it->first, o.zone);
			p->val = object(it->second, o.zone);
			++p;
			++it;
		} while(p < pend);
	}
}


template <typename K, typename V>
inline std::multimap<K, V> operator>> (object o, std::multimap<K, V>& v)
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
inline packer<Stream>& operator<< (packer<Stream>& o, const std::multimap<K,V>& v)
{
	o.pack_map(v.size());
	for(typename std::multimap<K,V>::const_iterator it(v.begin()), it_end(v.end());
			it != it_end; ++it) {
		o.pack(it->first);
		o.pack(it->second);
	}
	return o;
}

template <typename K, typename V>
inline void operator<< (object::with_zone& o, const std::multimap<K,V>& v)
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
		typename std::multimap<K,V>::const_iterator it(v.begin());
		do {
			p->key = object(it->first, o.zone);
			p->val = object(it->second, o.zone);
			++p;
			++it;
		} while(p < pend);
	}
}


}  // namespace msgpack

#endif /* msgpack/type/map.hpp */

