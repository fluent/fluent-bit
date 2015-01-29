//
// MessagePack for C++ memory pool
//
// Copyright (C) 2008-2010 FURUHASHI Sadayuki
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
#ifndef MSGPACK_ZONE_HPP__
#define MSGPACK_ZONE_HPP__

#include "zone.h"
#include <cstdlib>
#include <memory>
#include <vector>


namespace msgpack {


class zone : public msgpack_zone {
public:
	zone(size_t chunk_size = MSGPACK_ZONE_CHUNK_SIZE);
	~zone();

public:
	void* malloc(size_t size);
	void* malloc_no_align(size_t size);

	void push_finalizer(void (*func)(void*), void* data);

	template <typename T>
	void push_finalizer(std::auto_ptr<T> obj);

	void clear();

	void swap(zone& o);
	static void* operator new(std::size_t size) throw(std::bad_alloc)
	{
		void* p = ::malloc(size);
		if (!p) throw std::bad_alloc();
		return p;
	}
	static void operator delete(void *p) throw()
	{
		::free(p);
	}
	
	template <typename T>
	T* allocate();
	
	template <typename T, typename A1>
	T* allocate(A1 a1);
	
	template <typename T, typename A1, typename A2>
	T* allocate(A1 a1, A2 a2);
	
	template <typename T, typename A1, typename A2, typename A3>
	T* allocate(A1 a1, A2 a2, A3 a3);
	
	template <typename T, typename A1, typename A2, typename A3, typename A4>
	T* allocate(A1 a1, A2 a2, A3 a3, A4 a4);
	
	template <typename T, typename A1, typename A2, typename A3, typename A4, typename A5>
	T* allocate(A1 a1, A2 a2, A3 a3, A4 a4, A5 a5);
	
	template <typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6>
	T* allocate(A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6);
	
	template <typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7>
	T* allocate(A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7);
	
	template <typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8>
	T* allocate(A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8);
	
	template <typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8, typename A9>
	T* allocate(A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9);
	
	template <typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8, typename A9, typename A10>
	T* allocate(A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10);
	
	template <typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8, typename A9, typename A10, typename A11>
	T* allocate(A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10, A11 a11);
	
	template <typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8, typename A9, typename A10, typename A11, typename A12>
	T* allocate(A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10, A11 a11, A12 a12);
	
	template <typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8, typename A9, typename A10, typename A11, typename A12, typename A13>
	T* allocate(A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10, A11 a11, A12 a12, A13 a13);
	
	template <typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8, typename A9, typename A10, typename A11, typename A12, typename A13, typename A14>
	T* allocate(A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10, A11 a11, A12 a12, A13 a13, A14 a14);
	
	template <typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8, typename A9, typename A10, typename A11, typename A12, typename A13, typename A14, typename A15>
	T* allocate(A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10, A11 a11, A12 a12, A13 a13, A14 a14, A15 a15);
	

private:
	void undo_malloc(size_t size);

	template <typename T>
	static void object_destructor(void* obj);

	typedef msgpack_zone base;

private:
	zone(const zone&);
};



inline zone::zone(size_t chunk_size)
{
	msgpack_zone_init(this, chunk_size);
}

inline zone::~zone()
{
	msgpack_zone_destroy(this);
}

inline void* zone::malloc(size_t size)
{
	void* ptr = msgpack_zone_malloc(this, size);
	if(!ptr) {
		throw std::bad_alloc();
	}
	return ptr;
}

inline void* zone::malloc_no_align(size_t size)
{
	void* ptr = msgpack_zone_malloc_no_align(this, size);
	if(!ptr) {
		throw std::bad_alloc();
	}
	return ptr;
}

inline void zone::push_finalizer(void (*func)(void*), void* data)
{
	if(!msgpack_zone_push_finalizer(this, func, data)) {
		throw std::bad_alloc();
	}
}

template <typename T>
inline void zone::push_finalizer(std::auto_ptr<T> obj)
{
	if(!msgpack_zone_push_finalizer(this, &zone::object_destructor<T>, obj.get())) {
		throw std::bad_alloc();
	}
	obj.release();
}

inline void zone::clear()
{
	msgpack_zone_clear(this);
}

inline void zone::swap(zone& o)
{
	msgpack_zone_swap(this, &o);
}

template <typename T>
void zone::object_destructor(void* obj)
{
	reinterpret_cast<T*>(obj)->~T();
}

inline void zone::undo_malloc(size_t size)
{
	base::chunk_list.ptr  -= size;
	base::chunk_list.free += size;
}


template <typename T>
T* zone::allocate()
{
	void* x = malloc(sizeof(T));
	if(!msgpack_zone_push_finalizer(this, &zone::object_destructor<T>, x)) {
		undo_malloc(sizeof(T));
		throw std::bad_alloc();
	}
	try {
		return new (x) T();
	} catch (...) {
		--base::finalizer_array.tail;
		undo_malloc(sizeof(T));
		throw;
	}
}

template <typename T, typename A1>
T* zone::allocate(A1 a1)
{
	void* x = malloc(sizeof(T));
	if(!msgpack_zone_push_finalizer(this, &zone::object_destructor<T>, x)) {
		undo_malloc(sizeof(T));
		throw std::bad_alloc();
	}
	try {
		return new (x) T(a1);
	} catch (...) {
		--base::finalizer_array.tail;
		undo_malloc(sizeof(T));
		throw;
	}
}

template <typename T, typename A1, typename A2>
T* zone::allocate(A1 a1, A2 a2)
{
	void* x = malloc(sizeof(T));
	if(!msgpack_zone_push_finalizer(this, &zone::object_destructor<T>, x)) {
		undo_malloc(sizeof(T));
		throw std::bad_alloc();
	}
	try {
		return new (x) T(a1, a2);
	} catch (...) {
		--base::finalizer_array.tail;
		undo_malloc(sizeof(T));
		throw;
	}
}

template <typename T, typename A1, typename A2, typename A3>
T* zone::allocate(A1 a1, A2 a2, A3 a3)
{
	void* x = malloc(sizeof(T));
	if(!msgpack_zone_push_finalizer(this, &zone::object_destructor<T>, x)) {
		undo_malloc(sizeof(T));
		throw std::bad_alloc();
	}
	try {
		return new (x) T(a1, a2, a3);
	} catch (...) {
		--base::finalizer_array.tail;
		undo_malloc(sizeof(T));
		throw;
	}
}

template <typename T, typename A1, typename A2, typename A3, typename A4>
T* zone::allocate(A1 a1, A2 a2, A3 a3, A4 a4)
{
	void* x = malloc(sizeof(T));
	if(!msgpack_zone_push_finalizer(this, &zone::object_destructor<T>, x)) {
		undo_malloc(sizeof(T));
		throw std::bad_alloc();
	}
	try {
		return new (x) T(a1, a2, a3, a4);
	} catch (...) {
		--base::finalizer_array.tail;
		undo_malloc(sizeof(T));
		throw;
	}
}

template <typename T, typename A1, typename A2, typename A3, typename A4, typename A5>
T* zone::allocate(A1 a1, A2 a2, A3 a3, A4 a4, A5 a5)
{
	void* x = malloc(sizeof(T));
	if(!msgpack_zone_push_finalizer(this, &zone::object_destructor<T>, x)) {
		undo_malloc(sizeof(T));
		throw std::bad_alloc();
	}
	try {
		return new (x) T(a1, a2, a3, a4, a5);
	} catch (...) {
		--base::finalizer_array.tail;
		undo_malloc(sizeof(T));
		throw;
	}
}

template <typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6>
T* zone::allocate(A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6)
{
	void* x = malloc(sizeof(T));
	if(!msgpack_zone_push_finalizer(this, &zone::object_destructor<T>, x)) {
		undo_malloc(sizeof(T));
		throw std::bad_alloc();
	}
	try {
		return new (x) T(a1, a2, a3, a4, a5, a6);
	} catch (...) {
		--base::finalizer_array.tail;
		undo_malloc(sizeof(T));
		throw;
	}
}

template <typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7>
T* zone::allocate(A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7)
{
	void* x = malloc(sizeof(T));
	if(!msgpack_zone_push_finalizer(this, &zone::object_destructor<T>, x)) {
		undo_malloc(sizeof(T));
		throw std::bad_alloc();
	}
	try {
		return new (x) T(a1, a2, a3, a4, a5, a6, a7);
	} catch (...) {
		--base::finalizer_array.tail;
		undo_malloc(sizeof(T));
		throw;
	}
}

template <typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8>
T* zone::allocate(A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8)
{
	void* x = malloc(sizeof(T));
	if(!msgpack_zone_push_finalizer(this, &zone::object_destructor<T>, x)) {
		undo_malloc(sizeof(T));
		throw std::bad_alloc();
	}
	try {
		return new (x) T(a1, a2, a3, a4, a5, a6, a7, a8);
	} catch (...) {
		--base::finalizer_array.tail;
		undo_malloc(sizeof(T));
		throw;
	}
}

template <typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8, typename A9>
T* zone::allocate(A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9)
{
	void* x = malloc(sizeof(T));
	if(!msgpack_zone_push_finalizer(this, &zone::object_destructor<T>, x)) {
		undo_malloc(sizeof(T));
		throw std::bad_alloc();
	}
	try {
		return new (x) T(a1, a2, a3, a4, a5, a6, a7, a8, a9);
	} catch (...) {
		--base::finalizer_array.tail;
		undo_malloc(sizeof(T));
		throw;
	}
}

template <typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8, typename A9, typename A10>
T* zone::allocate(A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10)
{
	void* x = malloc(sizeof(T));
	if(!msgpack_zone_push_finalizer(this, &zone::object_destructor<T>, x)) {
		undo_malloc(sizeof(T));
		throw std::bad_alloc();
	}
	try {
		return new (x) T(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10);
	} catch (...) {
		--base::finalizer_array.tail;
		undo_malloc(sizeof(T));
		throw;
	}
}

template <typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8, typename A9, typename A10, typename A11>
T* zone::allocate(A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10, A11 a11)
{
	void* x = malloc(sizeof(T));
	if(!msgpack_zone_push_finalizer(this, &zone::object_destructor<T>, x)) {
		undo_malloc(sizeof(T));
		throw std::bad_alloc();
	}
	try {
		return new (x) T(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11);
	} catch (...) {
		--base::finalizer_array.tail;
		undo_malloc(sizeof(T));
		throw;
	}
}

template <typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8, typename A9, typename A10, typename A11, typename A12>
T* zone::allocate(A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10, A11 a11, A12 a12)
{
	void* x = malloc(sizeof(T));
	if(!msgpack_zone_push_finalizer(this, &zone::object_destructor<T>, x)) {
		undo_malloc(sizeof(T));
		throw std::bad_alloc();
	}
	try {
		return new (x) T(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12);
	} catch (...) {
		--base::finalizer_array.tail;
		undo_malloc(sizeof(T));
		throw;
	}
}

template <typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8, typename A9, typename A10, typename A11, typename A12, typename A13>
T* zone::allocate(A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10, A11 a11, A12 a12, A13 a13)
{
	void* x = malloc(sizeof(T));
	if(!msgpack_zone_push_finalizer(this, &zone::object_destructor<T>, x)) {
		undo_malloc(sizeof(T));
		throw std::bad_alloc();
	}
	try {
		return new (x) T(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13);
	} catch (...) {
		--base::finalizer_array.tail;
		undo_malloc(sizeof(T));
		throw;
	}
}

template <typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8, typename A9, typename A10, typename A11, typename A12, typename A13, typename A14>
T* zone::allocate(A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10, A11 a11, A12 a12, A13 a13, A14 a14)
{
	void* x = malloc(sizeof(T));
	if(!msgpack_zone_push_finalizer(this, &zone::object_destructor<T>, x)) {
		undo_malloc(sizeof(T));
		throw std::bad_alloc();
	}
	try {
		return new (x) T(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14);
	} catch (...) {
		--base::finalizer_array.tail;
		undo_malloc(sizeof(T));
		throw;
	}
}

template <typename T, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6, typename A7, typename A8, typename A9, typename A10, typename A11, typename A12, typename A13, typename A14, typename A15>
T* zone::allocate(A1 a1, A2 a2, A3 a3, A4 a4, A5 a5, A6 a6, A7 a7, A8 a8, A9 a9, A10 a10, A11 a11, A12 a12, A13 a13, A14 a14, A15 a15)
{
	void* x = malloc(sizeof(T));
	if(!msgpack_zone_push_finalizer(this, &zone::object_destructor<T>, x)) {
		undo_malloc(sizeof(T));
		throw std::bad_alloc();
	}
	try {
		return new (x) T(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15);
	} catch (...) {
		--base::finalizer_array.tail;
		undo_malloc(sizeof(T));
		throw;
	}
}


}  // namespace msgpack

#endif /* msgpack/zone.hpp */

