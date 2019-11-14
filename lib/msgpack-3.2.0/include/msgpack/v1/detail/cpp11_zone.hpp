//
// MessagePack for C++ memory pool
//
// Copyright (C) 2008-2013 FURUHASHI Sadayuki and KONDO Takatoshi
//
//    Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//    http://www.boost.org/LICENSE_1_0.txt)
//
#ifndef MSGPACK_CPP11_ZONE_HPP
#define MSGPACK_CPP11_ZONE_HPP

#include "msgpack/versioning.hpp"
#include "msgpack/cpp_config.hpp"
#include "msgpack/zone_decl.hpp"

#include <cstdlib>
#include <memory>
#include <vector>

namespace msgpack {

/// @cond
MSGPACK_API_VERSION_NAMESPACE(v1) {
/// @endcond

class zone {
private:
    struct finalizer {
        finalizer(void (*func)(void*), void* data):m_func(func), m_data(data) {}
        void operator()() { m_func(m_data); }
        void (*m_func)(void*);
        void* m_data;
    };
    struct finalizer_array {
        finalizer_array():m_tail(MSGPACK_NULLPTR), m_end(MSGPACK_NULLPTR), m_array(MSGPACK_NULLPTR) {}
        void call() {
            finalizer* fin = m_tail;
            for(; fin != m_array; --fin) (*(fin-1))();
        }
        ~finalizer_array() {
            call();
            ::free(m_array);
        }
        void clear() {
            call();
            m_tail = m_array;
        }
        void push(void (*func)(void* data), void* data)
        {
            finalizer* fin = m_tail;

            if(fin == m_end) {
                push_expand(func, data);
                return;
            }

            fin->m_func = func;
            fin->m_data = data;

            ++m_tail;
        }
        void push_expand(void (*func)(void*), void* data) {
            const size_t nused = static_cast<size_t>(m_end - m_array);
            size_t nnext;
            if(nused == 0) {
                nnext = (sizeof(finalizer) < 72/2) ?
                    72 / sizeof(finalizer) : 8;
            } else {
                nnext = nused * 2;
            }
            finalizer* tmp =
                static_cast<finalizer*>(::realloc(m_array, sizeof(finalizer) * nnext));
            if(!tmp) {
                throw std::bad_alloc();
            }
            m_array     = tmp;
            m_end   = tmp + nnext;
            m_tail  = tmp + nused;
            new (m_tail) finalizer(func, data);

            ++m_tail;
        }
        finalizer_array(finalizer_array&& other) noexcept
            :m_tail(other.m_tail), m_end(other.m_end), m_array(other.m_array)
        {
            other.m_tail = MSGPACK_NULLPTR;
            other.m_end = MSGPACK_NULLPTR;
            other.m_array = MSGPACK_NULLPTR;
        }
        finalizer_array& operator=(finalizer_array&& other) noexcept
        {
            this->~finalizer_array();
            new (this) finalizer_array(std::move(other));
            return *this;
        }

        finalizer* m_tail;
        finalizer* m_end;
        finalizer* m_array;

    private:
        finalizer_array(const finalizer_array&);
        finalizer_array& operator=(const finalizer_array&);
    };
    struct chunk {
        chunk* m_next;
    };
    struct chunk_list {
        chunk_list(size_t chunk_size)
        {
            chunk* c = static_cast<chunk*>(::malloc(sizeof(chunk) + chunk_size));
            if(!c) {
                throw std::bad_alloc();
            }

            m_head = c;
            m_free = chunk_size;
            m_ptr  = reinterpret_cast<char*>(c) + sizeof(chunk);
            c->m_next = MSGPACK_NULLPTR;
        }
        ~chunk_list()
        {
            chunk* c = m_head;
            while(c) {
                chunk* n = c->m_next;
                ::free(c);
                c = n;
            }
        }
        void clear(size_t chunk_size)
        {
            chunk* c = m_head;
            while(true) {
                chunk* n = c->m_next;
                if(n) {
                    ::free(c);
                    c = n;
                } else {
                    m_head = c;
                    break;
                }
            }
            m_head->m_next = MSGPACK_NULLPTR;
            m_free = chunk_size;
            m_ptr  = reinterpret_cast<char*>(m_head) + sizeof(chunk);
        }
        chunk_list(chunk_list&& other) noexcept
            :m_free(other.m_free), m_ptr(other.m_ptr), m_head(other.m_head)
        {
            other.m_head = MSGPACK_NULLPTR;
        }
        chunk_list& operator=(chunk_list&& other) noexcept
        {
            this->~chunk_list();
            new (this) chunk_list(std::move(other));
            return *this;
        }

        size_t m_free;
        char* m_ptr;
        chunk* m_head;
    private:
        chunk_list(const chunk_list&);
        chunk_list& operator=(const chunk_list&);
    };
    size_t m_chunk_size;
    chunk_list m_chunk_list;
    finalizer_array m_finalizer_array;

public:
    zone(size_t chunk_size = MSGPACK_ZONE_CHUNK_SIZE) noexcept;

public:
    void* allocate_align(size_t size, size_t align = MSGPACK_ZONE_ALIGN);
    void* allocate_no_align(size_t size);

    void push_finalizer(void (*func)(void*), void* data);

    template <typename T>
    void push_finalizer(msgpack::unique_ptr<T> obj);

    void clear();

    void swap(zone& o);

    static void* operator new(std::size_t size)
    {
        void* p = ::malloc(size);
        if (!p) throw std::bad_alloc();
        return p;
    }
    static void operator delete(void *p) noexcept
    {
        ::free(p);
    }
    static void* operator new(std::size_t /*size*/, void* mem) noexcept
    {
        return mem;
    }
    static void operator delete(void * /*p*/, void* /*mem*/) noexcept
    {
    }

    template <typename T, typename... Args>
    T* allocate(Args... args);

    zone(zone&&) = default;
    zone& operator=(zone&&) = default;
    zone(const zone&) = delete;
    zone& operator=(const zone&) = delete;

private:
    void undo_allocate(size_t size);

    template <typename T>
    static void object_destruct(void* obj);

    template <typename T>
    static void object_delete(void* obj);

    static char* get_aligned(char* ptr, size_t align);

    char* allocate_expand(size_t size);
};

inline zone::zone(size_t chunk_size) noexcept:m_chunk_size(chunk_size), m_chunk_list(m_chunk_size)
{
}

inline char* zone::get_aligned(char* ptr, size_t align)
{
    return
        reinterpret_cast<char*>(
            reinterpret_cast<size_t>(
            (ptr + (align - 1))) / align * align);
}

inline void* zone::allocate_align(size_t size, size_t align)
{
    char* aligned = get_aligned(m_chunk_list.m_ptr, align);
    size_t adjusted_size = size + static_cast<size_t>(aligned - m_chunk_list.m_ptr);
    if (m_chunk_list.m_free < adjusted_size) {
        size_t enough_size = size + align - 1;
        char* ptr = allocate_expand(enough_size);
        aligned = get_aligned(ptr, align);
        adjusted_size = size + static_cast<size_t>(aligned - m_chunk_list.m_ptr);
    }
    m_chunk_list.m_free -= adjusted_size;
    m_chunk_list.m_ptr  += adjusted_size;
    return aligned;
}

inline void* zone::allocate_no_align(size_t size)
{
    char* ptr = m_chunk_list.m_ptr;
    if(m_chunk_list.m_free < size) {
        ptr = allocate_expand(size);
    }
    m_chunk_list.m_free -= size;
    m_chunk_list.m_ptr  += size;

    return ptr;
}

inline char* zone::allocate_expand(size_t size)
{
    chunk_list* const cl = &m_chunk_list;

    size_t sz = m_chunk_size;

    while(sz < size) {
        size_t tmp_sz = sz * 2;
        if (tmp_sz <= sz) {
            sz = size;
            break;
        }
        sz = tmp_sz;
    }

    chunk* c = static_cast<chunk*>(::malloc(sizeof(chunk) + sz));
    if (!c) throw std::bad_alloc();

    char* ptr = reinterpret_cast<char*>(c) + sizeof(chunk);

    c->m_next  = cl->m_head;
    cl->m_head = c;
    cl->m_free = sz;
    cl->m_ptr  = ptr;

    return ptr;
}

inline void zone::push_finalizer(void (*func)(void*), void* data)
{
    m_finalizer_array.push(func, data);
}

template <typename T>
inline void zone::push_finalizer(msgpack::unique_ptr<T> obj)
{
    m_finalizer_array.push(&zone::object_delete<T>, obj.release());
}

inline void zone::clear()
{
    m_finalizer_array.clear();
    m_chunk_list.clear(m_chunk_size);
}

inline void zone::swap(zone& o)
{
    std::swap(*this, o);
}

template <typename T>
void zone::object_delete(void* obj)
{
    delete static_cast<T*>(obj);
}

template <typename T>
void zone::object_destruct(void* obj)
{
    static_cast<T*>(obj)->~T();
}

inline void zone::undo_allocate(size_t size)
{
    m_chunk_list.m_ptr  -= size;
    m_chunk_list.m_free += size;
}


template <typename T, typename... Args>
T* zone::allocate(Args... args)
{
    void* x = allocate_align(sizeof(T), MSGPACK_ZONE_ALIGNOF(T));
    try {
        m_finalizer_array.push(&zone::object_destruct<T>, x);
    } catch (...) {
        undo_allocate(sizeof(T));
        throw;
    }
    try {
        return new (x) T(args...);
    } catch (...) {
        --m_finalizer_array.m_tail;
        undo_allocate(sizeof(T));
        throw;
    }
}

inline std::size_t aligned_size(
    std::size_t size,
    std::size_t align) {
    return (size + align - 1) / align * align;
}

/// @cond
}  // MSGPACK_API_VERSION_NAMESPACE(v1)
/// @endcond

}  // namespace msgpack

#endif // MSGPACK_CPP11_ZONE_HPP
