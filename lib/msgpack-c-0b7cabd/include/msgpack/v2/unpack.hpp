//
// MessagePack for C++ deserializing routine
//
// Copyright (C) 2016 KONDO Takatoshi
//
//    Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//    http://www.boost.org/LICENSE_1_0.txt)
//
#ifndef MSGPACK_V2_UNPACK_HPP
#define MSGPACK_V2_UNPACK_HPP

#include "msgpack/unpack_decl.hpp"

namespace msgpack {

/// @cond
MSGPACK_API_VERSION_NAMESPACE(v2) {
/// @endcond

struct null_visitor {
    bool visit_nil() {
        return true;
    }
    bool visit_boolean(bool /*v*/) {
        return true;
    }
    bool visit_positive_integer(uint64_t /*v*/) {
        return true;
    }
    bool visit_negative_integer(int64_t /*v*/) {
        return true;
    }
    bool visit_float(double /*v*/) {
        return true;
    }
    bool visit_str(const char* /*v*/, uint32_t /*size*/) {
        return true;
    }
    bool visit_bin(const char* /*v*/, uint32_t /*size*/) {
        return true;
    }
    bool visit_ext(const char* /*v*/, uint32_t /*size*/) {
        return true;
    }
    bool start_array(uint32_t /*num_elements*/) {
        return true;
    }
    bool start_array_item() {
        return true;
    }
    bool end_array_item() {
        return true;
    }
    bool end_array() {
        return true;
    }
    bool start_map(uint32_t /*num_kv_pairs*/) {
        return true;
    }
    bool start_map_key() {
        return true;
    }
    bool end_map_key() {
        return true;
    }
    bool start_map_value() {
        return true;
    }
    bool end_map_value() {
        return true;
    }
    bool end_map() {
        return true;
    }
    void parse_error(size_t /*parsed_offset*/, size_t /*error_offset*/) {
    }
    void insufficient_bytes(size_t /*parsed_offset*/, size_t /*error_offset*/) {
    }
};

namespace detail {

class create_object_visitor {
public:
    create_object_visitor(unpack_reference_func f, void* user_data, unpack_limit const& limit)
        :m_func(f), m_user_data(user_data), m_limit(limit) {
        m_stack.reserve(MSGPACK_EMBED_STACK_SIZE);
        m_stack.push_back(&m_obj);
    }

#if !defined(MSGPACK_USE_CPP03)
    create_object_visitor(create_object_visitor&& other)
        :m_func(other.m_func),
         m_user_data(other.m_user_data),
         m_limit(std::move(other.m_limit)),
         m_stack(std::move(other.m_stack)),
         m_zone(other.m_zone),
         m_referenced(other.m_referenced) {
        other.m_zone = MSGPACK_NULLPTR;
        m_stack[0] = &m_obj;
    }
    create_object_visitor& operator=(create_object_visitor&& other) {
        this->~create_object_visitor();
        new (this) create_object_visitor(std::move(other));
        return *this;
    }
#endif // !defined(MSGPACK_USE_CPP03)

    void init() {
        m_stack.resize(1);
        m_obj = msgpack::object();
        m_stack[0] = &m_obj;
    }
    msgpack::object const& data() const
    {
        return m_obj;
    }
    msgpack::zone const& zone() const { return *m_zone; }
    msgpack::zone& zone() { return *m_zone; }
    void set_zone(msgpack::zone& zone) { m_zone = &zone; }
    bool referenced() const { return m_referenced; }
    void set_referenced(bool referenced) { m_referenced = referenced; }
    // visit functions
    bool visit_nil() {
        msgpack::object* obj = m_stack.back();
        obj->type = msgpack::type::NIL;
        return true;
    }
    bool visit_boolean(bool v) {
        msgpack::object* obj = m_stack.back();
        obj->type = msgpack::type::BOOLEAN;
        obj->via.boolean = v;
        return true;
    }
    bool visit_positive_integer(uint64_t v) {
        msgpack::object* obj = m_stack.back();
        obj->type = msgpack::type::POSITIVE_INTEGER;
        obj->via.u64 = v;
        return true;
    }
    bool visit_negative_integer(int64_t v) {
        msgpack::object* obj = m_stack.back();
        if(v >= 0) {
            obj->type = msgpack::type::POSITIVE_INTEGER;
            obj->via.u64 = v;
        }
        else {
            obj->type = msgpack::type::NEGATIVE_INTEGER;
            obj->via.i64 = v;
        }
        return true;
    }
    bool visit_float(double v) {
        msgpack::object* obj = m_stack.back();
        obj->type = msgpack::type::FLOAT;
        obj->via.f64 = v;
        return true;
    }
    bool visit_str(const char* v, uint32_t size) {
        if (size > m_limit.str()) throw msgpack::str_size_overflow("str size overflow");
        msgpack::object* obj = m_stack.back();
        obj->type = msgpack::type::STR;
        if (m_func && m_func(obj->type, size, m_user_data)) {
            obj->via.str.ptr = v;
            set_referenced(true);
        }
        else {
            char* tmp = static_cast<char*>(zone().allocate_align(size));
            std::memcpy(tmp, v, size);
            obj->via.str.ptr = tmp;
        }
        obj->via.str.size = size;
        return true;
    }
    bool visit_bin(const char* v, uint32_t size) {
        if (size > m_limit.bin()) throw msgpack::bin_size_overflow("bin size overflow");
        msgpack::object* obj = m_stack.back();
        obj->type = msgpack::type::BIN;
        if (m_func && m_func(obj->type, size, m_user_data)) {
            obj->via.bin.ptr = v;
            set_referenced(true);
        }
        else {
            char* tmp = static_cast<char*>(zone().allocate_align(size));
            std::memcpy(tmp, v, size);
            obj->via.bin.ptr = tmp;
        }
        obj->via.bin.size = size;
        return true;
    }
    bool visit_ext(const char* v, uint32_t size) {
        if (size > m_limit.ext()) throw msgpack::ext_size_overflow("ext size overflow");
        msgpack::object* obj = m_stack.back();
        obj->type = msgpack::type::EXT;
        if (m_func && m_func(obj->type, size, m_user_data)) {
            obj->via.ext.ptr = v;
            set_referenced(true);
        }
        else {
            char* tmp = static_cast<char*>(zone().allocate_align(size));
            std::memcpy(tmp, v, size);
            obj->via.ext.ptr = tmp;
        }
        obj->via.ext.size = static_cast<uint32_t>(size - 1);
        return true;
    }
    bool start_array(uint32_t num_elements) {
        if (num_elements > m_limit.array()) throw msgpack::array_size_overflow("array size overflow");
        if (m_stack.size() > m_limit.depth()) throw msgpack::depth_size_overflow("depth size overflow");
        msgpack::object* obj = m_stack.back();
        obj->type = msgpack::type::ARRAY;
        obj->via.array.size = num_elements;
        if (num_elements == 0) {
            obj->via.array.ptr = MSGPACK_NULLPTR;
        }
        else {
            obj->via.array.ptr =
                static_cast<msgpack::object*>(m_zone->allocate_align(num_elements*sizeof(msgpack::object)));
        }
        m_stack.push_back(obj->via.array.ptr);
        return true;
    }
    bool start_array_item() {
        return true;
    }
    bool end_array_item() {
        ++m_stack.back();
        return true;
    }
    bool end_array() {
        m_stack.pop_back();
        return true;
    }
    bool start_map(uint32_t num_kv_pairs) {
        if (num_kv_pairs > m_limit.map()) throw msgpack::map_size_overflow("map size overflow");
        if (m_stack.size() > m_limit.depth()) throw msgpack::depth_size_overflow("depth size overflow");
        msgpack::object* obj = m_stack.back();
        obj->type = msgpack::type::MAP;
        obj->via.map.size = num_kv_pairs;
        if (num_kv_pairs == 0) {
            obj->via.map.ptr = MSGPACK_NULLPTR;
        }
        else {
            obj->via.map.ptr =
                static_cast<msgpack::object_kv*>(m_zone->allocate_align(num_kv_pairs*sizeof(msgpack::object_kv)));
        }
        m_stack.push_back(reinterpret_cast<msgpack::object*>(obj->via.map.ptr));
        return true;
    }
    bool start_map_key() {
        return true;
    }
    bool end_map_key() {
        ++m_stack.back();
        return true;
    }
    bool start_map_value() {
        return true;
    }
    bool end_map_value() {
        ++m_stack.back();
        return true;
    }
    bool end_map() {
        m_stack.pop_back();
        return true;
    }
    void parse_error(size_t /*parsed_offset*/, size_t /*error_offset*/) {
        throw msgpack::parse_error("parse error");
    }
    void insufficient_bytes(size_t /*parsed_offset*/, size_t /*error_offset*/) {
        throw msgpack::insufficient_bytes("insufficient bytes");
    }
private:
public:
    unpack_reference_func m_func;
    void* m_user_data;
    unpack_limit m_limit;
    msgpack::object m_obj;
    std::vector<msgpack::object*> m_stack;
    msgpack::zone* m_zone;
    bool m_referenced;
};

template <typename VisitorHolder>
class context {
public:
    context()
        :m_trail(0), m_cs(MSGPACK_CS_HEADER)
    {
    }

    void init()
    {
        m_cs = MSGPACK_CS_HEADER;
        m_trail = 0;
        m_stack.clear();
        holder().visitor().init();
    }

    unpack_return execute(const char* data, std::size_t len, std::size_t& off);

private:
    template <typename T>
    static uint32_t next_cs(T p)
    {
        return static_cast<uint32_t>(*p) & 0x1f;
    }

    VisitorHolder& holder() {
        return static_cast<VisitorHolder&>(*this);
    }

    template <typename T, typename StartVisitor, typename EndVisitor>
    unpack_return start_aggregate(
        StartVisitor const& sv,
        EndVisitor const& ev,
        const char* load_pos,
        std::size_t& off) {
        typename value<T>::type size;
        load<T>(size, load_pos);
        ++m_current;
        if (size == 0) {
            if (!sv(size)) {
                off = m_current - m_start;
                return UNPACK_STOP_VISITOR;
            }
            if (!ev()) {
                off = m_current - m_start;
                return UNPACK_STOP_VISITOR;
            }
            unpack_return ret = m_stack.consume(holder());
            if (ret != UNPACK_CONTINUE) {
                off = m_current - m_start;
                return ret;
            }
        }
        else {
            m_stack.push(sv.type(), static_cast<uint32_t>(size));
            if (!sv(size)) {
                off = m_current - m_start;
                return UNPACK_STOP_VISITOR;
            }
        }
        m_cs = MSGPACK_CS_HEADER;
        return UNPACK_CONTINUE;
    }

    unpack_return after_visit_proc(bool visit_result, std::size_t& off) {
        ++m_current;
        if (!visit_result) {
            off = m_current - m_start;
            return UNPACK_STOP_VISITOR;
        }
        unpack_return ret = m_stack.consume(holder());
        if (ret == UNPACK_CONTINUE) {
            m_cs = MSGPACK_CS_HEADER;
        }
        else {
            off = m_current - m_start;
        }
        return ret;
    }

    struct array_sv {
        array_sv(VisitorHolder& visitor_holder):m_visitor_holder(visitor_holder) {}
        bool operator()(uint32_t size) const {
            return m_visitor_holder.visitor().start_array(size);
        }
        msgpack_container_type type() const { return MSGPACK_CT_ARRAY_ITEM; }
    private:
        VisitorHolder& m_visitor_holder;
    };
    struct array_ev {
        array_ev(VisitorHolder& visitor_holder):m_visitor_holder(visitor_holder) {}
        bool operator()() const {
            return m_visitor_holder.visitor().end_array();
        }
    private:
        VisitorHolder& m_visitor_holder;
    };
    struct map_sv {
        map_sv(VisitorHolder& visitor_holder):m_visitor_holder(visitor_holder) {}
        bool operator()(uint32_t size) const {
            return m_visitor_holder.visitor().start_map(size);
        }
        msgpack_container_type type() const { return MSGPACK_CT_MAP_KEY; }
    private:
        VisitorHolder& m_visitor_holder;
    };
    struct map_ev {
        map_ev(VisitorHolder& visitor_holder):m_visitor_holder(visitor_holder) {}
        bool operator()() const {
            return m_visitor_holder.visitor().end_map();
        }
    private:
        VisitorHolder& m_visitor_holder;
    };

    struct unpack_stack {
        struct stack_elem {
            stack_elem(msgpack_container_type type, uint32_t rest):m_type(type), m_rest(rest) {}
            msgpack_container_type m_type;
            uint32_t m_rest;
        };
        unpack_stack() {
            m_stack.reserve(MSGPACK_EMBED_STACK_SIZE);
        }
        void push(msgpack_container_type type, uint32_t rest) {
            m_stack.push_back(stack_elem(type, rest));
        }
        unpack_return consume(VisitorHolder& visitor_holder) {
            while (!m_stack.empty()) {
                stack_elem& e = m_stack.back();
                switch (e.m_type) {
                case MSGPACK_CT_ARRAY_ITEM:
                    if (!visitor_holder.visitor().end_array_item()) return UNPACK_STOP_VISITOR;
                    if (--e.m_rest == 0)  {
                        m_stack.pop_back();
                        if (!visitor_holder.visitor().end_array()) return UNPACK_STOP_VISITOR;
                    }
                    else {
                        if (!visitor_holder.visitor().start_array_item()) return UNPACK_STOP_VISITOR;
                        return UNPACK_CONTINUE;
                    }
                    break;
                case MSGPACK_CT_MAP_KEY:
                    if (!visitor_holder.visitor().end_map_key()) return UNPACK_STOP_VISITOR;
                    if (!visitor_holder.visitor().start_map_value()) return UNPACK_STOP_VISITOR;
                    e.m_type = MSGPACK_CT_MAP_VALUE;
                    return UNPACK_CONTINUE;
                case MSGPACK_CT_MAP_VALUE:
                    if (!visitor_holder.visitor().end_map_value()) return UNPACK_STOP_VISITOR;
                    if (--e.m_rest == 0) {
                        m_stack.pop_back();
                        if (!visitor_holder.visitor().end_map()) return UNPACK_STOP_VISITOR;
                    }
                    else {
                        e.m_type = MSGPACK_CT_MAP_KEY;
                        if (!visitor_holder.visitor().start_map_key()) return UNPACK_STOP_VISITOR;
                        return UNPACK_CONTINUE;
                    }
                    break;
                }
            }
            return UNPACK_SUCCESS;
        }
        bool empty() const { return m_stack.empty(); }
        void clear() { m_stack.clear(); }
    private:
        std::vector<stack_elem> m_stack;
    };

    char const* m_start;
    char const* m_current;

    std::size_t m_trail;
    uint32_t m_cs;
    uint32_t m_num_elements;
    unpack_stack m_stack;
};

template <std::size_t N>
inline void check_ext_size(std::size_t /*size*/) {
}

template <>
inline void check_ext_size<4>(std::size_t size) {
    if (size == 0xffffffff) throw msgpack::ext_size_overflow("ext size overflow");
}

template <typename VisitorHolder>
inline unpack_return context<VisitorHolder>::execute(const char* data, std::size_t len, std::size_t& off)
{
    assert(len >= off);

    m_start = data;
    m_current = data + off;
    const char* const pe = data + len;
    const char* n = MSGPACK_NULLPTR;

    msgpack::object obj;

    if(m_current == pe) {
        off = m_current - m_start;
        return UNPACK_CONTINUE;
    }
    bool fixed_trail_again = false;
    do {
        if (m_cs == MSGPACK_CS_HEADER) {
            fixed_trail_again = false;
            int selector = *reinterpret_cast<const unsigned char*>(m_current);
            if (0x00 <= selector && selector <= 0x7f) { // Positive Fixnum
                uint8_t tmp = *reinterpret_cast<const uint8_t*>(m_current);
                bool visret = holder().visitor().visit_positive_integer(tmp);
                unpack_return upr = after_visit_proc(visret, off);
                if (upr != UNPACK_CONTINUE) return upr;
            } else if(0xe0 <= selector && selector <= 0xff) { // Negative Fixnum
                int8_t tmp = *reinterpret_cast<const int8_t*>(m_current);
                bool visret = holder().visitor().visit_negative_integer(tmp);
                unpack_return upr = after_visit_proc(visret, off);
                if (upr != UNPACK_CONTINUE) return upr;
            } else if (0xc4 <= selector && selector <= 0xdf) {
                const uint32_t trail[] = {
                    1, // bin     8  0xc4
                    2, // bin    16  0xc5
                    4, // bin    32  0xc6
                    1, // ext     8  0xc7
                    2, // ext    16  0xc8
                    4, // ext    32  0xc9
                    4, // float  32  0xca
                    8, // float  64  0xcb
                    1, // uint    8  0xcc
                    2, // uint   16  0xcd
                    4, // uint   32  0xce
                    8, // uint   64  0xcf
                    1, // int     8  0xd0
                    2, // int    16  0xd1
                    4, // int    32  0xd2
                    8, // int    64  0xd3
                    2, // fixext  1  0xd4
                    3, // fixext  2  0xd5
                    5, // fixext  4  0xd6
                    9, // fixext  8  0xd7
                    17,// fixext 16  0xd8
                    1, // str     8  0xd9
                    2, // str    16  0xda
                    4, // str    32  0xdb
                    2, // array  16  0xdc
                    4, // array  32  0xdd
                    2, // map    16  0xde
                    4, // map    32  0xdf
                };
                m_trail = trail[selector - 0xc4];
                m_cs = next_cs(m_current);
                fixed_trail_again = true;
            } else if(0xa0 <= selector && selector <= 0xbf) { // FixStr
                m_trail = static_cast<uint32_t>(*m_current) & 0x1f;
                if(m_trail == 0) {
                    bool visret = holder().visitor().visit_str(n, static_cast<uint32_t>(m_trail));
                    unpack_return upr = after_visit_proc(visret, off);
                    if (upr != UNPACK_CONTINUE) return upr;
                }
                else {
                    m_cs = MSGPACK_ACS_STR_VALUE;
                    fixed_trail_again = true;
                }
            } else if(0x90 <= selector && selector <= 0x9f) { // FixArray
                unpack_return ret = start_aggregate<fix_tag>(array_sv(holder()), array_ev(holder()), m_current, off);
                if (ret != UNPACK_CONTINUE) return ret;
                if (!holder().visitor().start_array_item()) return UNPACK_STOP_VISITOR;
            } else if(0x80 <= selector && selector <= 0x8f) { // FixMap
                unpack_return ret = start_aggregate<fix_tag>(map_sv(holder()), map_ev(holder()), m_current, off);
                if (ret != UNPACK_CONTINUE) return ret;
                if (!holder().visitor().start_map_key()) return UNPACK_STOP_VISITOR;
            } else if(selector == 0xc2) { // false
                bool visret = holder().visitor().visit_boolean(false);
                unpack_return upr = after_visit_proc(visret, off);
                if (upr != UNPACK_CONTINUE) return upr;
            } else if(selector == 0xc3) { // true
                bool visret = holder().visitor().visit_boolean(true);
                unpack_return upr = after_visit_proc(visret, off);
                if (upr != UNPACK_CONTINUE) return upr;
            } else if(selector == 0xc0) { // nil
                bool visret = holder().visitor().visit_nil();
                unpack_return upr = after_visit_proc(visret, off);
                if (upr != UNPACK_CONTINUE) return upr;
            } else {
                off = m_current - m_start;
                holder().visitor().parse_error(off - 1, off);
                return UNPACK_PARSE_ERROR;
            }
            // end MSGPACK_CS_HEADER
        }
        if (m_cs != MSGPACK_CS_HEADER || fixed_trail_again) {
            if (fixed_trail_again) {
                ++m_current;
                fixed_trail_again = false;
            }
            if(static_cast<std::size_t>(pe - m_current) < m_trail) {
                off = m_current - m_start;
                return UNPACK_CONTINUE;
            }
            n = m_current;
            m_current += m_trail - 1;
            switch(m_cs) {
                //case MSGPACK_CS_
                //case MSGPACK_CS_
            case MSGPACK_CS_FLOAT: {
                union { uint32_t i; float f; } mem;
                load<uint32_t>(mem.i, n);
                bool visret = holder().visitor().visit_float(mem.f);
                unpack_return upr = after_visit_proc(visret, off);
                if (upr != UNPACK_CONTINUE) return upr;
            } break;
            case MSGPACK_CS_DOUBLE: {
                union { uint64_t i; double f; } mem;
                load<uint64_t>(mem.i, n);
#if defined(TARGET_OS_IPHONE)
                // ok
#elif defined(__arm__) && !(__ARM_EABI__) // arm-oabi
                // https://github.com/msgpack/msgpack-perl/pull/1
                mem.i = (mem.i & 0xFFFFFFFFUL) << 32UL | (mem.i >> 32UL);
#endif
                bool visret = holder().visitor().visit_float(mem.f);
                unpack_return upr = after_visit_proc(visret, off);
                if (upr != UNPACK_CONTINUE) return upr;
            } break;
            case MSGPACK_CS_UINT_8: {
                uint8_t tmp;
                load<uint8_t>(tmp, n);
                bool visret = holder().visitor().visit_positive_integer(tmp);
                unpack_return upr = after_visit_proc(visret, off);
                if (upr != UNPACK_CONTINUE) return upr;
            } break;
            case MSGPACK_CS_UINT_16: {
                uint16_t tmp;
                load<uint16_t>(tmp, n);
                bool visret = holder().visitor().visit_positive_integer(tmp);
                unpack_return upr = after_visit_proc(visret, off);
                if (upr != UNPACK_CONTINUE) return upr;
            } break;
            case MSGPACK_CS_UINT_32: {
                uint32_t tmp;
                load<uint32_t>(tmp, n);
                bool visret = holder().visitor().visit_positive_integer(tmp);
                unpack_return upr = after_visit_proc(visret, off);
                if (upr != UNPACK_CONTINUE) return upr;
            } break;
            case MSGPACK_CS_UINT_64: {
                uint64_t tmp;
                load<uint64_t>(tmp, n);
                bool visret = holder().visitor().visit_positive_integer(tmp);
                unpack_return upr = after_visit_proc(visret, off);
                if (upr != UNPACK_CONTINUE) return upr;
            } break;
            case MSGPACK_CS_INT_8: {
                int8_t tmp;
                load<int8_t>(tmp, n);
                bool visret = holder().visitor().visit_negative_integer(tmp);
                unpack_return upr = after_visit_proc(visret, off);
                if (upr != UNPACK_CONTINUE) return upr;
            } break;
            case MSGPACK_CS_INT_16: {
                int16_t tmp;
                load<int16_t>(tmp, n);
                bool visret = holder().visitor().visit_negative_integer(tmp);
                unpack_return upr = after_visit_proc(visret, off);
                if (upr != UNPACK_CONTINUE) return upr;
            } break;
            case MSGPACK_CS_INT_32: {
                int32_t tmp;
                load<int32_t>(tmp, n);
                bool visret = holder().visitor().visit_negative_integer(tmp);
                unpack_return upr = after_visit_proc(visret, off);
                if (upr != UNPACK_CONTINUE) return upr;
            } break;
            case MSGPACK_CS_INT_64: {
                int64_t tmp;
                load<int64_t>(tmp, n);
                bool visret = holder().visitor().visit_negative_integer(tmp);
                unpack_return upr = after_visit_proc(visret, off);
                if (upr != UNPACK_CONTINUE) return upr;
            } break;
            case MSGPACK_CS_FIXEXT_1: {
                bool visret = holder().visitor().visit_ext(n, 1+1);
                unpack_return upr = after_visit_proc(visret, off);
                if (upr != UNPACK_CONTINUE) return upr;
            } break;
            case MSGPACK_CS_FIXEXT_2: {
                bool visret = holder().visitor().visit_ext(n, 2+1);
                unpack_return upr = after_visit_proc(visret, off);
                if (upr != UNPACK_CONTINUE) return upr;
            } break;
            case MSGPACK_CS_FIXEXT_4: {
                bool visret = holder().visitor().visit_ext(n, 4+1);
                unpack_return upr = after_visit_proc(visret, off);
                if (upr != UNPACK_CONTINUE) return upr;
            } break;
            case MSGPACK_CS_FIXEXT_8: {
                bool visret = holder().visitor().visit_ext(n, 8+1);
                unpack_return upr = after_visit_proc(visret, off);
                if (upr != UNPACK_CONTINUE) return upr;
            } break;
            case MSGPACK_CS_FIXEXT_16: {
                bool visret = holder().visitor().visit_ext(n, 16+1);
                unpack_return upr = after_visit_proc(visret, off);
                if (upr != UNPACK_CONTINUE) return upr;
            } break;
            case MSGPACK_CS_STR_8: {
                uint8_t tmp;
                load<uint8_t>(tmp, n);
                m_trail = tmp;
                if(m_trail == 0) {
                    bool visret = holder().visitor().visit_str(n, static_cast<uint32_t>(m_trail));
                    unpack_return upr = after_visit_proc(visret, off);
                    if (upr != UNPACK_CONTINUE) return upr;
                }
                else {
                    m_cs = MSGPACK_ACS_STR_VALUE;
                    fixed_trail_again = true;
                }
            } break;
            case MSGPACK_CS_BIN_8: {
                uint8_t tmp;
                load<uint8_t>(tmp, n);
                m_trail = tmp;
                if(m_trail == 0) {
                    bool visret = holder().visitor().visit_bin(n, static_cast<uint32_t>(m_trail));
                    unpack_return upr = after_visit_proc(visret, off);
                    if (upr != UNPACK_CONTINUE) return upr;
                }
                else {
                    m_cs = MSGPACK_ACS_BIN_VALUE;
                    fixed_trail_again = true;
                }
            } break;
            case MSGPACK_CS_EXT_8: {
                uint8_t tmp;
                load<uint8_t>(tmp, n);
                m_trail = tmp + 1;
                if(m_trail == 0) {
                    bool visret = holder().visitor().visit_ext(n, m_trail);
                    unpack_return upr = after_visit_proc(visret, off);
                    if (upr != UNPACK_CONTINUE) return upr;
                }
                else {
                    m_cs = MSGPACK_ACS_EXT_VALUE;
                    fixed_trail_again = true;
                }
            } break;
            case MSGPACK_CS_STR_16: {
                uint16_t tmp;
                load<uint16_t>(tmp, n);
                m_trail = tmp;
                if(m_trail == 0) {
                    bool visret = holder().visitor().visit_str(n, static_cast<uint32_t>(m_trail));
                    unpack_return upr = after_visit_proc(visret, off);
                    if (upr != UNPACK_CONTINUE) return upr;
                }
                else {
                    m_cs = MSGPACK_ACS_STR_VALUE;
                    fixed_trail_again = true;
                }
            } break;
            case MSGPACK_CS_BIN_16: {
                uint16_t tmp;
                load<uint16_t>(tmp, n);
                m_trail = tmp;
                if(m_trail == 0) {
                    bool visret = holder().visitor().visit_bin(n, static_cast<uint32_t>(m_trail));
                    unpack_return upr = after_visit_proc(visret, off);
                    if (upr != UNPACK_CONTINUE) return upr;
                }
                else {
                    m_cs = MSGPACK_ACS_BIN_VALUE;
                    fixed_trail_again = true;
                }
            } break;
            case MSGPACK_CS_EXT_16: {
                uint16_t tmp;
                load<uint16_t>(tmp, n);
                m_trail = tmp + 1;
                if(m_trail == 0) {
                    bool visret = holder().visitor().visit_ext(n, m_trail);
                    unpack_return upr = after_visit_proc(visret, off);
                    if (upr != UNPACK_CONTINUE) return upr;
                }
                else {
                    m_cs = MSGPACK_ACS_EXT_VALUE;
                    fixed_trail_again = true;
                }
            } break;
            case MSGPACK_CS_STR_32: {
                uint32_t tmp;
                load<uint32_t>(tmp, n);
                m_trail = tmp;
                if(m_trail == 0) {
                    bool visret = holder().visitor().visit_str(n, static_cast<uint32_t>(m_trail));
                    unpack_return upr = after_visit_proc(visret, off);
                    if (upr != UNPACK_CONTINUE) return upr;
                }
                else {
                    m_cs = MSGPACK_ACS_STR_VALUE;
                    fixed_trail_again = true;
                }
            } break;
            case MSGPACK_CS_BIN_32: {
                uint32_t tmp;
                load<uint32_t>(tmp, n);
                m_trail = tmp;
                if(m_trail == 0) {
                    bool visret = holder().visitor().visit_bin(n, static_cast<uint32_t>(m_trail));
                    unpack_return upr = after_visit_proc(visret, off);
                    if (upr != UNPACK_CONTINUE) return upr;
                }
                else {
                    m_cs = MSGPACK_ACS_BIN_VALUE;
                    fixed_trail_again = true;
                }
            } break;
            case MSGPACK_CS_EXT_32: {
                uint32_t tmp;
                load<uint32_t>(tmp, n);
                check_ext_size<sizeof(std::size_t)>(tmp);
                m_trail = tmp;
                ++m_trail;
                if(m_trail == 0) {
                    bool visret = holder().visitor().visit_ext(n, m_trail);
                    unpack_return upr = after_visit_proc(visret, off);
                    if (upr != UNPACK_CONTINUE) return upr;
                }
                else {
                    m_cs = MSGPACK_ACS_EXT_VALUE;
                    fixed_trail_again = true;
                }
            } break;
            case MSGPACK_ACS_STR_VALUE: {
                bool visret = holder().visitor().visit_str(n, m_trail);
                unpack_return upr = after_visit_proc(visret, off);
                if (upr != UNPACK_CONTINUE) return upr;
            } break;
            case MSGPACK_ACS_BIN_VALUE: {
                bool visret = holder().visitor().visit_bin(n, static_cast<uint32_t>(m_trail));
                unpack_return upr = after_visit_proc(visret, off);
                if (upr != UNPACK_CONTINUE) return upr;
            } break;
            case MSGPACK_ACS_EXT_VALUE: {
                bool visret = holder().visitor().visit_ext(n, m_trail);
                unpack_return upr = after_visit_proc(visret, off);
                if (upr != UNPACK_CONTINUE) return upr;
            } break;
            case MSGPACK_CS_ARRAY_16: {
                unpack_return ret = start_aggregate<uint16_t>(array_sv(holder()), array_ev(holder()), n, off);
                if (ret != UNPACK_CONTINUE) return ret;
                if (!holder().visitor().start_array_item()) return UNPACK_STOP_VISITOR;

            } break;
            case MSGPACK_CS_ARRAY_32: {
                unpack_return ret = start_aggregate<uint32_t>(array_sv(holder()), array_ev(holder()), n, off);
                if (ret != UNPACK_CONTINUE) return ret;
                if (!holder().visitor().start_array_item()) return UNPACK_STOP_VISITOR;
            } break;
            case MSGPACK_CS_MAP_16: {
                unpack_return ret = start_aggregate<uint16_t>(map_sv(holder()), map_ev(holder()), n, off);
                if (ret != UNPACK_CONTINUE) return ret;
                if (!holder().visitor().start_map_key()) return UNPACK_STOP_VISITOR;
            } break;
            case MSGPACK_CS_MAP_32: {
                unpack_return ret = start_aggregate<uint32_t>(map_sv(holder()), map_ev(holder()), n, off);
                if (ret != UNPACK_CONTINUE) return ret;
                if (!holder().visitor().start_map_key()) return UNPACK_STOP_VISITOR;
            } break;
            default:
                off = m_current - m_start;
                holder().visitor().parse_error(n - m_start - 1, n - m_start);
                return UNPACK_PARSE_ERROR;
            }
        }
    } while(m_current != pe);

    off = m_current - m_start;
    return UNPACK_CONTINUE;
}

} // detail


/// Unpacking class for a stream deserialization.

template <typename VisitorHolder, typename ReferencedBufferHook>
class parser : public detail::context<VisitorHolder> {
    typedef parser<VisitorHolder, ReferencedBufferHook> this_type;
    typedef detail::context<VisitorHolder> context_type;
public:
    /// Constructor
    /**
     * @param referenced If the unpacked object contains reference of the buffer, then set as true, otherwise false.
     * @param f A judging function that msgpack::object refer to the buffer.
     * @param user_data This parameter is passed to f.
     * @param initial_buffer_size The memory size to allocate when unpacker is constructed.
     * @param limit The size limit information of msgpack::object.
     *
     */
    parser(ReferencedBufferHook& hook,
           std::size_t initial_buffer_size = MSGPACK_UNPACKER_INIT_BUFFER_SIZE);

#if !defined(MSGPACK_USE_CPP03)
    parser(this_type&& other);
    this_type& operator=(this_type&& other);
#endif // !defined(MSGPACK_USE_CPP03)

    ~parser();

public:
    /// Reserve a buffer memory.
    /**
     * @param size The size of allocating memory.
     *
     * After returning this function, buffer_capacity() returns at least 'size'.
     * See:
     * https://github.com/msgpack/msgpack-c/wiki/v1_1_cpp_unpacker#msgpack-controls-a-buffer
     */
    void reserve_buffer(std::size_t size = MSGPACK_UNPACKER_RESERVE_SIZE);

    /// Get buffer pointer.
    /**
     * You need to care about the memory is enable between buffer() and buffer() + buffer_capacity()
     * See:
     * https://github.com/msgpack/msgpack-c/wiki/v1_1_cpp_unpacker#msgpack-controls-a-buffer
     */
    char* buffer();

    /// Get buffer capacity.
    /**
     * @return The memory size that you can write.
     *
     * See:
     * https://github.com/msgpack/msgpack-c/wiki/v1_1_cpp_unpacker#msgpack-controls-a-buffer
     */
    std::size_t buffer_capacity() const;

    /// Notify a buffer consumed information to msgpack::unpacker.
    /**
     * @param size The size of memory that you consumed.
     *
     * After copying the data to the memory that is pointed by buffer(), you need to call the
     * function to notify how many bytes are consumed. Then you can call next() functions.
     *
     * See:
     * https://github.com/msgpack/msgpack-c/wiki/v1_1_cpp_unpacker#msgpack-controls-a-buffer
     */
    void buffer_consumed(std::size_t size);

    /// Unpack one msgpack::object.
    /**
     *
     *
     * @return If one msgpack::object is unpacked, then return true, if msgpack::object is incomplete
     *         and additional data is required, then return false. If data format is invalid, throw
     *         msgpack::parse_error.
     *
     * See:
     * https://github.com/msgpack/msgpack-c/wiki/v1_1_cpp_unpacker#msgpack-controls-a-buffer
     */
    bool next();

    /// Get message size.
    /**
     * @return Returns parsed_size() + nonparsed_size()
     */
    std::size_t message_size() const;

public:
    /// Get parsed message size.
    /**
     * @return Parsed message size.
     *
     * This function is usable when non-MessagePack message follows after
     * MessagePack message.
     */
    std::size_t parsed_size() const;

    /// Get the address that is not parsed in the buffer.
    /**
     * @return Address of the buffer that is not parsed
     *
     * This function is usable when non-MessagePack message follows after
     * MessagePack message.
     */
    char* nonparsed_buffer();

    /// Get the size of the buffer that is not parsed.
    /**
     * @return Size of the buffer that is not parsed
     *
     * This function is usable when non-MessagePack message follows after
     * MessagePack message.
     */
    std::size_t nonparsed_size() const;

    /// Skip the specified size of non-parsed buffer.
    /**
     * @param size to skip
     *
     * Note that the `size' argument must be smaller than nonparsed_size().
     * This function is usable when non-MessagePack message follows after
     * MessagePack message.
     */
    void skip_nonparsed_buffer(std::size_t size);

    /// Remove nonparsed buffer and reset the current position as a new start point.
    /**
     * This function is usable when non-MessagePack message follows after
     * MessagePack message.
     */
    void remove_nonparsed_buffer();

    void reset();

protected:
    char* get_raw_buffer() {
        return m_buffer;
    }
private:
    void expand_buffer(std::size_t size);
    unpack_return execute_imp();

private:
    char* m_buffer;
    std::size_t m_used;
    std::size_t m_free;
    std::size_t m_off;
    std::size_t m_parsed;
    std::size_t m_initial_buffer_size;
    ReferencedBufferHook& m_referenced_buffer_hook;

#if defined(MSGPACK_USE_CPP03)
private:
    parser(const this_type&);
    this_type& operator=(const this_type&);
#else  // defined(MSGPACK_USE_CPP03)
public:
    parser(const this_type&) = delete;
    this_type& operator=(const this_type&) = delete;
#endif // defined(MSGPACK_USE_CPP03)
};

template <typename VisitorHolder, typename ReferencedBufferHook>
inline parser<VisitorHolder, ReferencedBufferHook>::parser(
    ReferencedBufferHook& hook,
    std::size_t initial_buffer_size)
    :m_referenced_buffer_hook(hook)
{
    if(initial_buffer_size < COUNTER_SIZE) {
        initial_buffer_size = COUNTER_SIZE;
    }

    char* buffer = static_cast<char*>(::malloc(initial_buffer_size));
    if(!buffer) {
        throw std::bad_alloc();
    }

    m_buffer = buffer;
    m_used = COUNTER_SIZE;
    m_free = initial_buffer_size - m_used;
    m_off = COUNTER_SIZE;
    m_parsed = 0;
    m_initial_buffer_size = initial_buffer_size;

    detail::init_count(m_buffer);
}

#if !defined(MSGPACK_USE_CPP03)
// Move constructor and move assignment operator

template <typename VisitorHolder, typename ReferencedBufferHook>
inline parser<VisitorHolder, ReferencedBufferHook>::parser(this_type&& other)
    :context_type(std::move(other)),
     m_buffer(other.m_buffer),
     m_used(other.m_used),
     m_free(other.m_free),
     m_off(other.m_off),
     m_parsed(other.m_parsed),
     m_initial_buffer_size(other.m_initial_buffer_size),
     m_referenced_buffer_hook(other.m_referenced_buffer_hook) {
    other.m_buffer = MSGPACK_NULLPTR;
    other.m_used = 0;
    other.m_free = 0;
    other.m_off = 0;
    other.m_parsed = 0;
}

template <typename VisitorHolder, typename ReferencedBufferHook>
inline parser<VisitorHolder, ReferencedBufferHook>& parser<VisitorHolder, ReferencedBufferHook>::operator=(this_type&& other) {
    this->~parser();
    new (this) this_type(std::move(other));
    return *this;
}

#endif // !defined(MSGPACK_USE_CPP03)


template <typename VisitorHolder, typename ReferencedBufferHook>
inline parser<VisitorHolder, ReferencedBufferHook>::~parser()
{
    // These checks are required for move operations.
    if (m_buffer) detail::decr_count(m_buffer);
}


template <typename VisitorHolder, typename ReferencedBufferHook>
inline void parser<VisitorHolder, ReferencedBufferHook>::reserve_buffer(std::size_t size)
{
    if(m_free >= size) return;
    expand_buffer(size);
}

template <typename VisitorHolder, typename ReferencedBufferHook>
inline void parser<VisitorHolder, ReferencedBufferHook>::expand_buffer(std::size_t size)
{
    if(m_used == m_off && detail::get_count(m_buffer) == 1
       && static_cast<VisitorHolder&>(*this).visitor().referenced()) {
        // rewind buffer
        m_free += m_used - COUNTER_SIZE;
        m_used = COUNTER_SIZE;
        m_off  = COUNTER_SIZE;

        if(m_free >= size) return;
    }

    if(m_off == COUNTER_SIZE) {
        std::size_t next_size = (m_used + m_free) * 2;    // include COUNTER_SIZE
        while(next_size < size + m_used) {
            std::size_t tmp_next_size = next_size * 2;
            if (tmp_next_size <= next_size) {
                next_size = size + m_used;
                break;
            }
            next_size = tmp_next_size;
        }

        char* tmp = static_cast<char*>(::realloc(m_buffer, next_size));
        if(!tmp) {
            throw std::bad_alloc();
        }

        m_buffer = tmp;
        m_free = next_size - m_used;

    } else {
        std::size_t next_size = m_initial_buffer_size;  // include COUNTER_SIZE
        std::size_t not_parsed = m_used - m_off;
        while(next_size < size + not_parsed + COUNTER_SIZE) {
            std::size_t tmp_next_size = next_size * 2;
            if (tmp_next_size <= next_size) {
                next_size = size + not_parsed + COUNTER_SIZE;
                break;
            }
            next_size = tmp_next_size;
        }

        char* tmp = static_cast<char*>(::malloc(next_size));
        if(!tmp) {
            throw std::bad_alloc();
        }

        detail::init_count(tmp);

        std::memcpy(tmp+COUNTER_SIZE, m_buffer + m_off, not_parsed);

        if(static_cast<VisitorHolder&>(*this).referenced()) {
            try {
                m_referenced_buffer_hook(m_buffer);
            }
            catch (...) {
                ::free(tmp);
                throw;
            }
            static_cast<VisitorHolder&>(*this).set_referenced(false);
        } else {
            detail::decr_count(m_buffer);
        }

        m_buffer = tmp;
        m_used  = not_parsed + COUNTER_SIZE;
        m_free  = next_size - m_used;
        m_off   = COUNTER_SIZE;
    }
}

template <typename VisitorHolder, typename ReferencedBufferHook>
inline char* parser<VisitorHolder, ReferencedBufferHook>::buffer()
{
    return m_buffer + m_used;
}

template <typename VisitorHolder, typename ReferencedBufferHook>
inline std::size_t parser<VisitorHolder, ReferencedBufferHook>::buffer_capacity() const
{
    return m_free;
}

template <typename VisitorHolder, typename ReferencedBufferHook>
inline void parser<VisitorHolder, ReferencedBufferHook>::buffer_consumed(std::size_t size)
{
    m_used += size;
    m_free -= size;
}

template <typename VisitorHolder, typename ReferencedBufferHook>
    inline bool parser<VisitorHolder, ReferencedBufferHook>::next()
{
    unpack_return ret = execute_imp();
    return ret == UNPACK_SUCCESS;
}

template <typename VisitorHolder, typename ReferencedBufferHook>
inline unpack_return parser<VisitorHolder, ReferencedBufferHook>::execute_imp()
{
    std::size_t off = m_off;
    unpack_return ret = context_type::execute(m_buffer, m_used, m_off);
    if(m_off > off) {
        m_parsed += m_off - off;
    }
    return ret;
}

template <typename VisitorHolder, typename ReferencedBufferHook>
inline void parser<VisitorHolder, ReferencedBufferHook>::reset()
{
    context_type::init();
    // don't reset referenced flag
    m_parsed = 0;
}

template <typename VisitorHolder, typename ReferencedBufferHook>
inline std::size_t parser<VisitorHolder, ReferencedBufferHook>::message_size() const
{
    return m_parsed - m_off + m_used;
}

template <typename VisitorHolder, typename ReferencedBufferHook>
inline std::size_t parser<VisitorHolder, ReferencedBufferHook>::parsed_size() const
{
    return m_parsed;
}

template <typename VisitorHolder, typename ReferencedBufferHook>
inline char* parser<VisitorHolder, ReferencedBufferHook>::nonparsed_buffer()
{
    return m_buffer + m_off;
}

template <typename VisitorHolder, typename ReferencedBufferHook>
inline std::size_t parser<VisitorHolder, ReferencedBufferHook>::nonparsed_size() const
{
    return m_used - m_off;
}

template <typename VisitorHolder, typename ReferencedBufferHook>
inline void parser<VisitorHolder, ReferencedBufferHook>::skip_nonparsed_buffer(std::size_t size)
{
    m_off += size;
}

template <typename VisitorHolder, typename ReferencedBufferHook>
inline void parser<VisitorHolder, ReferencedBufferHook>::remove_nonparsed_buffer()
{
    m_used = m_off;
}

struct zone_push_finalizer {
    zone_push_finalizer(msgpack::zone& z):m_z(&z) {}
    void set_zone(msgpack::zone& z) { m_z = &z; }
    void operator()(char* buffer) {
        m_z->push_finalizer(&detail::decr_count, buffer);
    }
    msgpack::zone* m_z;
};

class unpacker : public parser<unpacker, zone_push_finalizer>,
                 public detail::create_object_visitor {
    typedef parser<unpacker, zone_push_finalizer> parser_t;
public:
    unpacker(unpack_reference_func f = &unpacker::default_reference_func,
             void* user_data = MSGPACK_NULLPTR,
             std::size_t initial_buffer_size = MSGPACK_UNPACKER_INIT_BUFFER_SIZE,
             unpack_limit const& limit = unpack_limit())
        :parser_t(m_finalizer, initial_buffer_size),
         detail::create_object_visitor(f, user_data, limit),
         m_z(new msgpack::zone),
         m_finalizer(*m_z) {
        set_zone(*m_z);
        set_referenced(false);
    }

    detail::create_object_visitor& visitor() { return *this; }
    /// Unpack one msgpack::object.
    /**
     *
     * @param result The object that contains unpacked data.
     * @param referenced If the unpacked object contains reference of the buffer,
     *                   then set as true, otherwise false.
     *
     * @return If one msgpack::object is unpacked, then return true, if msgpack::object is incomplete
     *         and additional data is required, then return false. If data format is invalid, throw
     *         msgpack::parse_error.
     *
     * See:
     * https://github.com/msgpack/msgpack-c/wiki/v1_1_cpp_unpacker#msgpack-controls-a-buffer
     */
    bool next(msgpack::object_handle& result, bool& referenced);

    /// Unpack one msgpack::object.
    /**
     *
     * @param result The object that contains unpacked data.
     *
     * @return If one msgpack::object is unpacked, then return true, if msgpack::object is incomplete
     *         and additional data is required, then return false. If data format is invalid, throw
     *         msgpack::parse_error.
     *
     * See:
     * https://github.com/msgpack/msgpack-c/wiki/v1_1_cpp_unpacker#msgpack-controls-a-buffer
     */
    bool next(msgpack::object_handle& result);
    msgpack::zone* release_zone();
    void reset_zone();
    bool flush_zone();
private:
    static bool default_reference_func(msgpack::type::object_type /*type*/, std::size_t /*len*/, void*) {
        return true;
    }
    msgpack::unique_ptr<msgpack::zone> m_z;
    zone_push_finalizer m_finalizer;
};

inline bool unpacker::next(msgpack::object_handle& result, bool& referenced) {
    bool ret = parser_t::next();
    if (ret) {
        referenced = detail::create_object_visitor::referenced();
        result.zone().reset( release_zone() );
        result.set(data());
        reset();
    }
    else {
        result.zone().reset();
        result.set(msgpack::object());
    }
    return ret;
}

inline bool unpacker::next(msgpack::object_handle& result) {
    bool referenced;
    return next(result, referenced);
}

inline msgpack::zone* unpacker::release_zone()
{
    if(!flush_zone()) {
        return MSGPACK_NULLPTR;
    }

    msgpack::zone* r =  new msgpack::zone;
    msgpack::zone* old = m_z.release();
    m_z.reset(r);
    set_zone(*m_z);
    m_finalizer.set_zone(*m_z);

    return old;
}

inline void unpacker::reset_zone()
{
    m_z->clear();
}

inline bool unpacker::flush_zone()
{
    if(referenced()) {
        try {
            m_z->push_finalizer(&detail::decr_count, get_raw_buffer());
        } catch (...) {
            return false;
        }
        set_referenced(false);

        detail::incr_count(get_raw_buffer());
    }

    return true;
}

inline msgpack::object_handle unpack(
    const char* data, std::size_t len, std::size_t& off, bool& referenced,
    unpack_reference_func f, void* user_data,
    unpack_limit const& limit
)
{
    msgpack::object obj;
    msgpack::unique_ptr<msgpack::zone> z(new msgpack::zone);
    referenced = false;
    std::size_t noff = off;
    unpack_return ret = detail::unpack_imp(
        data, len, noff, *z, obj, referenced, f, user_data, limit);

    switch(ret) {
    case UNPACK_SUCCESS:
        off = noff;
        return msgpack::object_handle(obj, msgpack::move(z));
    case UNPACK_EXTRA_BYTES:
        off = noff;
        return msgpack::object_handle(obj, msgpack::move(z));
    default:
        break;
    }
    return msgpack::object_handle();
}

inline msgpack::object_handle unpack(
    const char* data, std::size_t len, std::size_t& off,
    unpack_reference_func f, void* user_data,
    unpack_limit const& limit)
{
    bool referenced;
    return msgpack::v2::unpack(data, len, off, referenced, f, user_data, limit);
}

inline msgpack::object_handle unpack(
    const char* data, std::size_t len, bool& referenced,
    unpack_reference_func f, void* user_data,
    unpack_limit const& limit)
{
    std::size_t off = 0;
    return msgpack::v2::unpack(data, len, off, referenced, f, user_data, limit);
}

inline msgpack::object_handle unpack(
    const char* data, std::size_t len,
    unpack_reference_func f, void* user_data,
    unpack_limit const& limit)
{
    bool referenced;
    std::size_t off = 0;
    return msgpack::v2::unpack(data, len, off, referenced, f, user_data, limit);
}

inline void unpack(
    msgpack::object_handle& result,
    const char* data, std::size_t len, std::size_t& off, bool& referenced,
    unpack_reference_func f, void* user_data,
    unpack_limit const& limit)
{
    msgpack::object obj;
    msgpack::unique_ptr<msgpack::zone> z(new msgpack::zone);
    referenced = false;
    std::size_t noff = off;
    unpack_return ret = detail::unpack_imp(
        data, len, noff, *z, obj, referenced, f, user_data, limit);

    switch(ret) {
    case UNPACK_SUCCESS:
        off = noff;
        result.set(obj);
        result.zone() = msgpack::move(z);
        return;
    case UNPACK_EXTRA_BYTES:
        off = noff;
        result.set(obj);
        result.zone() = msgpack::move(z);
        return;
    default:
        return;
    }
}

inline void unpack(
    msgpack::object_handle& result,
    const char* data, std::size_t len, std::size_t& off,
    msgpack::v2::unpack_reference_func f, void* user_data,
            unpack_limit const& limit)
{
    bool referenced;
    msgpack::v2::unpack(result, data, len, off, referenced, f, user_data, limit);
}

inline void unpack(
    msgpack::object_handle& result,
    const char* data, std::size_t len, bool& referenced,
    unpack_reference_func f, void* user_data,
    unpack_limit const& limit)
{
    std::size_t off = 0;
    msgpack::v2::unpack(result, data, len, off, referenced, f, user_data, limit);
}

inline void unpack(
    msgpack::object_handle& result,
    const char* data, std::size_t len,
    unpack_reference_func f, void* user_data,
    unpack_limit const& limit)
{
    bool referenced;
    std::size_t off = 0;
    msgpack::v2::unpack(result, data, len, off, referenced, f, user_data, limit);
}


inline msgpack::object unpack(
    msgpack::zone& z,
    const char* data, std::size_t len, std::size_t& off, bool& referenced,
    unpack_reference_func f, void* user_data,
    unpack_limit const& limit)
{
    msgpack::object obj;
    std::size_t noff = off;
    referenced = false;
    unpack_return ret = detail::unpack_imp(
        data, len, noff, z, obj, referenced, f, user_data, limit);

    switch(ret) {
    case UNPACK_SUCCESS:
        off = noff;
        return obj;
    case UNPACK_EXTRA_BYTES:
        off = noff;
        return obj;
    default:
        break;
    }
    return obj;
}

inline msgpack::object unpack(
    msgpack::zone& z,
    const char* data, std::size_t len, std::size_t& off,
    unpack_reference_func f, void* user_data,
    unpack_limit const& limit)
{
    bool referenced;
    return msgpack::v2::unpack(z, data, len, off, referenced, f, user_data, limit);
}

inline msgpack::object unpack(
    msgpack::zone& z,
    const char* data, std::size_t len, bool& referenced,
    unpack_reference_func f, void* user_data,
    unpack_limit const& limit)
{
    std::size_t off = 0;
    return msgpack::v2::unpack(z, data, len, off, referenced, f, user_data, limit);
}

inline msgpack::object unpack(
    msgpack::zone& z,
    const char* data, std::size_t len,
    unpack_reference_func f, void* user_data,
    unpack_limit const& limit)
{
    bool referenced;
    std::size_t off = 0;
    return msgpack::v2::unpack(z, data, len, off, referenced, f, user_data, limit);
}

template <typename Visitor>
inline bool parse(const char* data, size_t len, size_t& off, Visitor& v) {
    unpack_return ret = detail::parse_imp(data, len, off, v);
    return ret == UNPACK_SUCCESS || ret == UNPACK_EXTRA_BYTES;
}

template <typename Visitor>
inline bool parse(const char* data, size_t len, Visitor& v) {
    std::size_t off = 0;
    return parse(data, len, off, v);
}

namespace detail {

template <typename Visitor>
struct parse_helper : context<parse_helper<Visitor> > {
    parse_helper(Visitor& v):m_visitor(v) {}
    unpack_return execute(const char* data, std::size_t len, std::size_t& off) {
        return context<parse_helper<Visitor> >::execute(data, len, off);
    }
    Visitor& visitor() const { return m_visitor; }
    Visitor& m_visitor;
};

template <typename Visitor>
inline unpack_return
parse_imp(const char* data, size_t len, size_t& off, Visitor& v) {
    std::size_t noff = off;

    if(len <= noff) {
        // FIXME
        v.insufficient_bytes(noff, noff);
        return UNPACK_CONTINUE;
    }
    detail::parse_helper<Visitor> h(v);
    unpack_return ret = h.execute(data, len, noff);
    switch (ret) {
    case UNPACK_CONTINUE:
        off = noff;
        v.insufficient_bytes(noff - 1, noff);
        return ret;
    case UNPACK_SUCCESS:
        off = noff;
        if(noff < len) {
            return UNPACK_EXTRA_BYTES;
        }
        return ret;
    default:
        return ret;
    }
}

inline unpack_return
unpack_imp(const char* data, std::size_t len, std::size_t& off,
           msgpack::zone& result_zone, msgpack::object& result, bool& referenced,
           unpack_reference_func f = MSGPACK_NULLPTR, void* user_data = MSGPACK_NULLPTR,
           unpack_limit const& limit = unpack_limit())
{
    create_object_visitor v(f, user_data, limit);
    v.set_zone(result_zone);
    referenced = false;
    v.set_referenced(referenced);
    unpack_return ret = parse_imp(data, len, off, v);
    referenced = v.referenced();
    result = v.data();
    return ret;
}

} // detail


/// @cond
}  // MSGPACK_API_VERSION_NAMESPACE(v2)
/// @endcond

}  // namespace msgpack


#endif // MSGPACK_V2_UNPACK_HPP
