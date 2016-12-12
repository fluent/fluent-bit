#include <msgpack.hpp>
#include <gtest/gtest.h>
#include <sstream>

// To avoid link error
TEST(visitor, dummy)
{
}

#if MSGPACK_DEFAULT_API_VERSION >= 2

struct json_like_visitor : msgpack::v2::null_visitor {
    json_like_visitor(std::string& s):m_s(s) {}

    bool visit_nil() {
        m_s += "null";
        return true;
    }
    bool visit_boolean(bool v) {
        if (v) m_s += "true";
        else m_s += "false";
        return true;
    }
    bool visit_positive_integer(uint64_t v) {
        std::stringstream ss;
        ss << v;
        m_s += ss.str();
        return true;
    }
    bool visit_negative_integer(int64_t v) {
        std::stringstream ss;
        ss << v;
        m_s += ss.str();
        return true;
    }
    bool visit_str(const char* v, uint32_t size) {
        // I omit escape process.
        m_s += '"' + std::string(v, size) + '"';
        return true;
    }
    bool start_array(uint32_t /*num_elements*/) {
        m_s += "[";
        return true;
    }
    bool end_array_item() {
        m_s += ",";
        return true;
    }
    bool end_array() {
        m_s.erase(m_s.size() - 1, 1); // remove the last ','
        m_s += "]";
        return true;
    }
    bool start_map(uint32_t /*num_kv_pairs*/) {
        m_s += "{";
        return true;
    }
    bool end_map_key() {
        m_s += ":";
        return true;
    }
    bool end_map_value() {
        m_s += ",";
        return true;
    }
    bool end_map() {
        m_s.erase(m_s.size() - 1, 1); // remove the last ','
        m_s += "}";
        return true;
    }
    void parse_error(size_t /*parsed_offset*/, size_t /*error_offset*/) {
        EXPECT_TRUE(false);
    }
    void insufficient_bytes(size_t /*parsed_offset*/, size_t /*error_offset*/) {
        EXPECT_TRUE(false);
    }
    std::string& m_s;
};

TEST(visitor, json_like)
{
    std::stringstream ss;
    msgpack::packer<std::stringstream> p(ss);
    p.pack_map(1);
    p.pack("key");
    p.pack_array(3);
    p.pack(42);
    p.pack_nil();
    p.pack(true);

    std::string json_like;
    json_like_visitor v(json_like);
    std::size_t off = 0;
    bool ret = msgpack::v2::parse(ss.str().data(), ss.str().size(), off, v);
    EXPECT_TRUE(ret);
    EXPECT_EQ("{\"key\":[42,null,true]}", json_like);
}

struct parse_error_check_visitor : msgpack::v2::null_visitor {
    parse_error_check_visitor(bool& called):m_called(called) {}
    void parse_error(size_t parsed_offset, size_t error_offset) {
        EXPECT_EQ(static_cast<size_t>(1), parsed_offset);
        EXPECT_EQ(static_cast<size_t>(2), error_offset);
        m_called = true;
    }
    bool& m_called;
};

TEST(visitor, parse_error)
{
    bool called = false;
    parse_error_check_visitor v(called);
    std::size_t off = 0;
    char const data[] = { static_cast<char>(0x93u), 0x01u, static_cast<char>(0xc1u), 0x03u };
    bool ret = msgpack::v2::parse(data, sizeof(data), off, v);
    EXPECT_FALSE(ret);
    EXPECT_TRUE(called);
}

struct insuf_bytes_check_visitor : msgpack::v2::null_visitor {
    insuf_bytes_check_visitor(bool& called):m_called(called) {}
    void insufficient_bytes(size_t parsed_offset, size_t error_offset) {
        EXPECT_EQ(static_cast<size_t>(2), parsed_offset);
        EXPECT_EQ(static_cast<size_t>(3), error_offset);
        m_called = true;
    }
    bool& m_called;
};

TEST(visitor, insuf_bytes)
{
    bool called = false;
    insuf_bytes_check_visitor v(called);
    std::size_t off = 0;
    char const data[] = { static_cast<char>(0x93u), 0x01u, 0x01u };
    bool ret = msgpack::v2::parse(data, sizeof(data), off, v);
    EXPECT_FALSE(ret);
    EXPECT_TRUE(called);
}

#endif // MSGPACK_DEFAULT_API_VERSION >= 1
