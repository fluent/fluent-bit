#include <iostream>
#include <sstream>
#include <msgpack.hpp>

struct json_like_visitor : msgpack::v2::null_visitor {
    json_like_visitor(std::string& s):m_s(s), m_ref(false) {} // m_ref is false by default

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
        std::cerr << "parse error"<<std::endl;
    }
    void insufficient_bytes(size_t /*parsed_offset*/, size_t /*error_offset*/) {
        std::cout << "insufficient bytes"<<std::endl;
    }
    std::string& m_s;

    // These two functions are required by parser.
    void set_referenced(bool ref) { m_ref = ref; }
    bool referenced() const { return m_ref; }
    bool m_ref;
};

struct do_nothing {
    void operator()(char* /*buffer*/) {
    }
};

class json_like_printer : public msgpack::parser<json_like_printer, do_nothing>,
                          public json_like_visitor {
    typedef parser<json_like_printer, do_nothing> parser_t;
public:
    json_like_printer(std::size_t initial_buffer_size = MSGPACK_UNPACKER_INIT_BUFFER_SIZE)
        :parser_t(do_nothing_, initial_buffer_size),
         json_like_visitor(json_str_) {
    }

    json_like_visitor& visitor() { return *this; }
    void print() { std::cout << json_str_ << std::endl; json_str_.clear();}
private:
    do_nothing do_nothing_;
    std::string json_str_;
};

template <typename T>
struct ref_buffer {
    ref_buffer(T& t):t(t) {}
    void write(char const* ptr, std::size_t len) {
        if (len > t.buffer_capacity()) {
            t.reserve_buffer(len - t.buffer_capacity());
        }
        std::memcpy(t.buffer(), ptr, len);
        t.buffer_consumed(len);
    }
    T& t;
};

#define BUFFERING_SIZE_MAX 100

//simulates streamed content (a socket for example)
bool produce( std::stringstream & ss, char* buff, std::size_t& size)
{
    ss.read(buff, BUFFERING_SIZE_MAX);
    size = static_cast<std::size_t>(ss.gcount());
    return (size > 0);
}

//shows how you can treat data 
void consume( const char* buff, const std::size_t size, 
    ref_buffer<json_like_printer> & rb,
    json_like_printer & jp
    )
{
    rb.write(buff,size);
    while( jp.next() )
    {
        //here we print the data, you could do any wanted processing
        jp.print();
    }  
}

int main() {

    std::vector<std::vector<int>> vvi1 { { 1,2,3,4,5}, { 6,7,8,9,10} }; 
    std::vector<std::vector<int>> vvi2 { { 11,12,13,14,15}, { 16,17,18,19,20} };

    std::stringstream ss;
    
    msgpack::pack(ss, vvi1);
    msgpack::pack(ss, vvi2);

    char buffer[BUFFERING_SIZE_MAX];
    std::size_t size = 0;

    json_like_printer jp(1); // set initial buffer size explicitly
    ref_buffer<json_like_printer> rb(jp);

    while( produce(ss,buffer,size) )
    {
        consume(buffer, size, rb, jp);
    }

}