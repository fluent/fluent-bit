// MessagePack for C++ example
//
// Copyright (C) 2008-2015 FURUHASHI Sadayuki and KONDO Takatoshi
//
//    Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//    http://www.boost.org/LICENSE_1_0.txt)
//

#include <msgpack.hpp>
#include <iostream>
#include <stdexcept>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

#if defined(_MSC_VER) || defined(__MINGW32__)
#include <io.h>
#include <fcntl.h>
#define pipe(fds) _pipe(fds, 4096, _O_BINARY)
#endif // _MSC_VER || __MINGW32__

class Server {
public:
    Server(int sock) : m_sock(sock) { }

    ~Server() { }

    typedef msgpack::unique_ptr<msgpack::zone> unique_zone;

    void socket_readable()
    {
        m_pac.reserve_buffer(1024);

        ssize_t count =
            read(m_sock, m_pac.buffer(), m_pac.buffer_capacity());

        if(count <= 0) {
            if(count == 0) {
                throw std::runtime_error("connection closed");
            }
            if(errno == EAGAIN || errno == EINTR) {
                return;
            }
            throw std::runtime_error(strerror(errno));
        }

        m_pac.buffer_consumed(count);

        msgpack::object_handle oh;
        while (m_pac.next(oh)) {
            msgpack::object msg = oh.get();
            unique_zone& life = oh.zone();
            process_message(msg, life);
        }

        if(m_pac.message_size() > 10*1024*1024) {
            throw std::runtime_error("message is too large");
        }
    }

private:
    void process_message(msgpack::object msg, unique_zone&)
    {
        std::cout << "message reached: " << msg << std::endl;
    }

private:
    int m_sock;
    msgpack::unpacker m_pac;
};


static void* run_server(void* arg)
{
    try {
        Server* srv = reinterpret_cast<Server*>(arg);

        while(true) {
            srv->socket_readable();
        }
        return NULL;

    } catch (std::exception& e) {
        std::cerr << "error while processing client packet: "
                  << e.what() << std::endl;
        return NULL;

    } catch (...) {
        std::cerr << "error while processing client packet: "
                  << "unknown error" << std::endl;
        return NULL;
    }
}

struct fwriter {
    fwriter(int fd) : m_fp( fdopen(fd, "w") ) { }

    void write(const char* buf, size_t buflen)
    {
        size_t count = fwrite(buf, buflen, 1, m_fp);
        if(count < 1) {
            std::cout << buflen << std::endl;
            std::cout << count << std::endl;
            throw std::runtime_error(strerror(errno));
        }
    }

    void flush() { fflush(m_fp); }

    void close() { fclose(m_fp); }

private:
    FILE* m_fp;
};


int main(void)
{
    int pair[2];
    if (pipe(pair) != 0) return -1;

    // run server thread
    Server srv(pair[0]);
    pthread_t thread;
    pthread_create(&thread, NULL,
            run_server, reinterpret_cast<void*>(&srv));

    // client thread:
    fwriter writer(pair[1]);
    msgpack::packer<fwriter> pk(writer);

    typedef msgpack::type::tuple<std::string, std::string, std::string> put_t;
    typedef msgpack::type::tuple<std::string, std::string> get_t;

    put_t req1("put", "apple", "red");
    put_t req2("put", "lemon", "yellow");
    get_t req3("get", "apple");
    pk.pack(req1);
    pk.pack(req2);
    pk.pack(req3);
    writer.flush();
    writer.close();

    pthread_join(thread, NULL);
}
