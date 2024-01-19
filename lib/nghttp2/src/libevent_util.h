/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2014 Tatsuhiro Tsujikawa
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifndef LIBEVENT_UTIL_H
#define LIBEVENT_UTIL_H

#include "nghttp2_config.h"

#include <event2/buffer.h>
#include <event2/bufferevent.h>

namespace nghttp2 {

namespace util {

class EvbufferBuffer {
public:
  EvbufferBuffer();
  // If |limit| is not -1, at most min(limit, bufmax) size bytes are
  // added to evbuffer_.
  EvbufferBuffer(evbuffer *evbuffer, uint8_t *buf, size_t bufmax,
                 ssize_t limit = -1);
  ~EvbufferBuffer();
  void reset(evbuffer *evbuffer, uint8_t *buf, size_t bufmax,
             ssize_t limit = -1);
  int flush();
  int add(const uint8_t *data, size_t datalen);
  size_t get_buflen() const;
  int write_buffer();
  // Returns the number of written bytes to evbuffer_ so far.  reset()
  // resets this value to 0.
  size_t get_writelen() const;

private:
  evbuffer *evbuffer_;
  evbuffer *bucket_;
  uint8_t *buf_;
  size_t bufmax_;
  size_t buflen_;
  ssize_t limit_;
  size_t writelen_;
};

// These functions are provided to reduce epoll_ctl syscall.  Avoid
// calling bufferevent_enable/disable() unless it is required by
// sniffing current enabled events.
void bev_enable_unless(bufferevent *bev, int events);
void bev_disable_unless(bufferevent *bev, int events);

} // namespace util

} // namespace nghttp2

#endif // LIBEVENT_UTIL_H
