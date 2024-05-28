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
#include "libevent_util.h"

#include <cstring>
#include <algorithm>

namespace nghttp2 {

namespace util {

EvbufferBuffer::EvbufferBuffer()
    : evbuffer_(nullptr),
      bucket_(nullptr),
      buf_(nullptr),
      bufmax_(0),
      buflen_(0),
      limit_(0),
      writelen_(0) {}

EvbufferBuffer::EvbufferBuffer(evbuffer *evbuffer, uint8_t *buf, size_t bufmax,
                               ssize_t limit)
    : evbuffer_(evbuffer),
      bucket_(limit == -1 ? nullptr : evbuffer_new()),
      buf_(buf),
      bufmax_(bufmax),
      buflen_(0),
      limit_(limit),
      writelen_(0) {}

void EvbufferBuffer::reset(evbuffer *evbuffer, uint8_t *buf, size_t bufmax,
                           ssize_t limit) {
  evbuffer_ = evbuffer;
  buf_ = buf;
  if (limit != -1 && !bucket_) {
    bucket_ = evbuffer_new();
  }
  bufmax_ = bufmax;
  buflen_ = 0;
  limit_ = limit;
  writelen_ = 0;
}

EvbufferBuffer::~EvbufferBuffer() {
  if (bucket_) {
    evbuffer_free(bucket_);
  }
}

int EvbufferBuffer::write_buffer() {
  for (auto pos = buf_, end = buf_ + buflen_; pos < end;) {
    // To avoid merging chunks in evbuffer, we first add to temporal
    // buffer bucket_ and then move its chain to evbuffer_.
    auto nwrite = std::min(end - pos, limit_);
    auto rv = evbuffer_add(bucket_, pos, nwrite);
    if (rv == -1) {
      return -1;
    }
    rv = evbuffer_add_buffer(evbuffer_, bucket_);
    if (rv == -1) {
      return -1;
    }
    pos += nwrite;
  }
  return 0;
}

int EvbufferBuffer::flush() {
  int rv;
  if (buflen_ > 0) {
    if (limit_ == -1) {
      rv = evbuffer_add(evbuffer_, buf_, buflen_);
    } else {
      rv = write_buffer();
    }
    if (rv == -1) {
      return -1;
    }
    writelen_ += buflen_;
    buflen_ = 0;
  }
  return 0;
}

int EvbufferBuffer::add(const uint8_t *data, size_t datalen) {
  int rv;
  if (buflen_ + datalen > bufmax_) {
    if (buflen_ > 0) {
      if (limit_ == -1) {
        rv = evbuffer_add(evbuffer_, buf_, buflen_);
      } else {
        rv = write_buffer();
      }
      if (rv == -1) {
        return -1;
      }
      writelen_ += buflen_;
      buflen_ = 0;
    }
    if (datalen > bufmax_) {
      if (limit_ == -1) {
        rv = evbuffer_add(evbuffer_, data, datalen);
      } else {
        rv = write_buffer();
      }
      if (rv == -1) {
        return -1;
      }
      writelen_ += buflen_;
      return 0;
    }
  }
  memcpy(buf_ + buflen_, data, datalen);
  buflen_ += datalen;
  return 0;
}

size_t EvbufferBuffer::get_buflen() const { return buflen_; }

size_t EvbufferBuffer::get_writelen() const { return writelen_; }

void bev_enable_unless(bufferevent *bev, int events) {
  if ((bufferevent_get_enabled(bev) & events) == events) {
    return;
  }

  bufferevent_enable(bev, events);
}

void bev_disable_unless(bufferevent *bev, int events) {
  if ((bufferevent_get_enabled(bev) & events) == 0) {
    return;
  }

  bufferevent_disable(bev, events);
}

} // namespace util

} // namespace nghttp2
