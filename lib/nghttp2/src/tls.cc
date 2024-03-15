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
#include "tls.h"

#include <cassert>
#include <vector>
#include <mutex>
#include <iostream>

#include <openssl/crypto.h>
#include <openssl/conf.h>

#include "ssl_compat.h"

namespace nghttp2 {

namespace tls {

#if OPENSSL_1_1_API

// CRYPTO_LOCK is deprecated as of OpenSSL 1.1.0
LibsslGlobalLock::LibsslGlobalLock() {}

#else // !OPENSSL_1_1_API

namespace {
std::mutex *ssl_global_locks;
} // namespace

namespace {
void ssl_locking_cb(int mode, int type, const char *file, int line) {
  if (mode & CRYPTO_LOCK) {
    ssl_global_locks[type].lock();
  } else {
    ssl_global_locks[type].unlock();
  }
}
} // namespace

LibsslGlobalLock::LibsslGlobalLock() {
  if (ssl_global_locks) {
    std::cerr << "OpenSSL global lock has been already set" << std::endl;
    assert(0);
  }
  ssl_global_locks = new std::mutex[CRYPTO_num_locks()];
  // CRYPTO_set_id_callback(ssl_thread_id); OpenSSL manual says that
  // if threadid_func is not specified using
  // CRYPTO_THREADID_set_callback(), then default implementation is
  // used. We use this default one.
  CRYPTO_set_locking_callback(ssl_locking_cb);
}

#endif // !OPENSSL_1_1_API

const char *get_tls_protocol(SSL *ssl) {
  switch (SSL_version(ssl)) {
  case SSL2_VERSION:
    return "SSLv2";
  case SSL3_VERSION:
    return "SSLv3";
#ifdef TLS1_3_VERSION
  case TLS1_3_VERSION:
    return "TLSv1.3";
#endif // TLS1_3_VERSION
  case TLS1_2_VERSION:
    return "TLSv1.2";
  case TLS1_1_VERSION:
    return "TLSv1.1";
  case TLS1_VERSION:
    return "TLSv1";
  default:
    return "unknown";
  }
}

TLSSessionInfo *get_tls_session_info(TLSSessionInfo *tls_info, SSL *ssl) {
  if (!ssl) {
    return nullptr;
  }

  auto session = SSL_get_session(ssl);
  if (!session) {
    return nullptr;
  }

  tls_info->cipher = SSL_get_cipher_name(ssl);
  tls_info->protocol = get_tls_protocol(ssl);
  tls_info->session_reused = SSL_session_reused(ssl);

  unsigned int session_id_length;
  tls_info->session_id = SSL_SESSION_get_id(session, &session_id_length);
  tls_info->session_id_length = session_id_length;

  return tls_info;
}

/* Conditional logic w/ lookup tables to check if id is one of the
   the block listed cipher suites for HTTP/2 described in RFC 7540.
   https://github.com/jay/http2_blacklisted_ciphers
*/
#define IS_CIPHER_BANNED_METHOD2(id)                                           \
  ((0x0000 <= id && id <= 0x00FF &&                                            \
    "\xFF\xFF\xFF\xCF\xFF\xFF\xFF\xFF\x7F\x00\x00\x00\x80\x3F\x00\x00"         \
    "\xF0\xFF\xFF\x3F\xF3\xF3\xFF\xFF\x3F\x00\x00\x00\x00\x00\x00\x80"         \
            [(id & 0xFF) / 8] &                                                \
        (1 << (id % 8))) ||                                                    \
   (0xC000 <= id && id <= 0xC0FF &&                                            \
    "\xFE\xFF\xFF\xFF\xFF\x67\xFE\xFF\xFF\xFF\x33\xCF\xFC\xCF\xFF\xCF"         \
    "\x3C\xF3\xFC\x3F\x33\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"         \
            [(id & 0xFF) / 8] &                                                \
        (1 << (id % 8))))

bool check_http2_cipher_block_list(SSL *ssl) {
  int id = SSL_CIPHER_get_id(SSL_get_current_cipher(ssl)) & 0xFFFFFF;

  return IS_CIPHER_BANNED_METHOD2(id);
}

bool check_http2_tls_version(SSL *ssl) {
  auto tls_ver = SSL_version(ssl);

  return tls_ver >= TLS1_2_VERSION;
}

bool check_http2_requirement(SSL *ssl) {
  return check_http2_tls_version(ssl) && !check_http2_cipher_block_list(ssl);
}

void libssl_init() {
#if OPENSSL_1_1_API
// No explicit initialization is required.
#elif defined(NGHTTP2_OPENSSL_IS_BORINGSSL)
  CRYPTO_library_init();
#else  // !OPENSSL_1_1_API && !defined(NGHTTP2_OPENSSL_IS_BORINGSSL)
  OPENSSL_config(nullptr);
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();
#endif // !OPENSSL_1_1_API && !defined(NGHTTP2_OPENSSL_IS_BORINGSSL)
}

int ssl_ctx_set_proto_versions(SSL_CTX *ssl_ctx, int min, int max) {
#if OPENSSL_1_1_API || defined(NGHTTP2_OPENSSL_IS_BORINGSSL)
  if (SSL_CTX_set_min_proto_version(ssl_ctx, min) != 1 ||
      SSL_CTX_set_max_proto_version(ssl_ctx, max) != 1) {
    return -1;
  }
  return 0;
#else  // !OPENSSL_1_1_API && !defined(NGHTTP2_OPENSSL_IS_BORINGSSL)
  long int opts = 0;

  // TODO We depends on the ordering of protocol version macro in
  // OpenSSL.
  if (min > TLS1_VERSION) {
    opts |= SSL_OP_NO_TLSv1;
  }
  if (min > TLS1_1_VERSION) {
    opts |= SSL_OP_NO_TLSv1_1;
  }
  if (min > TLS1_2_VERSION) {
    opts |= SSL_OP_NO_TLSv1_2;
  }

  if (max < TLS1_2_VERSION) {
    opts |= SSL_OP_NO_TLSv1_2;
  }
  if (max < TLS1_1_VERSION) {
    opts |= SSL_OP_NO_TLSv1_1;
  }

  SSL_CTX_set_options(ssl_ctx, opts);

  return 0;
#endif // !OPENSSL_1_1_API && !defined(NGHTTP2_OPENSSL_IS_BORINGSSL)
}

} // namespace tls

} // namespace nghttp2
