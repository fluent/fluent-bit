/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2021 Tatsuhiro Tsujikawa
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
#include "shrpx_quic_connection_handler.h"

#include <openssl/rand.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#include "shrpx_worker.h"
#include "shrpx_client_handler.h"
#include "shrpx_log.h"
#include "shrpx_http3_upstream.h"
#include "shrpx_connection_handler.h"
#include "ssl_compat.h"

namespace shrpx {

namespace {
void stateless_reset_bucket_regen_timercb(struct ev_loop *loop, ev_timer *w,
                                          int revents) {
  auto quic_conn_handler = static_cast<QUICConnectionHandler *>(w->data);

  quic_conn_handler->on_stateless_reset_bucket_regen();
}
} // namespace

QUICConnectionHandler::QUICConnectionHandler(Worker *worker)
    : worker_{worker},
      stateless_reset_bucket_{SHRPX_QUIC_STATELESS_RESET_BURST} {
  ev_timer_init(&stateless_reset_bucket_regen_timer_,
                stateless_reset_bucket_regen_timercb, 0., 1.);
  stateless_reset_bucket_regen_timer_.data = this;
}

QUICConnectionHandler::~QUICConnectionHandler() {
  ev_timer_stop(worker_->get_loop(), &stateless_reset_bucket_regen_timer_);
}

int QUICConnectionHandler::handle_packet(const UpstreamAddr *faddr,
                                         const Address &remote_addr,
                                         const Address &local_addr,
                                         const ngtcp2_pkt_info &pi,
                                         const uint8_t *data, size_t datalen) {
  int rv;
  ngtcp2_version_cid vc;

  rv = ngtcp2_pkt_decode_version_cid(&vc, data, datalen, SHRPX_QUIC_SCIDLEN);
  switch (rv) {
  case 0:
    break;
  case NGTCP2_ERR_VERSION_NEGOTIATION:
    send_version_negotiation(faddr, vc.version, vc.dcid, vc.dcidlen, vc.scid,
                             vc.scidlen, remote_addr, local_addr);

    return 0;
  default:
    return 0;
  }

  auto config = get_config();

  ngtcp2_cid dcid_key;
  ngtcp2_cid_init(&dcid_key, vc.dcid, vc.dcidlen);

  auto conn_handler = worker_->get_connection_handler();

  ClientHandler *handler;

  auto &quicconf = config->quic;

  auto it = connections_.find(dcid_key);
  if (it == std::end(connections_)) {
    auto cwit = close_waits_.find(dcid_key);
    if (cwit != std::end(close_waits_)) {
      auto cw = (*cwit).second;

      cw->handle_packet(faddr, remote_addr, local_addr, pi, data, datalen);

      return 0;
    }

    if (data[0] & 0x80) {
      if (generate_quic_hashed_connection_id(dcid_key, remote_addr, local_addr,
                                             dcid_key) != 0) {
        return 0;
      }

      it = connections_.find(dcid_key);
      if (it == std::end(connections_)) {
        auto cwit = close_waits_.find(dcid_key);
        if (cwit != std::end(close_waits_)) {
          auto cw = (*cwit).second;

          cw->handle_packet(faddr, remote_addr, local_addr, pi, data, datalen);

          return 0;
        }
      }
    }
  }

  if (it == std::end(connections_)) {
    std::array<uint8_t, SHRPX_QUIC_DECRYPTED_DCIDLEN> decrypted_dcid;

    auto &qkms = conn_handler->get_quic_keying_materials();
    const QUICKeyingMaterial *qkm = nullptr;

    if (vc.dcidlen == SHRPX_QUIC_SCIDLEN) {
      qkm = select_quic_keying_material(
          *qkms.get(), vc.dcid[0] & SHRPX_QUIC_DCID_KM_ID_MASK);

      if (decrypt_quic_connection_id(decrypted_dcid.data(),
                                     vc.dcid + SHRPX_QUIC_CID_PREFIX_OFFSET,
                                     qkm->cid_encryption_key.data()) != 0) {
        return 0;
      }

      if (qkm != &qkms->keying_materials.front() ||
          !std::equal(std::begin(decrypted_dcid),
                      std::begin(decrypted_dcid) + SHRPX_QUIC_CID_PREFIXLEN,
                      worker_->get_cid_prefix())) {
        auto quic_lwp =
            conn_handler->match_quic_lingering_worker_process_cid_prefix(
                decrypted_dcid.data(), decrypted_dcid.size());
        if (quic_lwp) {
          if (conn_handler->forward_quic_packet_to_lingering_worker_process(
                  quic_lwp, remote_addr, local_addr, pi, data, datalen) == 0) {
            return 0;
          }

          return 0;
        }
      }
    }

    // new connection

    auto &upstreamconf = config->conn.upstream;
    if (worker_->get_worker_stat()->num_connections >=
        upstreamconf.worker_connections) {
      if (LOG_ENABLED(INFO)) {
        LOG(INFO) << "Too many connections >="
                  << upstreamconf.worker_connections;
      }

      return 0;
    }

    ngtcp2_pkt_hd hd;
    ngtcp2_cid odcid, *podcid = nullptr;
    const uint8_t *token = nullptr;
    size_t tokenlen = 0;
    ngtcp2_token_type token_type = NGTCP2_TOKEN_TYPE_UNKNOWN;

    switch (ngtcp2_accept(&hd, data, datalen)) {
    case 0: {
      // If we get Initial and it has the CID prefix of this worker,
      // it is likely that client is intentionally use the prefix.
      // Just drop it.
      if (vc.dcidlen == SHRPX_QUIC_SCIDLEN) {
        if (qkm != &qkms->keying_materials.front()) {
          qkm = &qkms->keying_materials.front();

          if (decrypt_quic_connection_id(decrypted_dcid.data(),
                                         vc.dcid + SHRPX_QUIC_CID_PREFIX_OFFSET,
                                         qkm->cid_encryption_key.data()) != 0) {
            return 0;
          }
        }

        if (std::equal(std::begin(decrypted_dcid),
                       std::begin(decrypted_dcid) + SHRPX_QUIC_CID_PREFIXLEN,
                       worker_->get_cid_prefix())) {
          return 0;
        }
      }

      if (worker_->get_graceful_shutdown()) {
        send_connection_close(faddr, hd.version, hd.dcid, hd.scid, remote_addr,
                              local_addr, NGTCP2_CONNECTION_REFUSED,
                              datalen * 3);
        return 0;
      }

      if (hd.tokenlen == 0) {
        if (quicconf.upstream.require_token) {
          send_retry(faddr, vc.version, vc.dcid, vc.dcidlen, vc.scid,
                     vc.scidlen, remote_addr, local_addr, datalen * 3);

          return 0;
        }

        break;
      }

      switch (hd.token[0]) {
      case NGTCP2_CRYPTO_TOKEN_MAGIC_RETRY: {
        if (vc.dcidlen != SHRPX_QUIC_SCIDLEN) {
          // Initial packets with Retry token must have DCID chosen by
          // server.
          return 0;
        }

        auto qkm = select_quic_keying_material(
            *qkms.get(), vc.dcid[0] & SHRPX_QUIC_DCID_KM_ID_MASK);

        if (verify_retry_token(odcid, hd.token, hd.tokenlen, hd.version,
                               hd.dcid, &remote_addr.su.sa, remote_addr.len,
                               qkm->secret.data(), qkm->secret.size()) != 0) {
          if (LOG_ENABLED(INFO)) {
            LOG(INFO) << "Failed to validate Retry token from remote="
                      << util::to_numeric_addr(&remote_addr);
          }

          // 2nd Retry packet is not allowed, so send CONNECTION_CLOSE
          // with INVALID_TOKEN.
          send_connection_close(faddr, hd.version, hd.dcid, hd.scid,
                                remote_addr, local_addr, NGTCP2_INVALID_TOKEN,
                                datalen * 3);
          return 0;
        }

        if (LOG_ENABLED(INFO)) {
          LOG(INFO) << "Successfully validated Retry token from remote="
                    << util::to_numeric_addr(&remote_addr);
        }

        podcid = &odcid;
        token = hd.token;
        tokenlen = hd.tokenlen;
        token_type = NGTCP2_TOKEN_TYPE_RETRY;

        break;
      }
      case NGTCP2_CRYPTO_TOKEN_MAGIC_REGULAR: {
        // If a token is a regular token, it must be at least
        // NGTCP2_MIN_INITIAL_DCIDLEN bytes long.
        if (vc.dcidlen < NGTCP2_MIN_INITIAL_DCIDLEN) {
          return 0;
        }

        if (hd.tokenlen != NGTCP2_CRYPTO_MAX_REGULAR_TOKENLEN + 1) {
          if (LOG_ENABLED(INFO)) {
            LOG(INFO) << "Failed to validate token from remote="
                      << util::to_numeric_addr(&remote_addr);
          }

          if (quicconf.upstream.require_token) {
            send_retry(faddr, vc.version, vc.dcid, vc.dcidlen, vc.scid,
                       vc.scidlen, remote_addr, local_addr, datalen * 3);

            return 0;
          }

          break;
        }

        auto qkm = select_quic_keying_material(
            *qkms.get(), hd.token[NGTCP2_CRYPTO_MAX_REGULAR_TOKENLEN]);

        if (verify_token(hd.token, hd.tokenlen - 1, &remote_addr.su.sa,
                         remote_addr.len, qkm->secret.data(),
                         qkm->secret.size()) != 0) {
          if (LOG_ENABLED(INFO)) {
            LOG(INFO) << "Failed to validate token from remote="
                      << util::to_numeric_addr(&remote_addr);
          }

          if (quicconf.upstream.require_token) {
            send_retry(faddr, vc.version, vc.dcid, vc.dcidlen, vc.scid,
                       vc.scidlen, remote_addr, local_addr, datalen * 3);

            return 0;
          }

          break;
        }

        if (LOG_ENABLED(INFO)) {
          LOG(INFO) << "Successfully validated token from remote="
                    << util::to_numeric_addr(&remote_addr);
        }

        token = hd.token;
        tokenlen = hd.tokenlen;
        token_type = NGTCP2_TOKEN_TYPE_NEW_TOKEN;

        break;
      }
      default:
        if (quicconf.upstream.require_token) {
          send_retry(faddr, vc.version, vc.dcid, vc.dcidlen, vc.scid,
                     vc.scidlen, remote_addr, local_addr, datalen * 3);

          return 0;
        }

        break;
      }

      break;
    }
    default:
      if (!config->single_thread && !(data[0] & 0x80) &&
          vc.dcidlen == SHRPX_QUIC_SCIDLEN &&
          !std::equal(std::begin(decrypted_dcid),
                      std::begin(decrypted_dcid) + SHRPX_QUIC_CID_PREFIXLEN,
                      worker_->get_cid_prefix())) {
        if (conn_handler->forward_quic_packet(faddr, remote_addr, local_addr,
                                              pi, decrypted_dcid.data(), data,
                                              datalen) == 0) {
          return 0;
        }
      }

      if (!(data[0] & 0x80)) {
        // TODO Must be rate limited
        send_stateless_reset(faddr, vc.dcid, vc.dcidlen, remote_addr,
                             local_addr);
      }

      return 0;
    }

    handler = handle_new_connection(faddr, remote_addr, local_addr, hd, podcid,
                                    token, tokenlen, token_type);
    if (handler == nullptr) {
      return 0;
    }
  } else {
    handler = (*it).second;
  }

  if (handler->read_quic(faddr, remote_addr, local_addr, pi, data, datalen) !=
      0) {
    delete handler;
    return 0;
  }

  handler->signal_write();

  return 0;
}

ClientHandler *QUICConnectionHandler::handle_new_connection(
    const UpstreamAddr *faddr, const Address &remote_addr,
    const Address &local_addr, const ngtcp2_pkt_hd &hd, const ngtcp2_cid *odcid,
    const uint8_t *token, size_t tokenlen, ngtcp2_token_type token_type) {
  std::array<char, NI_MAXHOST> host;
  std::array<char, NI_MAXSERV> service;
  int rv;

  rv = getnameinfo(&remote_addr.su.sa, remote_addr.len, host.data(),
                   host.size(), service.data(), service.size(),
                   NI_NUMERICHOST | NI_NUMERICSERV);
  if (rv != 0) {
    LOG(ERROR) << "getnameinfo() failed: " << gai_strerror(rv);

    return nullptr;
  }

  auto ssl_ctx = worker_->get_quic_sv_ssl_ctx();

  assert(ssl_ctx);

  auto ssl = tls::create_ssl(ssl_ctx);
  if (ssl == nullptr) {
    return nullptr;
  }

#if OPENSSL_1_1_1_API && !defined(NGHTTP2_OPENSSL_IS_BORINGSSL)
  assert(SSL_is_quic(ssl));
#endif // OPENSSL_1_1_1_API && !defined(NGHTTP2_OPENSSL_IS_BORINGSSL)

  SSL_set_accept_state(ssl);

  auto config = get_config();
  auto &quicconf = config->quic;

  if (quicconf.upstream.early_data) {
#if OPENSSL_1_1_1_API && !defined(NGHTTP2_OPENSSL_IS_BORINGSSL)
    SSL_set_quic_early_data_enabled(ssl, 1);
#else  // !(OPENSSL_1_1_1_API && !defined(NGHTTP2_OPENSSL_IS_BORINGSSL))
    SSL_set_early_data_enabled(ssl, 1);
#endif // !(OPENSSL_1_1_1_API && !defined(NGHTTP2_OPENSSL_IS_BORINGSSL))
  }

  // Disable TLS session ticket if we don't have working ticket
  // keys.
  if (!worker_->get_ticket_keys()) {
    SSL_set_options(ssl, SSL_OP_NO_TICKET);
  }

  auto handler = std::make_unique<ClientHandler>(
      worker_, faddr->fd, ssl, StringRef{host.data()},
      StringRef{service.data()}, remote_addr.su.sa.sa_family, faddr);

  auto upstream = std::make_unique<Http3Upstream>(handler.get());
  if (upstream->init(faddr, remote_addr, local_addr, hd, odcid, token, tokenlen,
                     token_type) != 0) {
    return nullptr;
  }

  handler->setup_http3_upstream(std::move(upstream));

  return handler.release();
}

namespace {
uint32_t generate_reserved_version(const Address &addr, uint32_t version) {
  uint32_t h = 0x811C9DC5u;
  const uint8_t *p = reinterpret_cast<const uint8_t *>(&addr.su.sa);
  const uint8_t *ep = p + addr.len;

  for (; p != ep; ++p) {
    h ^= *p;
    h *= 0x01000193u;
  }

  version = htonl(version);
  p = (const uint8_t *)&version;
  ep = p + sizeof(version);

  for (; p != ep; ++p) {
    h ^= *p;
    h *= 0x01000193u;
  }

  h &= 0xf0f0f0f0u;
  h |= 0x0a0a0a0au;

  return h;
}
} // namespace

int QUICConnectionHandler::send_retry(
    const UpstreamAddr *faddr, uint32_t version, const uint8_t *ini_dcid,
    size_t ini_dcidlen, const uint8_t *ini_scid, size_t ini_scidlen,
    const Address &remote_addr, const Address &local_addr, size_t max_pktlen) {
  std::array<char, NI_MAXHOST> host;
  std::array<char, NI_MAXSERV> port;

  if (getnameinfo(&remote_addr.su.sa, remote_addr.len, host.data(), host.size(),
                  port.data(), port.size(),
                  NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
    return -1;
  }

  auto config = get_config();
  auto &quicconf = config->quic;

  auto conn_handler = worker_->get_connection_handler();
  auto &qkms = conn_handler->get_quic_keying_materials();
  auto &qkm = qkms->keying_materials.front();

  ngtcp2_cid retry_scid;

  if (generate_quic_retry_connection_id(retry_scid, SHRPX_QUIC_SCIDLEN,
                                        quicconf.server_id.data(), qkm.id,
                                        qkm.cid_encryption_key.data()) != 0) {
    return -1;
  }

  std::array<uint8_t, NGTCP2_CRYPTO_MAX_RETRY_TOKENLEN> token;
  size_t tokenlen;

  ngtcp2_cid idcid, iscid;
  ngtcp2_cid_init(&idcid, ini_dcid, ini_dcidlen);
  ngtcp2_cid_init(&iscid, ini_scid, ini_scidlen);

  if (generate_retry_token(token.data(), tokenlen, version, &remote_addr.su.sa,
                           remote_addr.len, retry_scid, idcid,
                           qkm.secret.data(), qkm.secret.size()) != 0) {
    return -1;
  }

  std::vector<uint8_t> buf;
  buf.resize(std::min(max_pktlen, static_cast<size_t>(256)));

  auto nwrite =
      ngtcp2_crypto_write_retry(buf.data(), buf.size(), version, &iscid,
                                &retry_scid, &idcid, token.data(), tokenlen);
  if (nwrite < 0) {
    LOG(ERROR) << "ngtcp2_crypto_write_retry: " << ngtcp2_strerror(nwrite);
    return -1;
  }

  buf.resize(nwrite);

  quic_send_packet(faddr, &remote_addr.su.sa, remote_addr.len,
                   &local_addr.su.sa, local_addr.len, ngtcp2_pkt_info{},
                   buf.data(), buf.size(), 0);

  if (generate_quic_hashed_connection_id(idcid, remote_addr, local_addr,
                                         idcid) != 0) {
    return -1;
  }

  auto d =
      static_cast<ev_tstamp>(NGTCP2_DEFAULT_INITIAL_RTT * 3) / NGTCP2_SECONDS;

  if (LOG_ENABLED(INFO)) {
    LOG(INFO) << "Enter close-wait period " << d << "s with " << buf.size()
              << " bytes sentinel packet";
  }

  auto cw = std::make_unique<CloseWait>(worker_, std::vector<ngtcp2_cid>{idcid},
                                        std::move(buf), d);

  add_close_wait(cw.release());

  return 0;
}

int QUICConnectionHandler::send_version_negotiation(
    const UpstreamAddr *faddr, uint32_t version, const uint8_t *ini_dcid,
    size_t ini_dcidlen, const uint8_t *ini_scid, size_t ini_scidlen,
    const Address &remote_addr, const Address &local_addr) {
  std::array<uint32_t, 2> sv{
      generate_reserved_version(remote_addr, version),
      NGTCP2_PROTO_VER_V1,
  };

  std::array<uint8_t, NGTCP2_MAX_UDP_PAYLOAD_SIZE> buf;

  uint8_t rand_byte;
  util::random_bytes(&rand_byte, &rand_byte + 1, worker_->get_randgen());

  auto nwrite = ngtcp2_pkt_write_version_negotiation(
      buf.data(), buf.size(), rand_byte, ini_scid, ini_scidlen, ini_dcid,
      ini_dcidlen, sv.data(), sv.size());
  if (nwrite < 0) {
    LOG(ERROR) << "ngtcp2_pkt_write_version_negotiation: "
               << ngtcp2_strerror(nwrite);
    return -1;
  }

  return quic_send_packet(faddr, &remote_addr.su.sa, remote_addr.len,
                          &local_addr.su.sa, local_addr.len, ngtcp2_pkt_info{},
                          buf.data(), nwrite, 0);
}

int QUICConnectionHandler::send_stateless_reset(const UpstreamAddr *faddr,
                                                const uint8_t *dcid,
                                                size_t dcidlen,
                                                const Address &remote_addr,
                                                const Address &local_addr) {
  if (stateless_reset_bucket_ == 0) {
    if (LOG_ENABLED(INFO)) {
      LOG(INFO) << "Stateless Reset bucket has been depleted";
    }

    return 0;
  }

  --stateless_reset_bucket_;

  if (!ev_is_active(&stateless_reset_bucket_regen_timer_)) {
    ev_timer_again(worker_->get_loop(), &stateless_reset_bucket_regen_timer_);
  }

  int rv;
  std::array<uint8_t, NGTCP2_STATELESS_RESET_TOKENLEN> token;
  ngtcp2_cid cid;

  ngtcp2_cid_init(&cid, dcid, dcidlen);

  auto conn_handler = worker_->get_connection_handler();
  auto &qkms = conn_handler->get_quic_keying_materials();
  auto &qkm = qkms->keying_materials.front();

  rv = generate_quic_stateless_reset_token(token.data(), cid, qkm.secret.data(),
                                           qkm.secret.size());
  if (rv != 0) {
    return -1;
  }

  std::array<uint8_t, NGTCP2_MIN_STATELESS_RESET_RANDLEN> rand_bytes;

  if (RAND_bytes(rand_bytes.data(), rand_bytes.size()) != 1) {
    return -1;
  }

  std::array<uint8_t, NGTCP2_MAX_UDP_PAYLOAD_SIZE> buf;

  auto nwrite =
      ngtcp2_pkt_write_stateless_reset(buf.data(), buf.size(), token.data(),
                                       rand_bytes.data(), rand_bytes.size());
  if (nwrite < 0) {
    LOG(ERROR) << "ngtcp2_pkt_write_stateless_reset: "
               << ngtcp2_strerror(nwrite);
    return -1;
  }

  if (LOG_ENABLED(INFO)) {
    LOG(INFO) << "Send stateless_reset to remote="
              << util::to_numeric_addr(&remote_addr)
              << " dcid=" << util::format_hex(dcid, dcidlen);
  }

  return quic_send_packet(faddr, &remote_addr.su.sa, remote_addr.len,
                          &local_addr.su.sa, local_addr.len, ngtcp2_pkt_info{},
                          buf.data(), nwrite, 0);
}

int QUICConnectionHandler::send_connection_close(
    const UpstreamAddr *faddr, uint32_t version, const ngtcp2_cid &ini_dcid,
    const ngtcp2_cid &ini_scid, const Address &remote_addr,
    const Address &local_addr, uint64_t error_code, size_t max_pktlen) {
  std::array<uint8_t, NGTCP2_MAX_UDP_PAYLOAD_SIZE> buf;

  max_pktlen = std::min(max_pktlen, buf.size());

  auto nwrite = ngtcp2_crypto_write_connection_close(
      buf.data(), max_pktlen, version, &ini_scid, &ini_dcid, error_code,
      nullptr, 0);
  if (nwrite < 0) {
    LOG(ERROR) << "ngtcp2_crypto_write_connection_close failed";
    return -1;
  }

  if (LOG_ENABLED(INFO)) {
    LOG(INFO) << "Send Initial CONNECTION_CLOSE with error_code=" << log::hex
              << error_code << log::dec
              << " to remote=" << util::to_numeric_addr(&remote_addr)
              << " dcid=" << util::format_hex(ini_scid.data, ini_scid.datalen)
              << " scid=" << util::format_hex(ini_dcid.data, ini_dcid.datalen);
  }

  return quic_send_packet(faddr, &remote_addr.su.sa, remote_addr.len,
                          &local_addr.su.sa, local_addr.len, ngtcp2_pkt_info{},
                          buf.data(), nwrite, 0);
}

void QUICConnectionHandler::add_connection_id(const ngtcp2_cid &cid,
                                              ClientHandler *handler) {
  connections_.emplace(cid, handler);
}

void QUICConnectionHandler::remove_connection_id(const ngtcp2_cid &cid) {
  connections_.erase(cid);
}

void QUICConnectionHandler::add_close_wait(CloseWait *cw) {
  for (auto &cid : cw->scids) {
    close_waits_.emplace(cid, cw);
  }
}

void QUICConnectionHandler::remove_close_wait(const CloseWait *cw) {
  for (auto &cid : cw->scids) {
    close_waits_.erase(cid);
  }
}

void QUICConnectionHandler::on_stateless_reset_bucket_regen() {
  assert(stateless_reset_bucket_ < SHRPX_QUIC_STATELESS_RESET_BURST);

  if (++stateless_reset_bucket_ == SHRPX_QUIC_STATELESS_RESET_BURST) {
    ev_timer_stop(worker_->get_loop(), &stateless_reset_bucket_regen_timer_);
  }
}

static void close_wait_timeoutcb(struct ev_loop *loop, ev_timer *w,
                                 int revents) {
  auto cw = static_cast<CloseWait *>(w->data);

  if (LOG_ENABLED(INFO)) {
    LOG(INFO) << "close-wait period finished";
  }

  auto quic_conn_handler = cw->worker->get_quic_connection_handler();
  quic_conn_handler->remove_close_wait(cw);

  delete cw;
}

CloseWait::CloseWait(Worker *worker, std::vector<ngtcp2_cid> scids,
                     std::vector<uint8_t> pkt, ev_tstamp period)
    : worker{worker},
      scids{std::move(scids)},
      pkt{std::move(pkt)},
      bytes_recv{0},
      bytes_sent{0},
      num_pkts_recv{0},
      next_pkts_recv{1} {
  ++worker->get_worker_stat()->num_close_waits;

  ev_timer_init(&timer, close_wait_timeoutcb, period, 0.);
  timer.data = this;

  ev_timer_start(worker->get_loop(), &timer);
}

CloseWait::~CloseWait() {
  auto loop = worker->get_loop();

  ev_timer_stop(loop, &timer);

  auto worker_stat = worker->get_worker_stat();
  --worker_stat->num_close_waits;

  if (worker->get_graceful_shutdown() && worker_stat->num_connections == 0 &&
      worker_stat->num_close_waits == 0) {
    ev_break(loop);
  }
}

int CloseWait::handle_packet(const UpstreamAddr *faddr,
                             const Address &remote_addr,
                             const Address &local_addr,
                             const ngtcp2_pkt_info &pi, const uint8_t *data,
                             size_t datalen) {
  if (pkt.empty()) {
    return 0;
  }

  ++num_pkts_recv;
  bytes_recv += datalen;

  if (bytes_sent + pkt.size() > 3 * bytes_recv ||
      next_pkts_recv > num_pkts_recv) {
    return 0;
  }

  if (quic_send_packet(faddr, &remote_addr.su.sa, remote_addr.len,
                       &local_addr.su.sa, local_addr.len, ngtcp2_pkt_info{},
                       pkt.data(), pkt.size(), 0) != 0) {
    return -1;
  }

  next_pkts_recv *= 2;
  bytes_sent += pkt.size();

  return 0;
}

} // namespace shrpx
