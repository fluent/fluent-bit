/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2012 Tatsuhiro Tsujikawa
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
#include "shrpx_worker.h"

#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif // HAVE_UNISTD_H
#include <netinet/udp.h>

#include <cstdio>
#include <memory>

#include <openssl/rand.h>

#ifdef HAVE_LIBBPF
#  include <bpf/bpf.h>
#  include <bpf/libbpf.h>
#endif // HAVE_LIBBPF

#include "shrpx_tls.h"
#include "shrpx_log.h"
#include "shrpx_client_handler.h"
#include "shrpx_http2_session.h"
#include "shrpx_log_config.h"
#include "shrpx_memcached_dispatcher.h"
#ifdef HAVE_MRUBY
#  include "shrpx_mruby.h"
#endif // HAVE_MRUBY
#ifdef ENABLE_HTTP3
#  include "shrpx_quic_listener.h"
#endif // ENABLE_HTTP3
#include "shrpx_connection_handler.h"
#include "util.h"
#include "template.h"
#include "xsi_strerror.h"

namespace shrpx {

namespace {
void eventcb(struct ev_loop *loop, ev_async *w, int revents) {
  auto worker = static_cast<Worker *>(w->data);
  worker->process_events();
}
} // namespace

namespace {
void mcpool_clear_cb(struct ev_loop *loop, ev_timer *w, int revents) {
  auto worker = static_cast<Worker *>(w->data);
  if (worker->get_worker_stat()->num_connections != 0) {
    return;
  }
  auto mcpool = worker->get_mcpool();
  if (mcpool->freelistsize == mcpool->poolsize) {
    worker->get_mcpool()->clear();
  }
}
} // namespace

namespace {
void proc_wev_cb(struct ev_loop *loop, ev_timer *w, int revents) {
  auto worker = static_cast<Worker *>(w->data);
  worker->process_events();
}
} // namespace

DownstreamAddrGroup::DownstreamAddrGroup() : retired{false} {}

DownstreamAddrGroup::~DownstreamAddrGroup() {}

// DownstreamKey is used to index SharedDownstreamAddr in order to
// find the same configuration.
using DownstreamKey = std::tuple<
    std::vector<
        std::tuple<StringRef, StringRef, StringRef, size_t, size_t, Proto,
                   uint32_t, uint32_t, uint32_t, bool, bool, bool, bool>>,
    bool, SessionAffinity, StringRef, StringRef, SessionAffinityCookieSecure,
    SessionAffinityCookieStickiness, int64_t, int64_t, StringRef, bool>;

namespace {
DownstreamKey
create_downstream_key(const std::shared_ptr<SharedDownstreamAddr> &shared_addr,
                      const StringRef &mruby_file) {
  DownstreamKey dkey;

  auto &addrs = std::get<0>(dkey);
  addrs.resize(shared_addr->addrs.size());
  auto p = std::begin(addrs);
  for (auto &a : shared_addr->addrs) {
    std::get<0>(*p) = a.host;
    std::get<1>(*p) = a.sni;
    std::get<2>(*p) = a.group;
    std::get<3>(*p) = a.fall;
    std::get<4>(*p) = a.rise;
    std::get<5>(*p) = a.proto;
    std::get<6>(*p) = a.port;
    std::get<7>(*p) = a.weight;
    std::get<8>(*p) = a.group_weight;
    std::get<9>(*p) = a.host_unix;
    std::get<10>(*p) = a.tls;
    std::get<11>(*p) = a.dns;
    std::get<12>(*p) = a.upgrade_scheme;
    ++p;
  }
  std::sort(std::begin(addrs), std::end(addrs));

  std::get<1>(dkey) = shared_addr->redirect_if_not_tls;

  auto &affinity = shared_addr->affinity;
  std::get<2>(dkey) = affinity.type;
  std::get<3>(dkey) = affinity.cookie.name;
  std::get<4>(dkey) = affinity.cookie.path;
  std::get<5>(dkey) = affinity.cookie.secure;
  std::get<6>(dkey) = affinity.cookie.stickiness;
  auto &timeout = shared_addr->timeout;
  std::get<7>(dkey) = timeout.read;
  std::get<8>(dkey) = timeout.write;
  std::get<9>(dkey) = mruby_file;
  std::get<10>(dkey) = shared_addr->dnf;

  return dkey;
}
} // namespace

Worker::Worker(struct ev_loop *loop, SSL_CTX *sv_ssl_ctx, SSL_CTX *cl_ssl_ctx,
               SSL_CTX *tls_session_cache_memcached_ssl_ctx,
               tls::CertLookupTree *cert_tree,
#ifdef ENABLE_HTTP3
               SSL_CTX *quic_sv_ssl_ctx, tls::CertLookupTree *quic_cert_tree,
               const uint8_t *cid_prefix, size_t cid_prefixlen,
#  ifdef HAVE_LIBBPF
               size_t index,
#  endif // HAVE_LIBBPF
#endif   // ENABLE_HTTP3
               const std::shared_ptr<TicketKeys> &ticket_keys,
               ConnectionHandler *conn_handler,
               std::shared_ptr<DownstreamConfig> downstreamconf)
    :
#if defined(ENABLE_HTTP3) && defined(HAVE_LIBBPF)
      index_{index},
#endif // ENABLE_HTTP3 && HAVE_LIBBPF
      randgen_(util::make_mt19937()),
      worker_stat_{},
      dns_tracker_(loop, get_config()->conn.downstream->family),
#ifdef ENABLE_HTTP3
      quic_upstream_addrs_{get_config()->conn.quic_listener.addrs},
#endif // ENABLE_HTTP3
      loop_(loop),
      sv_ssl_ctx_(sv_ssl_ctx),
      cl_ssl_ctx_(cl_ssl_ctx),
      cert_tree_(cert_tree),
      conn_handler_(conn_handler),
#ifdef ENABLE_HTTP3
      quic_sv_ssl_ctx_{quic_sv_ssl_ctx},
      quic_cert_tree_{quic_cert_tree},
      quic_conn_handler_{this},
#endif // ENABLE_HTTP3
      ticket_keys_(ticket_keys),
      connect_blocker_(
          std::make_unique<ConnectBlocker>(randgen_, loop_, nullptr, nullptr)),
      graceful_shutdown_(false) {
#ifdef ENABLE_HTTP3
  std::copy_n(cid_prefix, cid_prefixlen, std::begin(cid_prefix_));
#endif // ENABLE_HTTP3

  ev_async_init(&w_, eventcb);
  w_.data = this;
  ev_async_start(loop_, &w_);

  ev_timer_init(&mcpool_clear_timer_, mcpool_clear_cb, 0., 0.);
  mcpool_clear_timer_.data = this;

  ev_timer_init(&proc_wev_timer_, proc_wev_cb, 0., 0.);
  proc_wev_timer_.data = this;

  auto &session_cacheconf = get_config()->tls.session_cache;

  if (!session_cacheconf.memcached.host.empty()) {
    session_cache_memcached_dispatcher_ = std::make_unique<MemcachedDispatcher>(
        &session_cacheconf.memcached.addr, loop,
        tls_session_cache_memcached_ssl_ctx,
        StringRef{session_cacheconf.memcached.host}, &mcpool_, randgen_);
  }

  replace_downstream_config(std::move(downstreamconf));
}

namespace {
void ensure_enqueue_addr(
    std::priority_queue<WeightGroupEntry, std::vector<WeightGroupEntry>,
                        WeightGroupEntryGreater> &wgpq,
    WeightGroup *wg, DownstreamAddr *addr) {
  uint32_t cycle;
  if (!wg->pq.empty()) {
    auto &top = wg->pq.top();
    cycle = top.cycle;
  } else {
    cycle = 0;
  }

  addr->cycle = cycle;
  addr->pending_penalty = 0;
  wg->pq.push(DownstreamAddrEntry{addr, addr->seq, addr->cycle});
  addr->queued = true;

  if (!wg->queued) {
    if (!wgpq.empty()) {
      auto &top = wgpq.top();
      cycle = top.cycle;
    } else {
      cycle = 0;
    }

    wg->cycle = cycle;
    wg->pending_penalty = 0;
    wgpq.push(WeightGroupEntry{wg, wg->seq, wg->cycle});
    wg->queued = true;
  }
}
} // namespace

void Worker::replace_downstream_config(
    std::shared_ptr<DownstreamConfig> downstreamconf) {
  for (auto &g : downstream_addr_groups_) {
    g->retired = true;

    auto &shared_addr = g->shared_addr;
    for (auto &addr : shared_addr->addrs) {
      addr.dconn_pool->remove_all();
    }
  }

  downstreamconf_ = downstreamconf;

  // Making a copy is much faster with multiple thread on
  // backendconfig API call.
  auto groups = downstreamconf->addr_groups;

  downstream_addr_groups_ =
      std::vector<std::shared_ptr<DownstreamAddrGroup>>(groups.size());

  std::map<DownstreamKey, size_t> addr_groups_indexer;
#ifdef HAVE_MRUBY
  // TODO It is a bit less efficient because
  // mruby::create_mruby_context returns std::unique_ptr and we cannot
  // use std::make_shared.
  std::map<StringRef, std::shared_ptr<mruby::MRubyContext>> shared_mruby_ctxs;
#endif // HAVE_MRUBY

  for (size_t i = 0; i < groups.size(); ++i) {
    auto &src = groups[i];
    auto &dst = downstream_addr_groups_[i];

    dst = std::make_shared<DownstreamAddrGroup>();
    dst->pattern =
        ImmutableString{std::begin(src.pattern), std::end(src.pattern)};

    auto shared_addr = std::make_shared<SharedDownstreamAddr>();

    shared_addr->addrs.resize(src.addrs.size());
    shared_addr->affinity.type = src.affinity.type;
    if (src.affinity.type == SessionAffinity::COOKIE) {
      shared_addr->affinity.cookie.name =
          make_string_ref(shared_addr->balloc, src.affinity.cookie.name);
      if (!src.affinity.cookie.path.empty()) {
        shared_addr->affinity.cookie.path =
            make_string_ref(shared_addr->balloc, src.affinity.cookie.path);
      }
      shared_addr->affinity.cookie.secure = src.affinity.cookie.secure;
      shared_addr->affinity.cookie.stickiness = src.affinity.cookie.stickiness;
    }
    shared_addr->affinity_hash = src.affinity_hash;
    shared_addr->affinity_hash_map = src.affinity_hash_map;
    shared_addr->redirect_if_not_tls = src.redirect_if_not_tls;
    shared_addr->dnf = src.dnf;
    shared_addr->timeout.read = src.timeout.read;
    shared_addr->timeout.write = src.timeout.write;

    for (size_t j = 0; j < src.addrs.size(); ++j) {
      auto &src_addr = src.addrs[j];
      auto &dst_addr = shared_addr->addrs[j];

      dst_addr.addr = src_addr.addr;
      dst_addr.host = make_string_ref(shared_addr->balloc, src_addr.host);
      dst_addr.hostport =
          make_string_ref(shared_addr->balloc, src_addr.hostport);
      dst_addr.port = src_addr.port;
      dst_addr.host_unix = src_addr.host_unix;
      dst_addr.weight = src_addr.weight;
      dst_addr.group = make_string_ref(shared_addr->balloc, src_addr.group);
      dst_addr.group_weight = src_addr.group_weight;
      dst_addr.affinity_hash = src_addr.affinity_hash;
      dst_addr.proto = src_addr.proto;
      dst_addr.tls = src_addr.tls;
      dst_addr.sni = make_string_ref(shared_addr->balloc, src_addr.sni);
      dst_addr.fall = src_addr.fall;
      dst_addr.rise = src_addr.rise;
      dst_addr.dns = src_addr.dns;
      dst_addr.upgrade_scheme = src_addr.upgrade_scheme;
    }

#ifdef HAVE_MRUBY
    auto mruby_ctx_it = shared_mruby_ctxs.find(src.mruby_file);
    if (mruby_ctx_it == std::end(shared_mruby_ctxs)) {
      shared_addr->mruby_ctx = mruby::create_mruby_context(src.mruby_file);
      assert(shared_addr->mruby_ctx);
      shared_mruby_ctxs.emplace(src.mruby_file, shared_addr->mruby_ctx);
    } else {
      shared_addr->mruby_ctx = (*mruby_ctx_it).second;
    }
#endif // HAVE_MRUBY

    // share the connection if patterns have the same set of backend
    // addresses.

    auto dkey = create_downstream_key(shared_addr, src.mruby_file);
    auto it = addr_groups_indexer.find(dkey);

    if (it == std::end(addr_groups_indexer)) {
      auto shared_addr_ptr = shared_addr.get();

      for (auto &addr : shared_addr->addrs) {
        addr.connect_blocker = std::make_unique<ConnectBlocker>(
            randgen_, loop_, nullptr, [shared_addr_ptr, &addr]() {
              if (!addr.queued) {
                if (!addr.wg) {
                  return;
                }
                ensure_enqueue_addr(shared_addr_ptr->pq, addr.wg, &addr);
              }
            });

        addr.live_check = std::make_unique<LiveCheck>(loop_, cl_ssl_ctx_, this,
                                                      &addr, randgen_);
      }

      size_t seq = 0;
      for (auto &addr : shared_addr->addrs) {
        addr.dconn_pool = std::make_unique<DownstreamConnectionPool>();
        addr.seq = seq++;
      }

      util::shuffle(std::begin(shared_addr->addrs),
                    std::end(shared_addr->addrs), randgen_,
                    [](auto i, auto j) { std::swap((*i).seq, (*j).seq); });

      if (shared_addr->affinity.type == SessionAffinity::NONE) {
        std::map<StringRef, WeightGroup *> wgs;
        size_t num_wgs = 0;
        for (auto &addr : shared_addr->addrs) {
          if (wgs.find(addr.group) == std::end(wgs)) {
            ++num_wgs;
            wgs.emplace(addr.group, nullptr);
          }
        }

        shared_addr->wgs = std::vector<WeightGroup>(num_wgs);

        for (auto &addr : shared_addr->addrs) {
          auto &wg = wgs[addr.group];
          if (wg == nullptr) {
            wg = &shared_addr->wgs[--num_wgs];
            wg->seq = num_wgs;
          }

          wg->weight = addr.group_weight;
          wg->pq.push(DownstreamAddrEntry{&addr, addr.seq, addr.cycle});
          addr.queued = true;
          addr.wg = wg;
        }

        assert(num_wgs == 0);

        for (auto &kv : wgs) {
          shared_addr->pq.push(
              WeightGroupEntry{kv.second, kv.second->seq, kv.second->cycle});
          kv.second->queued = true;
        }
      }

      dst->shared_addr = shared_addr;

      addr_groups_indexer.emplace(std::move(dkey), i);
    } else {
      auto &g = *(std::begin(downstream_addr_groups_) + (*it).second);
      if (LOG_ENABLED(INFO)) {
        LOG(INFO) << dst->pattern << " shares the same backend group with "
                  << g->pattern;
      }
      dst->shared_addr = g->shared_addr;
    }
  }
}

Worker::~Worker() {
  ev_async_stop(loop_, &w_);
  ev_timer_stop(loop_, &mcpool_clear_timer_);
  ev_timer_stop(loop_, &proc_wev_timer_);
}

void Worker::schedule_clear_mcpool() {
  // libev manual says: "If the watcher is already active nothing will
  // happen."  Since we don't change any timeout here, we don't have
  // to worry about querying ev_is_active.
  ev_timer_start(loop_, &mcpool_clear_timer_);
}

void Worker::wait() {
#ifndef NOTHREADS
  fut_.get();
#endif // !NOTHREADS
}

void Worker::run_async() {
#ifndef NOTHREADS
  fut_ = std::async(std::launch::async, [this] {
    (void)reopen_log_files(get_config()->logging);
    ev_run(loop_);
    delete_log_config();
  });
#endif // !NOTHREADS
}

void Worker::send(WorkerEvent event) {
  {
    std::lock_guard<std::mutex> g(m_);

    q_.emplace_back(std::move(event));
  }

  ev_async_send(loop_, &w_);
}

void Worker::process_events() {
  WorkerEvent wev;
  {
    std::lock_guard<std::mutex> g(m_);

    // Process event one at a time.  This is important for
    // WorkerEventType::NEW_CONNECTION event since accepting large
    // number of new connections at once may delay time to 1st byte
    // for existing connections.

    if (q_.empty()) {
      ev_timer_stop(loop_, &proc_wev_timer_);
      return;
    }

    wev = std::move(q_.front());
    q_.pop_front();
  }

  ev_timer_start(loop_, &proc_wev_timer_);

  auto config = get_config();

  auto worker_connections = config->conn.upstream.worker_connections;

  switch (wev.type) {
  case WorkerEventType::NEW_CONNECTION: {
    if (LOG_ENABLED(INFO)) {
      WLOG(INFO, this) << "WorkerEvent: client_fd=" << wev.client_fd
                       << ", addrlen=" << wev.client_addrlen;
    }

    if (worker_stat_.num_connections >= worker_connections) {

      if (LOG_ENABLED(INFO)) {
        WLOG(INFO, this) << "Too many connections >= " << worker_connections;
      }

      close(wev.client_fd);

      break;
    }

    auto client_handler =
        tls::accept_connection(this, wev.client_fd, &wev.client_addr.sa,
                               wev.client_addrlen, wev.faddr);
    if (!client_handler) {
      if (LOG_ENABLED(INFO)) {
        WLOG(ERROR, this) << "ClientHandler creation failed";
      }
      close(wev.client_fd);
      break;
    }

    if (LOG_ENABLED(INFO)) {
      WLOG(INFO, this) << "CLIENT_HANDLER:" << client_handler << " created ";
    }

    break;
  }
  case WorkerEventType::REOPEN_LOG:
    WLOG(NOTICE, this) << "Reopening log files: worker process (thread " << this
                       << ")";

    reopen_log_files(config->logging);

    break;
  case WorkerEventType::GRACEFUL_SHUTDOWN:
    WLOG(NOTICE, this) << "Graceful shutdown commencing";

    graceful_shutdown_ = true;

    if (worker_stat_.num_connections == 0 &&
        worker_stat_.num_close_waits == 0) {
      ev_break(loop_);

      return;
    }

    break;
  case WorkerEventType::REPLACE_DOWNSTREAM:
    WLOG(NOTICE, this) << "Replace downstream";

    replace_downstream_config(wev.downstreamconf);

    break;
#ifdef ENABLE_HTTP3
  case WorkerEventType::QUIC_PKT_FORWARD: {
    const UpstreamAddr *faddr;

    if (wev.quic_pkt->upstream_addr_index == static_cast<size_t>(-1)) {
      faddr = find_quic_upstream_addr(wev.quic_pkt->local_addr);
      if (faddr == nullptr) {
        LOG(ERROR) << "No suitable upstream address found";

        break;
      }
    } else if (quic_upstream_addrs_.size() <=
               wev.quic_pkt->upstream_addr_index) {
      LOG(ERROR) << "upstream_addr_index is too large";

      break;
    } else {
      faddr = &quic_upstream_addrs_[wev.quic_pkt->upstream_addr_index];
    }

    quic_conn_handler_.handle_packet(
        faddr, wev.quic_pkt->remote_addr, wev.quic_pkt->local_addr,
        wev.quic_pkt->pi, wev.quic_pkt->data.data(), wev.quic_pkt->data.size());

    break;
  }
#endif // ENABLE_HTTP3
  default:
    if (LOG_ENABLED(INFO)) {
      WLOG(INFO, this) << "unknown event type " << static_cast<int>(wev.type);
    }
  }
}

tls::CertLookupTree *Worker::get_cert_lookup_tree() const { return cert_tree_; }

#ifdef ENABLE_HTTP3
tls::CertLookupTree *Worker::get_quic_cert_lookup_tree() const {
  return quic_cert_tree_;
}
#endif // ENABLE_HTTP3

std::shared_ptr<TicketKeys> Worker::get_ticket_keys() {
#ifdef HAVE_ATOMIC_STD_SHARED_PTR
  return std::atomic_load_explicit(&ticket_keys_, std::memory_order_acquire);
#else  // !HAVE_ATOMIC_STD_SHARED_PTR
  std::lock_guard<std::mutex> g(ticket_keys_m_);
  return ticket_keys_;
#endif // !HAVE_ATOMIC_STD_SHARED_PTR
}

void Worker::set_ticket_keys(std::shared_ptr<TicketKeys> ticket_keys) {
#ifdef HAVE_ATOMIC_STD_SHARED_PTR
  // This is single writer
  std::atomic_store_explicit(&ticket_keys_, std::move(ticket_keys),
                             std::memory_order_release);
#else  // !HAVE_ATOMIC_STD_SHARED_PTR
  std::lock_guard<std::mutex> g(ticket_keys_m_);
  ticket_keys_ = std::move(ticket_keys);
#endif // !HAVE_ATOMIC_STD_SHARED_PTR
}

WorkerStat *Worker::get_worker_stat() { return &worker_stat_; }

struct ev_loop *Worker::get_loop() const { return loop_; }

SSL_CTX *Worker::get_sv_ssl_ctx() const { return sv_ssl_ctx_; }

SSL_CTX *Worker::get_cl_ssl_ctx() const { return cl_ssl_ctx_; }

#ifdef ENABLE_HTTP3
SSL_CTX *Worker::get_quic_sv_ssl_ctx() const { return quic_sv_ssl_ctx_; }
#endif // ENABLE_HTTP3

void Worker::set_graceful_shutdown(bool f) { graceful_shutdown_ = f; }

bool Worker::get_graceful_shutdown() const { return graceful_shutdown_; }

MemchunkPool *Worker::get_mcpool() { return &mcpool_; }

MemcachedDispatcher *Worker::get_session_cache_memcached_dispatcher() {
  return session_cache_memcached_dispatcher_.get();
}

std::mt19937 &Worker::get_randgen() { return randgen_; }

#ifdef HAVE_MRUBY
int Worker::create_mruby_context() {
  mruby_ctx_ = mruby::create_mruby_context(StringRef{get_config()->mruby_file});
  if (!mruby_ctx_) {
    return -1;
  }

  return 0;
}

mruby::MRubyContext *Worker::get_mruby_context() const {
  return mruby_ctx_.get();
}
#endif // HAVE_MRUBY

std::vector<std::shared_ptr<DownstreamAddrGroup>> &
Worker::get_downstream_addr_groups() {
  return downstream_addr_groups_;
}

ConnectBlocker *Worker::get_connect_blocker() const {
  return connect_blocker_.get();
}

const DownstreamConfig *Worker::get_downstream_config() const {
  return downstreamconf_.get();
}

ConnectionHandler *Worker::get_connection_handler() const {
  return conn_handler_;
}

#ifdef ENABLE_HTTP3
QUICConnectionHandler *Worker::get_quic_connection_handler() {
  return &quic_conn_handler_;
}
#endif // ENABLE_HTTP3

DNSTracker *Worker::get_dns_tracker() { return &dns_tracker_; }

#ifdef ENABLE_HTTP3
#  ifdef HAVE_LIBBPF
bool Worker::should_attach_bpf() const {
  auto config = get_config();
  auto &quicconf = config->quic;
  auto &apiconf = config->api;

  if (quicconf.bpf.disabled) {
    return false;
  }

  if (!config->single_thread && apiconf.enabled) {
    return index_ == 1;
  }

  return index_ == 0;
}

bool Worker::should_update_bpf_map() const {
  auto config = get_config();
  auto &quicconf = config->quic;

  return !quicconf.bpf.disabled;
}

uint32_t Worker::compute_sk_index() const {
  auto config = get_config();
  auto &apiconf = config->api;

  if (!config->single_thread && apiconf.enabled) {
    return index_ - 1;
  }

  return index_;
}
#  endif // HAVE_LIBBPF

int Worker::setup_quic_server_socket() {
  size_t n = 0;

  for (auto &addr : quic_upstream_addrs_) {
    assert(!addr.host_unix);
    if (create_quic_server_socket(addr) != 0) {
      return -1;
    }

    // Make sure that each endpoint has a unique address.
    for (size_t i = 0; i < n; ++i) {
      const auto &a = quic_upstream_addrs_[i];

      if (addr.hostport == a.hostport) {
        LOG(FATAL)
            << "QUIC frontend endpoint must be unique: a duplicate found for "
            << addr.hostport;

        return -1;
      }
    }

    ++n;

    quic_listeners_.emplace_back(std::make_unique<QUICListener>(&addr, this));
  }

  return 0;
}

int Worker::create_quic_server_socket(UpstreamAddr &faddr) {
  std::array<char, STRERROR_BUFSIZE> errbuf;
  int fd = -1;
  int rv;

  auto service = util::utos(faddr.port);
  addrinfo hints{};
  hints.ai_family = faddr.family;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;
#  ifdef AI_ADDRCONFIG
  hints.ai_flags |= AI_ADDRCONFIG;
#  endif // AI_ADDRCONFIG

  auto node =
      faddr.host == StringRef::from_lit("*") ? nullptr : faddr.host.c_str();

  addrinfo *res, *rp;
  rv = getaddrinfo(node, service.c_str(), &hints, &res);
#  ifdef AI_ADDRCONFIG
  if (rv != 0) {
    // Retry without AI_ADDRCONFIG
    hints.ai_flags &= ~AI_ADDRCONFIG;
    rv = getaddrinfo(node, service.c_str(), &hints, &res);
  }
#  endif // AI_ADDRCONFIG
  if (rv != 0) {
    LOG(FATAL) << "Unable to get IPv" << (faddr.family == AF_INET ? "4" : "6")
               << " address for " << faddr.host << ", port " << faddr.port
               << ": " << gai_strerror(rv);
    return -1;
  }

  auto res_d = defer(freeaddrinfo, res);

  std::array<char, NI_MAXHOST> host;

  for (rp = res; rp; rp = rp->ai_next) {
    rv = getnameinfo(rp->ai_addr, rp->ai_addrlen, host.data(), host.size(),
                     nullptr, 0, NI_NUMERICHOST);
    if (rv != 0) {
      LOG(WARN) << "getnameinfo() failed: " << gai_strerror(rv);
      continue;
    }

#  ifdef SOCK_NONBLOCK
    fd = socket(rp->ai_family, rp->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC,
                rp->ai_protocol);
    if (fd == -1) {
      auto error = errno;
      LOG(WARN) << "socket() syscall failed: "
                << xsi_strerror(error, errbuf.data(), errbuf.size());
      continue;
    }
#  else  // !SOCK_NONBLOCK
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd == -1) {
      auto error = errno;
      LOG(WARN) << "socket() syscall failed: "
                << xsi_strerror(error, errbuf.data(), errbuf.size());
      continue;
    }
    util::make_socket_nonblocking(fd);
    util::make_socket_closeonexec(fd);
#  endif // !SOCK_NONBLOCK

    int val = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val,
                   static_cast<socklen_t>(sizeof(val))) == -1) {
      auto error = errno;
      LOG(WARN) << "Failed to set SO_REUSEADDR option to listener socket: "
                << xsi_strerror(error, errbuf.data(), errbuf.size());
      close(fd);
      continue;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &val,
                   static_cast<socklen_t>(sizeof(val))) == -1) {
      auto error = errno;
      LOG(WARN) << "Failed to set SO_REUSEPORT option to listener socket: "
                << xsi_strerror(error, errbuf.data(), errbuf.size());
      close(fd);
      continue;
    }

    if (faddr.family == AF_INET6) {
#  ifdef IPV6_V6ONLY
      if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val,
                     static_cast<socklen_t>(sizeof(val))) == -1) {
        auto error = errno;
        LOG(WARN) << "Failed to set IPV6_V6ONLY option to listener socket: "
                  << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        continue;
      }
#  endif // IPV6_V6ONLY

      if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &val,
                     static_cast<socklen_t>(sizeof(val))) == -1) {
        auto error = errno;
        LOG(WARN)
            << "Failed to set IPV6_RECVPKTINFO option to listener socket: "
            << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        continue;
      }

      if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVTCLASS, &val,
                     static_cast<socklen_t>(sizeof(val))) == -1) {
        auto error = errno;
        LOG(WARN) << "Failed to set IPV6_RECVTCLASS option to listener socket: "
                  << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        continue;
      }

#  if defined(IPV6_MTU_DISCOVER) && defined(IPV6_PMTUDISC_DO)
      int mtu_disc = IPV6_PMTUDISC_DO;
      if (setsockopt(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &mtu_disc,
                     static_cast<socklen_t>(sizeof(mtu_disc))) == -1) {
        auto error = errno;
        LOG(WARN)
            << "Failed to set IPV6_MTU_DISCOVER option to listener socket: "
            << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        continue;
      }
#  endif // defined(IPV6_MTU_DISCOVER) && defined(IP_PMTUDISC_DO)
    } else {
      if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &val,
                     static_cast<socklen_t>(sizeof(val))) == -1) {
        auto error = errno;
        LOG(WARN) << "Failed to set IP_PKTINFO option to listener socket: "
                  << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        continue;
      }

      if (setsockopt(fd, IPPROTO_IP, IP_RECVTOS, &val,
                     static_cast<socklen_t>(sizeof(val))) == -1) {
        auto error = errno;
        LOG(WARN) << "Failed to set IP_RECVTOS option to listener socket: "
                  << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        continue;
      }

#  if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DO)
      int mtu_disc = IP_PMTUDISC_DO;
      if (setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &mtu_disc,
                     static_cast<socklen_t>(sizeof(mtu_disc))) == -1) {
        auto error = errno;
        LOG(WARN) << "Failed to set IP_MTU_DISCOVER option to listener socket: "
                  << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        continue;
      }
#  endif // defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DO)
    }

#  ifdef UDP_GRO
    if (setsockopt(fd, IPPROTO_UDP, UDP_GRO, &val, sizeof(val)) == -1) {
      auto error = errno;
      LOG(WARN) << "Failed to set UDP_GRO option to listener socket: "
                << xsi_strerror(error, errbuf.data(), errbuf.size());
      close(fd);
      continue;
    }
#  endif // UDP_GRO

    if (bind(fd, rp->ai_addr, rp->ai_addrlen) == -1) {
      auto error = errno;
      LOG(WARN) << "bind() syscall failed: "
                << xsi_strerror(error, errbuf.data(), errbuf.size());
      close(fd);
      continue;
    }

#  ifdef HAVE_LIBBPF
    auto config = get_config();

    auto &quic_bpf_refs = conn_handler_->get_quic_bpf_refs();

    if (should_attach_bpf()) {
      auto &bpfconf = config->quic.bpf;

      auto obj = bpf_object__open_file(bpfconf.prog_file.c_str(), nullptr);
      if (!obj) {
        auto error = errno;
        LOG(FATAL) << "Failed to open bpf object file: "
                   << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        return -1;
      }

      rv = bpf_object__load(obj);
      if (rv != 0) {
        auto error = errno;
        LOG(FATAL) << "Failed to load bpf object file: "
                   << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        return -1;
      }

      auto prog = bpf_object__find_program_by_name(obj, "select_reuseport");
      if (!prog) {
        auto error = errno;
        LOG(FATAL) << "Failed to find sk_reuseport program: "
                   << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        return -1;
      }

      auto &ref = quic_bpf_refs[faddr.index];

      ref.obj = obj;

      ref.reuseport_array =
          bpf_object__find_map_by_name(obj, "reuseport_array");
      if (!ref.reuseport_array) {
        auto error = errno;
        LOG(FATAL) << "Failed to get reuseport_array: "
                   << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        return -1;
      }

      ref.cid_prefix_map = bpf_object__find_map_by_name(obj, "cid_prefix_map");
      if (!ref.cid_prefix_map) {
        auto error = errno;
        LOG(FATAL) << "Failed to get cid_prefix_map: "
                   << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        return -1;
      }

      auto sk_info = bpf_object__find_map_by_name(obj, "sk_info");
      if (!sk_info) {
        auto error = errno;
        LOG(FATAL) << "Failed to get sk_info: "
                   << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        return -1;
      }

      constexpr uint32_t zero = 0;
      uint64_t num_socks = config->num_worker;

      rv = bpf_map__update_elem(sk_info, &zero, sizeof(zero), &num_socks,
                                sizeof(num_socks), BPF_ANY);
      if (rv != 0) {
        auto error = errno;
        LOG(FATAL) << "Failed to update sk_info: "
                   << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        return -1;
      }

      constexpr uint32_t key_high_idx = 1;
      constexpr uint32_t key_low_idx = 2;

      auto &qkms = conn_handler_->get_quic_keying_materials();
      auto &qkm = qkms->keying_materials.front();

      rv = bpf_map__update_elem(sk_info, &key_high_idx, sizeof(key_high_idx),
                                qkm.cid_encryption_key.data(),
                                qkm.cid_encryption_key.size() / 2, BPF_ANY);
      if (rv != 0) {
        auto error = errno;
        LOG(FATAL) << "Failed to update key_high_idx sk_info: "
                   << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        return -1;
      }

      rv = bpf_map__update_elem(sk_info, &key_low_idx, sizeof(key_low_idx),
                                qkm.cid_encryption_key.data() +
                                    qkm.cid_encryption_key.size() / 2,
                                qkm.cid_encryption_key.size() / 2, BPF_ANY);
      if (rv != 0) {
        auto error = errno;
        LOG(FATAL) << "Failed to update key_low_idx sk_info: "
                   << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        return -1;
      }

      auto prog_fd = bpf_program__fd(prog);

      if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &prog_fd,
                     static_cast<socklen_t>(sizeof(prog_fd))) == -1) {
        LOG(FATAL) << "Failed to attach bpf program: "
                   << xsi_strerror(errno, errbuf.data(), errbuf.size());
        close(fd);
        return -1;
      }
    }

    if (should_update_bpf_map()) {
      const auto &ref = quic_bpf_refs[faddr.index];
      auto sk_index = compute_sk_index();

      rv = bpf_map__update_elem(ref.reuseport_array, &sk_index,
                                sizeof(sk_index), &fd, sizeof(fd), BPF_NOEXIST);
      if (rv != 0) {
        auto error = errno;
        LOG(FATAL) << "Failed to update reuseport_array: "
                   << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        return -1;
      }

      rv = bpf_map__update_elem(ref.cid_prefix_map, cid_prefix_.data(),
                                cid_prefix_.size(), &sk_index, sizeof(sk_index),
                                BPF_NOEXIST);
      if (rv != 0) {
        auto error = errno;
        LOG(FATAL) << "Failed to update cid_prefix_map: "
                   << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        return -1;
      }
    }
#  endif // HAVE_LIBBPF

    break;
  }

  if (!rp) {
    LOG(FATAL) << "Listening " << (faddr.family == AF_INET ? "IPv4" : "IPv6")
               << " socket failed";

    return -1;
  }

  faddr.fd = fd;
  faddr.hostport = util::make_http_hostport(mod_config()->balloc,
                                            StringRef{host.data()}, faddr.port);

  LOG(NOTICE) << "Listening on " << faddr.hostport << ", quic";

  return 0;
}

const uint8_t *Worker::get_cid_prefix() const { return cid_prefix_.data(); }

const UpstreamAddr *Worker::find_quic_upstream_addr(const Address &local_addr) {
  std::array<char, NI_MAXHOST> host;

  auto rv = getnameinfo(&local_addr.su.sa, local_addr.len, host.data(),
                        host.size(), nullptr, 0, NI_NUMERICHOST);
  if (rv != 0) {
    LOG(ERROR) << "getnameinfo: " << gai_strerror(rv);

    return nullptr;
  }

  uint16_t port;

  switch (local_addr.su.sa.sa_family) {
  case AF_INET:
    port = htons(local_addr.su.in.sin_port);

    break;
  case AF_INET6:
    port = htons(local_addr.su.in6.sin6_port);

    break;
  default:
    assert(0);
    abort();
  }

  std::array<char, util::max_hostport> hostport_buf;

  auto hostport = util::make_http_hostport(std::begin(hostport_buf),
                                           StringRef{host.data()}, port);
  const UpstreamAddr *fallback_faddr = nullptr;

  for (auto &faddr : quic_upstream_addrs_) {
    if (faddr.hostport == hostport) {
      return &faddr;
    }

    if (faddr.port != port || faddr.family != local_addr.su.sa.sa_family) {
      continue;
    }

    if (faddr.port == 443 || faddr.port == 80) {
      switch (faddr.family) {
      case AF_INET:
        if (util::streq(faddr.hostport, StringRef::from_lit("0.0.0.0"))) {
          fallback_faddr = &faddr;
        }

        break;
      case AF_INET6:
        if (util::streq(faddr.hostport, StringRef::from_lit("[::]"))) {
          fallback_faddr = &faddr;
        }

        break;
      default:
        assert(0);
      }
    } else {
      switch (faddr.family) {
      case AF_INET:
        if (util::starts_with(faddr.hostport,
                              StringRef::from_lit("0.0.0.0:"))) {
          fallback_faddr = &faddr;
        }

        break;
      case AF_INET6:
        if (util::starts_with(faddr.hostport, StringRef::from_lit("[::]:"))) {
          fallback_faddr = &faddr;
        }

        break;
      default:
        assert(0);
      }
    }
  }

  return fallback_faddr;
}
#endif // ENABLE_HTTP3

namespace {
size_t match_downstream_addr_group_host(
    const RouterConfig &routerconf, const StringRef &host,
    const StringRef &path,
    const std::vector<std::shared_ptr<DownstreamAddrGroup>> &groups,
    size_t catch_all, BlockAllocator &balloc) {

  const auto &router = routerconf.router;
  const auto &rev_wildcard_router = routerconf.rev_wildcard_router;
  const auto &wildcard_patterns = routerconf.wildcard_patterns;

  if (LOG_ENABLED(INFO)) {
    LOG(INFO) << "Perform mapping selection, using host=" << host
              << ", path=" << path;
  }

  auto group = router.match(host, path);
  if (group != -1) {
    if (LOG_ENABLED(INFO)) {
      LOG(INFO) << "Found pattern with query " << host << path
                << ", matched pattern=" << groups[group]->pattern;
    }
    return group;
  }

  if (!wildcard_patterns.empty() && !host.empty()) {
    auto rev_host_src = make_byte_ref(balloc, host.size() - 1);
    auto ep =
        std::copy(std::begin(host) + 1, std::end(host), rev_host_src.base);
    std::reverse(rev_host_src.base, ep);
    auto rev_host = StringRef{rev_host_src.base, ep};

    ssize_t best_group = -1;
    const RNode *last_node = nullptr;

    for (;;) {
      size_t nread = 0;
      auto wcidx =
          rev_wildcard_router.match_prefix(&nread, &last_node, rev_host);
      if (wcidx == -1) {
        break;
      }

      rev_host = StringRef{std::begin(rev_host) + nread, std::end(rev_host)};

      auto &wc = wildcard_patterns[wcidx];
      auto group = wc.router.match(StringRef{}, path);
      if (group != -1) {
        // We sorted wildcard_patterns in a way that first match is the
        // longest host pattern.
        if (LOG_ENABLED(INFO)) {
          LOG(INFO) << "Found wildcard pattern with query " << host << path
                    << ", matched pattern=" << groups[group]->pattern;
        }

        best_group = group;
      }
    }

    if (best_group != -1) {
      return best_group;
    }
  }

  group = router.match(StringRef::from_lit(""), path);
  if (group != -1) {
    if (LOG_ENABLED(INFO)) {
      LOG(INFO) << "Found pattern with query " << path
                << ", matched pattern=" << groups[group]->pattern;
    }
    return group;
  }

  if (LOG_ENABLED(INFO)) {
    LOG(INFO) << "None match.  Use catch-all pattern";
  }
  return catch_all;
}
} // namespace

size_t match_downstream_addr_group(
    const RouterConfig &routerconf, const StringRef &hostport,
    const StringRef &raw_path,
    const std::vector<std::shared_ptr<DownstreamAddrGroup>> &groups,
    size_t catch_all, BlockAllocator &balloc) {
  if (std::find(std::begin(hostport), std::end(hostport), '/') !=
      std::end(hostport)) {
    // We use '/' specially, and if '/' is included in host, it breaks
    // our code.  Select catch-all case.
    return catch_all;
  }

  auto fragment = std::find(std::begin(raw_path), std::end(raw_path), '#');
  auto query = std::find(std::begin(raw_path), fragment, '?');
  auto path = StringRef{std::begin(raw_path), query};

  if (path.empty() || path[0] != '/') {
    path = StringRef::from_lit("/");
  }

  if (hostport.empty()) {
    return match_downstream_addr_group_host(routerconf, hostport, path, groups,
                                            catch_all, balloc);
  }

  StringRef host;
  if (hostport[0] == '[') {
    // assume this is IPv6 numeric address
    auto p = std::find(std::begin(hostport), std::end(hostport), ']');
    if (p == std::end(hostport)) {
      return catch_all;
    }
    if (p + 1 < std::end(hostport) && *(p + 1) != ':') {
      return catch_all;
    }
    host = StringRef{std::begin(hostport), p + 1};
  } else {
    auto p = std::find(std::begin(hostport), std::end(hostport), ':');
    if (p == std::begin(hostport)) {
      return catch_all;
    }
    host = StringRef{std::begin(hostport), p};
  }

  if (std::find_if(std::begin(host), std::end(host), [](char c) {
        return 'A' <= c || c <= 'Z';
      }) != std::end(host)) {
    auto low_host = make_byte_ref(balloc, host.size() + 1);
    auto ep = std::copy(std::begin(host), std::end(host), low_host.base);
    *ep = '\0';
    util::inp_strlower(low_host.base, ep);
    host = StringRef{low_host.base, ep};
  }
  return match_downstream_addr_group_host(routerconf, host, path, groups,
                                          catch_all, balloc);
}

void downstream_failure(DownstreamAddr *addr, const Address *raddr) {
  const auto &connect_blocker = addr->connect_blocker;

  if (connect_blocker->in_offline()) {
    return;
  }

  connect_blocker->on_failure();

  if (addr->fall == 0) {
    return;
  }

  auto fail_count = connect_blocker->get_fail_count();

  if (fail_count >= addr->fall) {
    if (raddr) {
      LOG(WARN) << "Could not connect to " << util::to_numeric_addr(raddr)
                << " " << fail_count
                << " times in a row; considered as offline";
    } else {
      LOG(WARN) << "Could not connect to " << addr->host << ":" << addr->port
                << " " << fail_count
                << " times in a row; considered as offline";
    }

    connect_blocker->offline();

    if (addr->rise) {
      addr->live_check->schedule();
    }
  }
}

#ifdef ENABLE_HTTP3
int create_cid_prefix(uint8_t *cid_prefix, const uint8_t *server_id) {
  auto p = std::copy_n(server_id, SHRPX_QUIC_SERVER_IDLEN, cid_prefix);

  if (RAND_bytes(p, SHRPX_QUIC_CID_PREFIXLEN - SHRPX_QUIC_SERVER_IDLEN) != 1) {
    return -1;
  }

  return 0;
}
#endif // ENABLE_HTTP3

} // namespace shrpx
