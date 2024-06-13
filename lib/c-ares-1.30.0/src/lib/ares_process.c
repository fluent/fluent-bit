/* MIT License
 *
 * Copyright (c) 1998 Massachusetts Institute of Technology
 * Copyright (c) 2010 Daniel Stenberg
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * SPDX-License-Identifier: MIT
 */

#include "ares_setup.h"


#ifdef HAVE_STRINGS_H
#  include <strings.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#  include <sys/ioctl.h>
#endif
#ifdef NETWARE
#  include <sys/filio.h>
#endif
#ifdef HAVE_STDINT_H
#  include <stdint.h>
#endif

#include <assert.h>
#include <fcntl.h>
#include <limits.h>

#include "ares.h"
#include "ares_private.h"
#include "ares_nameser.h"
#include "ares_dns.h"

static void          timeadd(ares_timeval_t *now, size_t millisecs);
static ares_bool_t   try_again(int errnum);
static void          write_tcp_data(ares_channel_t *channel, fd_set *write_fds,
                                    ares_socket_t write_fd);
static void          read_packets(ares_channel_t *channel, fd_set *read_fds,
                                  ares_socket_t read_fd, const ares_timeval_t *now);
static void          process_timeouts(ares_channel_t       *channel,
                                      const ares_timeval_t *now);
static ares_status_t process_answer(ares_channel_t      *channel,
                                    const unsigned char *abuf, size_t alen,
                                    struct server_connection *conn,
                                    ares_bool_t tcp, const ares_timeval_t *now);
static void          handle_conn_error(struct server_connection *conn,
                                       ares_bool_t               critical_failure);

static ares_bool_t   same_questions(const ares_dns_record_t *qrec,
                                    const ares_dns_record_t *arec);
static ares_bool_t   same_address(const struct sockaddr  *sa,
                                  const struct ares_addr *aa);
static void          end_query(ares_channel_t *channel, struct query *query,
                               ares_status_t status, const ares_dns_record_t *dnsrec);

/* Invoke the server state callback after a success or failure */
static void          invoke_server_state_cb(const struct server_state *server,
                                            ares_bool_t success, int flags)
{
  const ares_channel_t *channel = server->channel;
  ares__buf_t          *buf;
  ares_status_t         status;
  char                 *server_string;

  if (channel->server_state_cb == NULL) {
    return;
  }

  buf = ares__buf_create();
  if (buf == NULL) {
    return;
  }

  status = ares_get_server_addr(server, buf);
  if (status != ARES_SUCCESS) {
    ares__buf_destroy(buf);
    return;
  }

  server_string = ares__buf_finish_str(buf, NULL);
  buf           = NULL;
  if (server_string == NULL) {
    return;
  }

  channel->server_state_cb(server_string, success, flags,
                           channel->server_state_cb_data);
  ares_free(server_string);
}

static void server_increment_failures(struct server_state *server,
                                      ares_bool_t          used_tcp)
{
  ares__slist_node_t   *node;
  const ares_channel_t *channel = server->channel;
  ares_timeval_t        next_retry_time;

  node = ares__slist_node_find(channel->servers, server);
  if (node == NULL) {
    return;
  }

  server->consec_failures++;
  ares__slist_node_reinsert(node);

  next_retry_time = ares__tvnow();
  timeadd(&next_retry_time, channel->server_retry_delay);
  server->next_retry_time = next_retry_time;

  invoke_server_state_cb(server, ARES_FALSE,
                         used_tcp == ARES_TRUE ? ARES_SERV_STATE_TCP
                                               : ARES_SERV_STATE_UDP);
}

static void server_set_good(struct server_state *server, ares_bool_t used_tcp)
{
  ares__slist_node_t   *node;
  const ares_channel_t *channel = server->channel;

  node = ares__slist_node_find(channel->servers, server);
  if (node == NULL) {
    return;
  }

  if (server->consec_failures > 0) {
    server->consec_failures = 0;
    ares__slist_node_reinsert(node);
  }

  server->next_retry_time.sec  = 0;
  server->next_retry_time.usec = 0;

  invoke_server_state_cb(server, ARES_TRUE,
                         used_tcp == ARES_TRUE ? ARES_SERV_STATE_TCP
                                               : ARES_SERV_STATE_UDP);
}

/* return true if now is exactly check time or later */
ares_bool_t ares__timedout(const ares_timeval_t *now,
                           const ares_timeval_t *check)
{
  ares_int64_t secs = (now->sec - check->sec);

  if (secs > 0) {
    return ARES_TRUE; /* yes, timed out */
  }
  if (secs < 0) {
    return ARES_FALSE; /* nope, not timed out */
  }

  /* if the full seconds were identical, check the sub second parts */
  return ((ares_int64_t)now->usec - (ares_int64_t)check->usec) >= 0
           ? ARES_TRUE
           : ARES_FALSE;
}

/* add the specific number of milliseconds to the time in the first argument */
static void timeadd(ares_timeval_t *now, size_t millisecs)
{
  now->sec  += (ares_int64_t)millisecs / 1000;
  now->usec += (unsigned int)((millisecs % 1000) * 1000);

  if (now->usec >= 1000000) {
    now->sec  += now->usec / 1000000;
    now->usec %= 1000000;
  }
}

/*
 * generic process function
 */
static void processfds(ares_channel_t *channel, fd_set *read_fds,
                       ares_socket_t read_fd, fd_set *write_fds,
                       ares_socket_t write_fd)
{
  ares_timeval_t now;

  if (channel == NULL) {
    return;
  }

  ares__channel_lock(channel);

  now = ares__tvnow();
  read_packets(channel, read_fds, read_fd, &now);
  process_timeouts(channel, &now);
  /* Write last as the other 2 operations might have triggered writes */
  write_tcp_data(channel, write_fds, write_fd);

  ares__channel_unlock(channel);
}

/* Something interesting happened on the wire, or there was a timeout.
 * See what's up and respond accordingly.
 */
void ares_process(ares_channel_t *channel, fd_set *read_fds, fd_set *write_fds)
{
  processfds(channel, read_fds, ARES_SOCKET_BAD, write_fds, ARES_SOCKET_BAD);
}

/* Something interesting happened on the wire, or there was a timeout.
 * See what's up and respond accordingly.
 */
void ares_process_fd(ares_channel_t *channel,
                     ares_socket_t   read_fd, /* use ARES_SOCKET_BAD or valid
                                                 file descriptors */
                     ares_socket_t   write_fd)
{
  processfds(channel, NULL, read_fd, NULL, write_fd);
}

/* Return 1 if the specified error number describes a readiness error, or 0
 * otherwise. This is mostly for HP-UX, which could return EAGAIN or
 * EWOULDBLOCK. See this man page
 *
 * http://devrsrc1.external.hp.com/STKS/cgi-bin/man2html?
 *     manpage=/usr/share/man/man2.Z/send.2
 */
static ares_bool_t try_again(int errnum)
{
#if !defined EWOULDBLOCK && !defined EAGAIN
#  error "Neither EWOULDBLOCK nor EAGAIN defined"
#endif

#ifdef EWOULDBLOCK
  if (errnum == EWOULDBLOCK) {
    return ARES_TRUE;
  }
#endif

#if defined EAGAIN && EAGAIN != EWOULDBLOCK
  if (errnum == EAGAIN) {
    return ARES_TRUE;
  }
#endif

  return ARES_FALSE;
}

/* If any TCP sockets select true for writing, write out queued data
 * we have for them.
 */
static void write_tcp_data(ares_channel_t *channel, fd_set *write_fds,
                           ares_socket_t write_fd)
{
  ares__slist_node_t *node;

  if (!write_fds && (write_fd == ARES_SOCKET_BAD)) {
    /* no possible action */
    return;
  }

  for (node = ares__slist_node_first(channel->servers); node != NULL;
       node = ares__slist_node_next(node)) {
    struct server_state *server = ares__slist_node_val(node);
    const unsigned char *data;
    size_t               data_len;
    ares_ssize_t         count;

    /* Make sure server has data to send and is selected in write_fds or
       write_fd. */
    if (ares__buf_len(server->tcp_send) == 0 || server->tcp_conn == NULL) {
      continue;
    }

    if (write_fds) {
      if (!FD_ISSET(server->tcp_conn->fd, write_fds)) {
        continue;
      }
    } else {
      if (server->tcp_conn->fd != write_fd) {
        continue;
      }
    }

    if (write_fds) {
      /* If there's an error and we close this socket, then open
       * another with the same fd to talk to another server, then we
       * don't want to think that it was the new socket that was
       * ready. This is not disastrous, but is likely to result in
       * extra system calls and confusion. */
      FD_CLR(server->tcp_conn->fd, write_fds);
    }

    data  = ares__buf_peek(server->tcp_send, &data_len);
    count = ares__socket_write(channel, server->tcp_conn->fd, data, data_len);
    if (count <= 0) {
      if (!try_again(SOCKERRNO)) {
        handle_conn_error(server->tcp_conn, ARES_TRUE);
      }
      continue;
    }

    /* Strip data written from the buffer */
    ares__buf_consume(server->tcp_send, (size_t)count);

    /* Notify state callback all data is written */
    if (ares__buf_len(server->tcp_send) == 0) {
      SOCK_STATE_CALLBACK(channel, server->tcp_conn->fd, 1, 0);
    }
  }
}

/* If any TCP socket selects true for reading, read some data,
 * allocate a buffer if we finish reading the length word, and process
 * a packet if we finish reading one.
 */
static void read_tcp_data(ares_channel_t           *channel,
                          struct server_connection *conn,
                          const ares_timeval_t     *now)
{
  ares_ssize_t         count;
  struct server_state *server = conn->server;

  /* Fetch buffer to store data we are reading */
  size_t               ptr_len = 65535;
  unsigned char       *ptr;

  ptr = ares__buf_append_start(server->tcp_parser, &ptr_len);

  if (ptr == NULL) {
    handle_conn_error(conn, ARES_FALSE /* not critical to connection */);
    return; /* bail out on malloc failure. TODO: make this
               function return error codes */
  }

  /* Read from socket */
  count = ares__socket_recv(channel, conn->fd, ptr, ptr_len);
  if (count <= 0) {
    ares__buf_append_finish(server->tcp_parser, 0);
    if (!(count == -1 && try_again(SOCKERRNO))) {
      handle_conn_error(conn, ARES_TRUE);
    }
    return;
  }

  /* Record amount of data read */
  ares__buf_append_finish(server->tcp_parser, (size_t)count);

  /* Process all queued answers */
  while (1) {
    unsigned short       dns_len  = 0;
    const unsigned char *data     = NULL;
    size_t               data_len = 0;
    ares_status_t        status;

    /* Tag so we can roll back */
    ares__buf_tag(server->tcp_parser);

    /* Read length indicator */
    if (ares__buf_fetch_be16(server->tcp_parser, &dns_len) != ARES_SUCCESS) {
      ares__buf_tag_rollback(server->tcp_parser);
      break;
    }

    /* Not enough data for a full response yet */
    if (ares__buf_consume(server->tcp_parser, dns_len) != ARES_SUCCESS) {
      ares__buf_tag_rollback(server->tcp_parser);
      break;
    }

    /* Can't fail except for misuse */
    data = ares__buf_tag_fetch(server->tcp_parser, &data_len);
    if (data == NULL) {
      ares__buf_tag_clear(server->tcp_parser);
      break;
    }

    /* Strip off 2 bytes length */
    data     += 2;
    data_len -= 2;

    /* We finished reading this answer; process it */
    status = process_answer(channel, data, data_len, conn, ARES_TRUE, now);
    if (status != ARES_SUCCESS) {
      handle_conn_error(conn, ARES_TRUE);
      return;
    }

    /* Since we processed the answer, clear the tag so space can be reclaimed */
    ares__buf_tag_clear(server->tcp_parser);
  }

  ares__check_cleanup_conn(channel, conn);
}

static int socket_list_append(ares_socket_t **socketlist, ares_socket_t fd,
                              size_t *alloc_cnt, size_t *num)
{
  if (*num >= *alloc_cnt) {
    /* Grow by powers of 2 */
    size_t         new_alloc = (*alloc_cnt) << 1;
    ares_socket_t *new_list =
      ares_realloc(socketlist, new_alloc * sizeof(*new_list));
    if (new_list == NULL) {
      return 0;
    }
    *alloc_cnt  = new_alloc;
    *socketlist = new_list;
  }

  (*socketlist)[(*num)++] = fd;
  return 1;
}

static ares_socket_t *channel_socket_list(const ares_channel_t *channel,
                                          size_t               *num)
{
  size_t              alloc_cnt = 1 << 4;
  ares_socket_t      *out       = ares_malloc(alloc_cnt * sizeof(*out));
  ares__slist_node_t *snode;

  *num = 0;

  if (out == NULL) {
    return NULL;
  }

  for (snode = ares__slist_node_first(channel->servers); snode != NULL;
       snode = ares__slist_node_next(snode)) {
    struct server_state *server = ares__slist_node_val(snode);
    ares__llist_node_t  *node;

    for (node = ares__llist_node_first(server->connections); node != NULL;
         node = ares__llist_node_next(node)) {
      const struct server_connection *conn = ares__llist_node_val(node);

      if (conn->fd == ARES_SOCKET_BAD) {
        continue;
      }

      if (!socket_list_append(&out, conn->fd, &alloc_cnt, num)) {
        goto fail;
      }
    }
  }

  return out;

fail:
  ares_free(out);
  *num = 0;
  return NULL;
}

/* If any UDP sockets select true for reading, process them. */
static void read_udp_packets_fd(ares_channel_t           *channel,
                                struct server_connection *conn,
                                const ares_timeval_t     *now)
{
  ares_ssize_t  read_len;
  unsigned char buf[MAXENDSSZ + 1];

#ifdef HAVE_RECVFROM
  ares_socklen_t fromlen;

  union {
    struct sockaddr     sa;
    struct sockaddr_in  sa4;
    struct sockaddr_in6 sa6;
  } from;

  memset(&from, 0, sizeof(from));
#endif

  /* To reduce event loop overhead, read and process as many
   * packets as we can. */
  do {
    if (conn->fd == ARES_SOCKET_BAD) {
      read_len = -1;
    } else {
      if (conn->server->addr.family == AF_INET) {
        fromlen = sizeof(from.sa4);
      } else {
        fromlen = sizeof(from.sa6);
      }
      read_len = ares__socket_recvfrom(channel, conn->fd, (void *)buf,
                                       sizeof(buf), 0, &from.sa, &fromlen);
    }

    if (read_len == 0) {
      /* UDP is connectionless, so result code of 0 is a 0-length UDP
       * packet, and not an indication the connection is closed like on
       * tcp */
      continue;
    } else if (read_len < 0) {
      if (try_again(SOCKERRNO)) {
        break;
      }

      handle_conn_error(conn, ARES_TRUE);
      return;
#ifdef HAVE_RECVFROM
    } else if (!same_address(&from.sa, &conn->server->addr)) {
      /* The address the response comes from does not match the address we
       * sent the request to. Someone may be attempting to perform a cache
       * poisoning attack. */
      continue;
#endif

    } else {
      process_answer(channel, buf, (size_t)read_len, conn, ARES_FALSE, now);
    }

    /* Try to read again only if *we* set up the socket, otherwise it may be
     * a blocking socket and would cause recvfrom to hang. */
  } while (read_len >= 0 && channel->sock_funcs == NULL);

  ares__check_cleanup_conn(channel, conn);
}

static void read_packets(ares_channel_t *channel, fd_set *read_fds,
                         ares_socket_t read_fd, const ares_timeval_t *now)
{
  size_t                    i;
  ares_socket_t            *socketlist  = NULL;
  size_t                    num_sockets = 0;
  struct server_connection *conn        = NULL;
  ares__llist_node_t       *node        = NULL;

  if (!read_fds && (read_fd == ARES_SOCKET_BAD)) {
    /* no possible action */
    return;
  }

  /* Single socket specified */
  if (!read_fds) {
    node = ares__htable_asvp_get_direct(channel->connnode_by_socket, read_fd);
    if (node == NULL) {
      return;
    }

    conn = ares__llist_node_val(node);

    if (conn->is_tcp) {
      read_tcp_data(channel, conn, now);
    } else {
      read_udp_packets_fd(channel, conn, now);
    }

    return;
  }

  /* There is no good way to iterate across an fd_set, instead we must pull a
   * list of all known fds, and iterate across that checking against the fd_set.
   */
  socketlist = channel_socket_list(channel, &num_sockets);

  for (i = 0; i < num_sockets; i++) {
    if (!FD_ISSET(socketlist[i], read_fds)) {
      continue;
    }

    /* If there's an error and we close this socket, then open
     * another with the same fd to talk to another server, then we
     * don't want to think that it was the new socket that was
     * ready. This is not disastrous, but is likely to result in
     * extra system calls and confusion. */
    FD_CLR(socketlist[i], read_fds);

    node =
      ares__htable_asvp_get_direct(channel->connnode_by_socket, socketlist[i]);
    if (node == NULL) {
      return;
    }

    conn = ares__llist_node_val(node);

    if (conn->is_tcp) {
      read_tcp_data(channel, conn, now);
    } else {
      read_udp_packets_fd(channel, conn, now);
    }
  }

  ares_free(socketlist);
}

/* If any queries have timed out, note the timeout and move them on. */
static void process_timeouts(ares_channel_t *channel, const ares_timeval_t *now)
{
  ares__slist_node_t *node =
    ares__slist_node_first(channel->queries_by_timeout);
  while (node != NULL) {
    struct query             *query = ares__slist_node_val(node);
    /* Node might be removed, cache next */
    ares__slist_node_t       *next = ares__slist_node_next(node);
    struct server_connection *conn;
    /* Since this is sorted, as soon as we hit a query that isn't timed out,
     * break */
    if (!ares__timedout(now, &query->timeout)) {
      break;
    }

    query->error_status = ARES_ETIMEOUT;
    query->timeouts++;

    conn = query->conn;
    server_increment_failures(conn->server, query->using_tcp);
    ares__requeue_query(query, now);
    ares__check_cleanup_conn(channel, conn);

    node = next;
  }
}

static ares_status_t rewrite_without_edns(ares_dns_record_t *qdnsrec,
                                          struct query      *query)
{
  ares_status_t  status;
  size_t         i;
  ares_bool_t    found_opt_rr = ARES_FALSE;
  unsigned char *msg          = NULL;
  size_t         msglen       = 0;

  /* Find and remove the OPT RR record */
  for (i = 0; i < ares_dns_record_rr_cnt(qdnsrec, ARES_SECTION_ADDITIONAL);
       i++) {
    const ares_dns_rr_t *rr;
    rr = ares_dns_record_rr_get(qdnsrec, ARES_SECTION_ADDITIONAL, i);
    if (ares_dns_rr_get_type(rr) == ARES_REC_TYPE_OPT) {
      ares_dns_record_rr_del(qdnsrec, ARES_SECTION_ADDITIONAL, i);
      found_opt_rr = ARES_TRUE;
      break;
    }
  }

  if (!found_opt_rr) {
    status = ARES_EFORMERR;
    goto done;
  }

  /* Rewrite the DNS message */
  status = ares_dns_write(qdnsrec, &msg, &msglen);
  if (status != ARES_SUCCESS) {
    goto done;
  }

  ares_free(query->qbuf);
  query->qbuf = msg;
  query->qlen = msglen;

done:
  return status;
}

/* Handle an answer from a server. This must NEVER cleanup the
 * server connection! Return something other than ARES_SUCCESS to cause
 * the connection to be terminated after this call. */
static ares_status_t process_answer(ares_channel_t      *channel,
                                    const unsigned char *abuf, size_t alen,
                                    struct server_connection *conn,
                                    ares_bool_t tcp, const ares_timeval_t *now)
{
  struct query        *query;
  /* Cache these as once ares__send_query() gets called, it may end up
   * invalidating the connection all-together */
  struct server_state *server  = conn->server;
  ares_dns_record_t   *rdnsrec = NULL;
  ares_dns_record_t   *qdnsrec = NULL;
  ares_status_t        status;
  ares_bool_t          is_cached = ARES_FALSE;

  /* Parse the response */
  status = ares_dns_parse(abuf, alen, 0, &rdnsrec);
  if (status != ARES_SUCCESS) {
    /* Malformations are never accepted */
    status = ARES_EBADRESP;
    goto cleanup;
  }

  /* Find the query corresponding to this packet. The queries are
   * hashed/bucketed by query id, so this lookup should be quick.
   */
  query = ares__htable_szvp_get_direct(channel->queries_by_qid,
                                       ares_dns_record_get_id(rdnsrec));
  if (!query) {
    /* We may have stopped listening for this query, that's ok */
    status = ARES_SUCCESS;
    goto cleanup;
  }

  /* Parse the question we sent as we use it to compare */
  status = ares_dns_parse(query->qbuf, query->qlen, 0, &qdnsrec);
  if (status != ARES_SUCCESS) {
    end_query(channel, query, status, NULL);
    goto cleanup;
  }

  /* Both the query id and the questions must be the same. We will drop any
   * replies that aren't for the same query as this is considered invalid. */
  if (!same_questions(qdnsrec, rdnsrec)) {
    /* Possible qid conflict due to delayed response, that's ok */
    status = ARES_SUCCESS;
    goto cleanup;
  }

  /* At this point we know we've received an answer for this query, so we should
   * remove it from the connection's queue so we can possibly invalidate the
   * connection. Delay cleaning up the connection though as we may enqueue
   * something new.  */
  ares__llist_node_destroy(query->node_queries_to_conn);
  query->node_queries_to_conn = NULL;

  /* If we use EDNS and server answers with FORMERR without an OPT RR, the
   * protocol extension is not understood by the responder. We must retry the
   * query without EDNS enabled. */
  if (ares_dns_record_get_rcode(rdnsrec) == ARES_RCODE_FORMERR &&
      ares_dns_has_opt_rr(qdnsrec) && !ares_dns_has_opt_rr(rdnsrec)) {
    status = rewrite_without_edns(qdnsrec, query);
    if (status != ARES_SUCCESS) {
      end_query(channel, query, status, NULL);
      goto cleanup;
    }

    ares__send_query(query, now);
    status = ARES_SUCCESS;
    goto cleanup;
  }

  /* If we got a truncated UDP packet and are not ignoring truncation,
   * don't accept the packet, and switch the query to TCP if we hadn't
   * done so already.
   */
  if (ares_dns_record_get_flags(rdnsrec) & ARES_FLAG_TC && !tcp &&
      !(channel->flags & ARES_FLAG_IGNTC)) {
    query->using_tcp = ARES_TRUE;
    ares__send_query(query, now);
    status = ARES_SUCCESS; /* Switched to TCP is ok */
    goto cleanup;
  }

  /* If we aren't passing through all error packets, discard packets
   * with SERVFAIL, NOTIMP, or REFUSED response codes.
   */
  if (!(channel->flags & ARES_FLAG_NOCHECKRESP)) {
    ares_dns_rcode_t rcode = ares_dns_record_get_rcode(rdnsrec);
    if (rcode == ARES_RCODE_SERVFAIL || rcode == ARES_RCODE_NOTIMP ||
        rcode == ARES_RCODE_REFUSED) {
      switch (rcode) {
        case ARES_RCODE_SERVFAIL:
          query->error_status = ARES_ESERVFAIL;
          break;
        case ARES_RCODE_NOTIMP:
          query->error_status = ARES_ENOTIMP;
          break;
        case ARES_RCODE_REFUSED:
          query->error_status = ARES_EREFUSED;
          break;
        default:
          break;
      }

      server_increment_failures(server, query->using_tcp);
      ares__requeue_query(query, now);

      /* Should any of these cause a connection termination?
       * Maybe SERVER_FAILURE? */
      status = ARES_SUCCESS;
      goto cleanup;
    }
  }

  /* If cache insertion was successful, it took ownership.  We ignore
   * other cache insertion failures. */
  if (ares_qcache_insert(channel, now, query, rdnsrec) == ARES_SUCCESS) {
    is_cached = ARES_TRUE;
  }

  server_set_good(server, query->using_tcp);
  end_query(channel, query, ARES_SUCCESS, rdnsrec);

  status = ARES_SUCCESS;

cleanup:
  /* Don't cleanup the cached pointer to the dns response */
  if (!is_cached) {
    ares_dns_record_destroy(rdnsrec);
  }

  ares_dns_record_destroy(qdnsrec);
  return status;
}

static void handle_conn_error(struct server_connection *conn,
                              ares_bool_t               critical_failure)
{
  struct server_state *server = conn->server;

  /* Increment failures first before requeue so it is unlikely to requeue
   * to the same server */
  if (critical_failure) {
    server_increment_failures(server, conn->is_tcp);
  }

  /* This will requeue any connections automatically */
  ares__close_connection(conn);
}

ares_status_t ares__requeue_query(struct query         *query,
                                  const ares_timeval_t *now)
{
  ares_channel_t *channel = query->channel;
  size_t max_tries        = ares__slist_len(channel->servers) * channel->tries;

  query->try_count++;

  if (query->try_count < max_tries && !query->no_retries) {
    return ares__send_query(query, now);
  }

  /* If we are here, all attempts to perform query failed. */
  if (query->error_status == ARES_SUCCESS) {
    query->error_status = ARES_ETIMEOUT;
  }

  end_query(channel, query, query->error_status, NULL);
  return ARES_ETIMEOUT;
}

/* Pick a random server from the list, we first get a random number in the
 * range of the number of servers, then scan until we find that server in
 * the list */
static struct server_state *ares__random_server(ares_channel_t *channel)
{
  unsigned char       c;
  size_t              cnt;
  size_t              idx;
  ares__slist_node_t *node;
  size_t              num_servers = ares__slist_len(channel->servers);

  /* Silence coverity, not possible */
  if (num_servers == 0) {
    return NULL;
  }

  ares__rand_bytes(channel->rand_state, &c, 1);

  cnt = c;
  idx = cnt % num_servers;

  cnt = 0;
  for (node = ares__slist_node_first(channel->servers); node != NULL;
       node = ares__slist_node_next(node)) {
    if (cnt == idx) {
      return ares__slist_node_val(node);
    }

    cnt++;
  }

  return NULL;
}

/* Pick a server from the list with failover behavior.
 *
 * We default to using the first server in the sorted list of servers. That is
 * the server with the lowest number of consecutive failures and then the
 * highest priority server (by idx) if there is a draw.
 *
 * However, if a server temporarily goes down and hits some failures, then that
 * server will never be retried until all other servers hit the same number of
 * failures. This may prevent the server from being retried for a long time.
 *
 * To resolve this, with some probability we select a failed server to retry
 * instead.
 */
static struct server_state *ares__failover_server(ares_channel_t *channel)
{
  struct server_state *first_server = ares__slist_first_val(channel->servers);
  const struct server_state *last_server =
    ares__slist_last_val(channel->servers);
  unsigned short r;

  /* Defensive code against no servers being available on the channel. */
  if (first_server == NULL) {
    return NULL;
  }

  /* If no servers have failures, then prefer the first server in the list. */
  if (last_server != NULL && last_server->consec_failures == 0) {
    return first_server;
  }

  /* If we are not configured with a server retry chance then return the first
   * server.
   */
  if (channel->server_retry_chance == 0) {
    return first_server;
  }

  /* Generate a random value to decide whether to retry a failed server. The
   * probability to use is 1/channel->server_retry_chance, rounded up to a
   * precision of 1/2^B where B is the number of bits in the random value.
   * We use an unsigned short for the random value for increased precision.
   */
  ares__rand_bytes(channel->rand_state, (unsigned char *)&r, sizeof(r));
  if (r % channel->server_retry_chance == 0) {
    /* Select a suitable failed server to retry. */
    ares_timeval_t      now = ares__tvnow();
    ares__slist_node_t *node;
    for (node = ares__slist_node_first(channel->servers); node != NULL;
         node = ares__slist_node_next(node)) {
      struct server_state *node_val = ares__slist_node_val(node);
      if (node_val != NULL && node_val->consec_failures > 0 &&
          ares__timedout(&now, &node_val->next_retry_time)) {
        return node_val;
      }
    }
  }

  /* If we have not returned yet, then return the first server. */
  return first_server;
}

static ares_status_t ares__append_tcpbuf(struct server_state *server,
                                         const struct query  *query)
{
  ares_status_t status;

  status = ares__buf_append_be16(server->tcp_send, (unsigned short)query->qlen);
  if (status != ARES_SUCCESS) {
    return status;
  }
  return ares__buf_append(server->tcp_send, query->qbuf, query->qlen);
}

static size_t ares__calc_query_timeout(const struct query *query)
{
  const ares_channel_t *channel  = query->channel;
  size_t                timeplus = channel->timeout;
  size_t                rounds;
  size_t                num_servers = ares__slist_len(channel->servers);

  if (num_servers == 0) {
    return 0;
  }

  /* For each trip through the entire server list, we want to double the
   * retry from the last retry */
  rounds = (query->try_count / num_servers);
  if (rounds > 0) {
    timeplus <<= rounds;
  }

  if (channel->maxtimeout && timeplus > channel->maxtimeout) {
    timeplus = channel->maxtimeout;
  }

  /* Add some jitter to the retry timeout.
   *
   * Jitter is needed in situation when resolve requests are performed
   * simultaneously from multiple hosts and DNS server throttle these requests.
   * Adding randomness allows to avoid synchronisation of retries.
   *
   * Value of timeplus adjusted randomly to the range [0.5 * timeplus,
   * timeplus].
   */
  if (rounds > 0) {
    unsigned short r;
    float          delta_multiplier;

    ares__rand_bytes(channel->rand_state, (unsigned char *)&r, sizeof(r));
    delta_multiplier  = ((float)r / USHRT_MAX) * 0.5f;
    timeplus         -= (size_t)((float)timeplus * delta_multiplier);
  }

  /* We want explicitly guarantee that timeplus is greater or equal to timeout
   * specified in channel options. */
  if (timeplus < channel->timeout) {
    timeplus = channel->timeout;
  }

  return timeplus;
}

ares_status_t ares__send_query(struct query *query, const ares_timeval_t *now)
{
  ares_channel_t           *channel = query->channel;
  struct server_state      *server;
  struct server_connection *conn;
  size_t                    timeplus;
  ares_status_t             status;
  ares_bool_t               new_connection = ARES_FALSE;

  query->conn = NULL;

  /* Choose the server to send the query to */
  if (channel->rotate) {
    /* Pull random server */
    server = ares__random_server(channel);
  } else {
    /* Pull server with failover behavior */
    server = ares__failover_server(channel);
  }

  if (server == NULL) {
    end_query(channel, query, ARES_ENOSERVER /* ? */, NULL);
    return ARES_ENOSERVER;
  }

  if (query->using_tcp) {
    size_t prior_len = 0;
    /* Make sure the TCP socket for this server is set up and queue
     * a send request.
     */
    if (server->tcp_conn == NULL) {
      new_connection = ARES_TRUE;
      status         = ares__open_connection(channel, server, ARES_TRUE);
      switch (status) {
        /* Good result, continue on */
        case ARES_SUCCESS:
          break;

        /* These conditions are retryable as they are server-specific
         * error codes */
        case ARES_ECONNREFUSED:
        case ARES_EBADFAMILY:
          server_increment_failures(server, query->using_tcp);
          query->error_status = status;
          return ares__requeue_query(query, now);

        /* Anything else is not retryable, likely ENOMEM */
        default:
          end_query(channel, query, status, NULL);
          return status;
      }
    }

    conn = server->tcp_conn;

    prior_len = ares__buf_len(server->tcp_send);

    status = ares__append_tcpbuf(server, query);
    if (status != ARES_SUCCESS) {
      end_query(channel, query, status, NULL);

      /* Only safe to kill connection if it was new, otherwise it should be
       * cleaned up by another process later */
      if (new_connection) {
        ares__close_connection(conn);
      }
      return status;
    }

    if (prior_len == 0) {
      SOCK_STATE_CALLBACK(channel, conn->fd, 1, 1);
    }

  } else {
    ares__llist_node_t *node = ares__llist_node_first(server->connections);

    /* Don't use the found connection if we've gone over the maximum number
     * of queries. Also, skip over the TCP connection if it is the first in
     * the list */
    if (node != NULL) {
      conn = ares__llist_node_val(node);
      if (conn->is_tcp) {
        node = NULL;
      } else if (channel->udp_max_queries > 0 &&
                 conn->total_queries >= channel->udp_max_queries) {
        node = NULL;
      }
    }

    if (node == NULL) {
      new_connection = ARES_TRUE;
      status         = ares__open_connection(channel, server, ARES_FALSE);
      switch (status) {
        /* Good result, continue on */
        case ARES_SUCCESS:
          break;

        /* These conditions are retryable as they are server-specific
         * error codes */
        case ARES_ECONNREFUSED:
        case ARES_EBADFAMILY:
          server_increment_failures(server, query->using_tcp);
          query->error_status = status;
          return ares__requeue_query(query, now);

        /* Anything else is not retryable, likely ENOMEM */
        default:
          end_query(channel, query, status, NULL);
          return status;
      }
      node = ares__llist_node_first(server->connections);
    }

    conn = ares__llist_node_val(node);
    if (ares__socket_write(channel, conn->fd, query->qbuf, query->qlen) == -1) {
      /* FIXME: Handle EAGAIN here since it likely can happen. */
      server_increment_failures(server, query->using_tcp);
      status = ares__requeue_query(query, now);

      /* Only safe to kill connection if it was new, otherwise it should be
       * cleaned up by another process later */
      if (new_connection) {
        ares__close_connection(conn);
      }

      return status;
    }
  }

  timeplus = ares__calc_query_timeout(query);
  /* Keep track of queries bucketed by timeout, so we can process
   * timeout events quickly.
   */
  ares__slist_node_destroy(query->node_queries_by_timeout);
  query->timeout = *now;
  timeadd(&query->timeout, timeplus);
  query->node_queries_by_timeout =
    ares__slist_insert(channel->queries_by_timeout, query);
  if (!query->node_queries_by_timeout) {
    end_query(channel, query, ARES_ENOMEM, NULL);
    /* Only safe to kill connection if it was new, otherwise it should be
     * cleaned up by another process later */
    if (new_connection) {
      ares__close_connection(conn);
    }
    return ARES_ENOMEM;
  }

  /* Keep track of queries bucketed by connection, so we can process errors
   * quickly. */
  ares__llist_node_destroy(query->node_queries_to_conn);
  query->node_queries_to_conn =
    ares__llist_insert_last(conn->queries_to_conn, query);

  if (query->node_queries_to_conn == NULL) {
    end_query(channel, query, ARES_ENOMEM, NULL);
    /* Only safe to kill connection if it was new, otherwise it should be
     * cleaned up by another process later */
    if (new_connection) {
      ares__close_connection(conn);
    }
    return ARES_ENOMEM;
  }

  query->conn = conn;
  conn->total_queries++;
  return ARES_SUCCESS;
}

static ares_bool_t same_questions(const ares_dns_record_t *qrec,
                                  const ares_dns_record_t *arec)
{
  size_t      i;
  ares_bool_t rv = ARES_FALSE;


  if (ares_dns_record_query_cnt(qrec) != ares_dns_record_query_cnt(arec)) {
    goto done;
  }

  for (i = 0; i < ares_dns_record_query_cnt(qrec); i++) {
    const char         *qname = NULL;
    const char         *aname = NULL;
    ares_dns_rec_type_t qtype;
    ares_dns_rec_type_t atype;
    ares_dns_class_t    qclass;
    ares_dns_class_t    aclass;

    if (ares_dns_record_query_get(qrec, i, &qname, &qtype, &qclass) !=
          ARES_SUCCESS ||
        qname == NULL) {
      goto done;
    }

    if (ares_dns_record_query_get(arec, i, &aname, &atype, &aclass) !=
          ARES_SUCCESS ||
        aname == NULL) {
      goto done;
    }
    if (strcasecmp(qname, aname) != 0 || qtype != atype || qclass != aclass) {
      goto done;
    }
  }

  rv = ARES_TRUE;

done:
  return rv;
}

static ares_bool_t same_address(const struct sockaddr  *sa,
                                const struct ares_addr *aa)
{
  const void *addr1;
  const void *addr2;

  if (sa->sa_family == aa->family) {
    switch (aa->family) {
      case AF_INET:
        addr1 = &aa->addr.addr4;
        addr2 = &(CARES_INADDR_CAST(struct sockaddr_in *, sa))->sin_addr;
        if (memcmp(addr1, addr2, sizeof(aa->addr.addr4)) == 0) {
          return ARES_TRUE; /* match */
        }
        break;
      case AF_INET6:
        addr1 = &aa->addr.addr6;
        addr2 = &(CARES_INADDR_CAST(struct sockaddr_in6 *, sa))->sin6_addr;
        if (memcmp(addr1, addr2, sizeof(aa->addr.addr6)) == 0) {
          return ARES_TRUE; /* match */
        }
        break;
      default:
        break; /* LCOV_EXCL_LINE */
    }
  }
  return ARES_FALSE; /* different */
}

static void ares_detach_query(struct query *query)
{
  /* Remove the query from all the lists in which it is linked */
  ares__htable_szvp_remove(query->channel->queries_by_qid, query->qid);
  ares__slist_node_destroy(query->node_queries_by_timeout);
  ares__llist_node_destroy(query->node_queries_to_conn);
  ares__llist_node_destroy(query->node_all_queries);
  query->node_queries_by_timeout = NULL;
  query->node_queries_to_conn    = NULL;
  query->node_all_queries        = NULL;
}

static void end_query(ares_channel_t *channel, struct query *query,
                      ares_status_t status, const ares_dns_record_t *dnsrec)
{
  /* Invoke the callback. */
  query->callback(query->arg, status, query->timeouts, dnsrec);
  ares__free_query(query);

  /* Check and notify if no other queries are enqueued on the channel.  This
   * must come after the callback and freeing the query for 2 reasons.
   *  1) The callback itself may enqueue a new query
   *  2) Technically the current query isn't detached until it is free()'d.
   */
  ares_queue_notify_empty(channel);
}

void ares__free_query(struct query *query)
{
  ares_detach_query(query);
  /* Zero out some important stuff, to help catch bugs */
  query->callback = NULL;
  query->arg      = NULL;
  /* Deallocate the memory associated with the query */
  ares_free(query->qbuf);

  ares_free(query);
}
