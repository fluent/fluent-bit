/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2015 Monkey Software LLC <eduardo@monkey.io>
 *  Copyright 2012, Sonny Karlsson
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <monkey/mk_api.h>

#include <sys/un.h> /* sockaddr_un */
#include <regex.h>  /* regex_t, regcomp */

#include "dbg.h"
#include "fcgi_config.h"
#include "fcgi_context.h"
#include "fcgi_env.h"
#include "fcgi_fd.h"
#include "protocol.h"
#include "chunk.h"
#include "request.h"

const mk_ptr_t mk_fcgi_iov_none = {
	.data = "",
	.len = 0,
};

static struct fcgi_config fcgi_global_config;
static struct fcgi_context_list fcgi_global_context_list;

static pthread_key_t fcgi_local_context;

#define UNUSED_VARIABLE(var) (void)(var)

static int fcgi_handle_cgi_header(struct mk_http_request *sr,
                                  char *entry,
                                  size_t len)
{
	size_t value_len;
	char *value;
	int status;

	if (!strncasecmp(entry, "Content-type: ", 14)) {
		value = entry + 14;
		value_len = len - 14;
		sr->headers.content_type = (mk_ptr_t){
			.data = value,
			.len = value_len,
		};
	}
	else if (!strncasecmp(entry, "Location: ", 10)) {
		value = entry + 10;
		value_len = len - 10 - (*(entry + len - 2) == '\r' ? 2 : 1);
		sr->headers.location = mk_api->mem_alloc(value_len + 1);
		check_mem(sr->headers.location);
		memcpy(sr->headers.location, value, value_len);
		sr->headers.location[value_len] = '\0';
	}
	else if (!strncasecmp(entry, "Status: ", 8)) {
		value = entry + 8;
		check(sscanf(value, "%d", &status) == 1,
              "Could not scan status from FastCGI return.");
		mk_api->header_set_http_status(sr, status);
	} else {
		if (!sr->headers._extra_rows) {
			sr->headers._extra_rows = mk_api->iov_create(
                                                         MK_PLUGIN_HEADER_EXTRA_ROWS * 2,
                                                         0);
		}
		mk_api->iov_add(sr->headers._extra_rows,
                        entry, len, MK_FALSE);
	}
	return 0;
 error:
	return -1;
}

static size_t fcgi_parse_cgi_headers(struct mk_http_request *sr,
                                     struct chunk_iov *iov)
{
	size_t cnt = 0, entry_len, i, len = iov->io[0].iov_len;
	char *p = iov->io[0].iov_base, *q = NULL;

	for (i = 0; cnt < len; i++) {
		q = memchr(p, '\n', len);
		if (!q) {
			break;
		}
		cnt += (size_t)(q - p) + 1;
		if (p + 2 >= q) {
			break;
		}

		entry_len = q - p + 1;
		fcgi_handle_cgi_header(sr, p, entry_len);
		p = q + 1;
	}
	return cnt;
}
/**
 * Will return 0 if there are any connections available to handle a
 * request. If such a connection is sleeping, wake it.
 */
int fcgi_wake_connection(int location_id)
{
	struct fcgi_context *cntx;
	struct fcgi_fd_list *fdl;
	struct fcgi_fd *fd;

	cntx = pthread_getspecific(fcgi_local_context);
	check(cntx, "No fcgi context on thread.");
	fdl = &cntx->fdl;

	fd = fcgi_fd_list_get(fdl,
                          FCGI_FD_SLEEPING | FCGI_FD_READY,
                          location_id);
	if (!fd) {
		return -1;
	}
	else if (fd->state == FCGI_FD_SLEEPING) {

		PLUGIN_TRACE("[FCGI_FD %d] Waking up connection.", fd->fd);
		mk_api->event_socket_change_mode(fd->fd,
                                         MK_EVENT_WRITE, -1);
		check(!fcgi_fd_set_state(fd, FCGI_FD_READY),
              "[FCGI_FD %d]  State change failed.", fd->fd);
	}
	return 0;
 error:
	return -1;
}

int fcgi_server_connect(const struct fcgi_server *server)
{
	int sock_fd = -1;
	socklen_t addr_len;
	struct sockaddr_un addr;

	if (server->path) {
		sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
		check(sock_fd != -1, "Failed to create unix socket.");

		addr.sun_family = AF_UNIX;
		check(sizeof(addr.sun_path) > strlen(server->path) + 1,
              "Socket path too long.");
		strcpy(addr.sun_path, server->path);

		addr_len = sizeof(addr.sun_family) + strlen(addr.sun_path);
		check(connect(sock_fd, (struct sockaddr *)&addr, addr_len) != -1,
              "Failed to connect unix socket.");
	}
	else if (server->addr) {
		sock_fd = mk_api->socket_connect(server->addr, server->port);
		check(sock_fd != -1, "Could not connect to fcgi server.");
	}

	return sock_fd;

 error:
	if (sock_fd != -1) {
		mk_api->socket_close(sock_fd);
	}
	return -1;
}

int fcgi_new_connection(int location_id)
{
	struct fcgi_context *cntx;
	struct fcgi_fd_list *fdl;
	struct fcgi_fd *fd;
	struct fcgi_server *server;

	cntx = pthread_getspecific(fcgi_local_context);
	check(cntx, "No fcgi context on thread.");
	fdl = &cntx->fdl;

	fd = fcgi_fd_list_get(fdl, FCGI_FD_AVAILABLE, location_id);
	if (!fd) {
		PLUGIN_TRACE("Connection limit reached.");
		return 0;
	}

	server = fcgi_config_get_server(&fcgi_global_config, fd->server_id);
	check(server, "Server for this fcgi_fd does not exist.");

	fd->fd = fcgi_server_connect(server);
	check_debug(fd->fd != -1, "Failed to connect to server.");

	mk_api->socket_set_nonblocking(fd->fd);

	//check(!mk_api->event_add(fd->fd,
    //                         MK_EVENT_WRITE,
    //                         plugin, -1),
    //                         "[FD %d] Failed to add event.", fd->fd);

	fcgi_fd_set_state(fd, FCGI_FD_READY);

	return 0;
 error:
	return -1;
}

int fcgi_prepare_request(struct request *req)
{
	struct fcgi_context *cntx;
	struct request_list *rl;
	uint16_t req_id = 0;

	struct fcgi_begin_req_body b = {
		.role  = FCGI_RESPONDER,
	};

	struct fcgi_header h = {
		.version  = FCGI_VERSION_1,
		.body_pad = 0,
	};

	struct fcgi_location *location;

	size_t len = 4096, pos = 0, tmp;
	ssize_t ret;
	uint8_t *buffer;

	cntx = pthread_getspecific(fcgi_local_context);
	check(cntx, "No fcgi context on thread.");
	rl = &cntx->rl;

	buffer = mk_api->mem_alloc(len);
	check_mem(buffer);

	req_id = request_list_index_of(rl, req);
	check(req_id > 0, "[REQ_ID %d] Bad request id.", req_id);

	location = fcgi_config_get_location(&fcgi_global_config, req->clock_id);
	check(location, "[REQ_ID %d] Failed to get location.", req_id);

	// Write begin request.
	h.type     = FCGI_BEGIN_REQUEST;
	h.req_id   = req_id;
	h.body_len = sizeof(b);
	check(len - pos > sizeof(h), "Not enough space left.");
	ret = fcgi_write_header(buffer + pos, &h);
	pos += ret;

	b.flags = location->keep_alive ? FCGI_KEEP_CONN : 0;
	check(len - pos > sizeof(h), "Not enough space left.");
	ret = fcgi_write_begin_req_body(buffer + pos, &b);
	pos += ret;

	tmp = pos;
	pos += sizeof(h);

	ret = fcgi_env_write(buffer + pos, len - pos, req->cs, req->sr);
	check(ret != -1, "Failed to write env.");

	h.type = FCGI_PARAMS;
	h.body_len = ret;
	h.body_pad = ~(ret - 1) & 7;
	fcgi_write_header(buffer + tmp, &h);

	pos += h.body_len + h.body_pad;

	h.type = FCGI_PARAMS;
	h.body_len = 0;
	h.body_pad = 0;
	check(len - pos > sizeof(h), "Not enough space left.");
	ret = fcgi_write_header(buffer + pos, &h);
	pos += ret;

	h.type = FCGI_STDIN;
	if (req->sr->data.len > 0) {
		h.type = FCGI_STDIN;
		h.body_len = req->sr->data.len;
		h.body_pad = ~(req->sr->data.len - 1) & 7;
		check(len - pos > sizeof(h), "Not enough space left.");
		fcgi_write_header(buffer + pos, &h);
		pos += ret;

		check(!chunk_iov_add_ptr(&req->iov, buffer, pos, 1),
              "Adding data to iov failed.");

		check(!chunk_iov_add_ptr(&req->iov,
                                 req->sr->data.data,
                                 req->sr->data.len, 0),
              "Adding data to iov failed.");

		tmp = pos;
		pos += h.body_len + h.body_pad;

		h.body_len = 0;
		h.body_pad = 0;
		check(len - pos > sizeof(h), "Not enough space left.");
		ret = fcgi_write_header(buffer + pos, &h);
		pos += ret;

		check(!chunk_iov_add_ptr(&req->iov, buffer + tmp, pos, 0),
              "Adding data to iov failed.");
	}
	else {
		h.body_len = 0;
		check(len - pos > sizeof(h), "Not enough space left.");
		ret = fcgi_write_header(buffer + pos, &h);
		pos += ret;

		check(!chunk_iov_add_ptr(&req->iov, buffer, pos, 1),
              "Adding data to iov failed.");
	}
	return 0;

 error:
	chunk_iov_reset(&req->iov);
	return -1;
}

int fcgi_send_abort_request(struct request *req, struct fcgi_fd *fd)
{
	struct fcgi_context *cntx;
	struct request_list *rl;
	struct fcgi_header h = {
		.version  = FCGI_VERSION_1,
		.type     = FCGI_ABORT_REQUEST,
		.req_id   = 0,
		.body_len = 0,
		.body_pad = 0,
	};
	uint8_t buf[sizeof(h)];
	ssize_t ret;

	cntx = pthread_getspecific(fcgi_local_context);
	check(cntx, "No fcgi context on thread.");
	rl = &cntx->rl;

	h.req_id = request_list_index_of(rl, req);
	check(h.req_id > 0, "Bad request id: %d.", h.req_id);
	fcgi_write_header(buf, &h);

	ret = write(fd->fd, buf, sizeof(h));
	check(ret != -1, "Socket error.");

	return 0;

 error:
	return -1;
}

int fcgi_send_response_headers(struct request *req)
{
	ssize_t headers_offset;

	if (request_get_flag(req, REQ_HEADERS_SENT)) {
		return 0;
	}

	mk_api->header_set_http_status(req->sr, MK_HTTP_OK);
	req->sr->headers.cgi = SH_NOCGI;

	PLUGIN_TRACE("[FD %d] Length prior to removing headers is %ld.",
                 req->fd, chunk_iov_length(&req->iov));

	headers_offset = fcgi_parse_cgi_headers(req->sr, &req->iov);
	check(!chunk_iov_drop(&req->iov, headers_offset),
          "Failed to drop from req->iov.");
	req->sr->headers.content_length = chunk_iov_length(&req->iov);

	mk_api->header_prepare(req->cs, req->sr);
	req->sr->headers.location = NULL;

	request_set_flag(req, REQ_HEADERS_SENT);

	return 0;

 error:
	return -1;
}

int fcgi_send_response(struct request *req)
{
	int fd = req->fd;
	ssize_t ret;
	struct mk_iov mkiov;

	check(request_get_flag(req, REQ_HEADERS_SENT),
          "Headers not yet sent for request.");

    memset(&mkiov, 0, sizeof(mkiov));
    mkiov.io = req->iov.io;
    mkiov.iov_idx = req->iov.index;
    mkiov.total_len = chunk_iov_length(&req->iov);
	ret = mk_api->socket_sendv(fd, &mkiov);

	PLUGIN_TRACE("[FD %d] Wrote %ld bytes.", fd, ret);
	check(ret != -1, "[FD %d] Failed to send request response.", fd);

	if (ret == (ssize_t)chunk_iov_length(&req->iov)) {
		check(!request_set_state(req, REQ_FINISHED),
              "Failed to set request state.");
		request_recycle(req);

		mk_api->socket_cork_flag(fd, TCP_CORK_OFF);
		mk_api->http_request_end(req->cs, MK_FALSE);
	}
	else {
		check(!chunk_iov_drop(&req->iov, ret),
              "Failed to drop data from chunk.");
	}

	return 0;

 error:
	return -1;
}

static int fcgi_handle_pkg(struct fcgi_fd *fd,
                           struct request *req,
                           struct fcgi_header h,
                           struct chunk_ptr read)
{
	struct fcgi_end_req_body b;

	check(req, "[REQ_ID %d] Failed to fetch request.", h.req_id);

	switch (h.type) {
	case FCGI_STDERR:
		PLUGIN_TRACE("[REQ_ID %d] Recevied stderr, len %d.", h.req_id, h.body_len);
		PLUGIN_TRACE("[REQ_ID %d] %.*s", h.req_id, h.body_len, read.data + sizeof(h));
		break;

	case FCGI_STDOUT:
		if (req->state == REQ_FAILED) {
			PLUGIN_TRACE("[REQ_ID %d] Ignoring stdout to failed req, len %d",
                         h.req_id, h.body_len);
		}
		else if (h.body_len == 0) {
			PLUGIN_TRACE("[REQ_ID %d] Recevied stdout, end-of-stream.",
                         h.req_id);
			check(!request_set_state(req, REQ_STREAM_CLOSED),
                  "Failed to set request state.");
		}
		else {
			PLUGIN_TRACE("[REQ_ID %d] Recevied stdout, len %d",
                         h.req_id, h.body_len);
			check(request_add_pkg(req, h, read) > 0,
                  "[REQ_ID %d] Failed to add stdout package.",
                  h.req_id);
		}
		break;

	case FCGI_END_REQUEST:
		PLUGIN_TRACE("[REQ_ID %d] Recevied end request.", h.req_id);
		fcgi_read_end_req_body(read.data + sizeof(h), &b);

		switch (b.app_status) {
		case EXIT_SUCCESS:
			break;
		case EXIT_FAILURE:
			log_warn("[REQ_ID %d] Application exit failure.",
                     h.req_id);
			break;
		}

		switch (b.protocol_status) {
		case FCGI_REQUEST_COMPLETE:
			break;
		case FCGI_CANT_MPX_CONN:
		case FCGI_OVERLOADED:
		case FCGI_UNKNOWN_ROLE:
		default:
			log_warn("[REQ_ID %d] Protocol status: %s",
                     h.req_id,
                     FCGI_PROTOCOL_STATUS_STR(b.protocol_status));
		}

		request_set_fcgi_fd(req, -1);

		check(!fcgi_fd_set_state(fd, FCGI_FD_READY),
              "[FCGI_FD %d] Failed to set FCGI_FD_READY state.",
              fd->fd);

		if (req->fd == -1) {
			request_recycle(req);
		}
		else if (req->state != REQ_FAILED) {
			PLUGIN_TRACE("[REQ_ID %d] Ending request.",
                         h.req_id);
			check(!request_set_state(req, REQ_ENDED),
                  "[REQ_ID %d] Failed to set request state.",
                  h.req_id);
			if (request_get_flag(req, REQ_SLEEPING)) {
				mk_api->event_socket_change_mode(req->fd,
                                                 MK_EVENT_WRITE, -1);
				request_unset_flag(req, REQ_SLEEPING);
			}
		}
		break;
	case 0:
		sentinel("[REQ_ID %d] Received NULL package.", h.req_id);
		break;
	default:
		log_info("[REQ_ID %d] Ignore package type: %s",
                 h.req_id,
                 FCGI_MSG_TYPE_STR(h.type));
	}

	return 0;
 error:
	if (req) {
		request_set_state(req, REQ_FAILED);
		if (request_get_flag(req, REQ_SLEEPING)) {
			mk_api->event_socket_change_mode(req->fd,
                                             MK_EVENT_WRITE, -1);
			request_unset_flag(req, REQ_SLEEPING);
		}
	}
	return -1;
}

int fcgi_recv_response(struct fcgi_fd *fd,
		struct chunk_list *cl,
                       struct request_list *rl,
                       int (*handle_pkg)(struct fcgi_fd *fd,
                                         struct request *req,
                                         struct fcgi_header h,
                                         struct chunk_ptr rcp))
{
	size_t pkg_size = 0, inherit = 0;
	ssize_t ret = 0;
	int done = 0;

	struct fcgi_header h;
	struct request *req;
	struct chunk *c;
	struct chunk_ptr wcp = { .len = 0, .data = NULL, .parent = NULL};
	struct chunk_ptr rcp = { .len = 0, .data = NULL, .parent = NULL};

	PLUGIN_TRACE("[FCGI_FD %d] Receiving response.", fd->fd);

	c = fcgi_fd_get_chunk(fd);
	if (c != NULL) {
		wcp = chunk_write_ptr(c);
		rcp  = chunk_read_ptr(c);
	}

	do {
		if (inherit > 0 || wcp.len < sizeof(h)) {
			PLUGIN_TRACE("[FCGI_FD %d] New chunk, inherit %ld.",
                         fd->fd,
                         inherit);
			if (pkg_size > CHUNK_SIZE(8192)) {
				c = chunk_new(SIZE_CHUNK(pkg_size));
			} else {
				c = chunk_new(8192);
			}
			check_mem(c);
			chunk_list_add(cl, c);
			check(!fcgi_fd_set_chunk(fd, c, inherit),
                  "[FCGI_FD %d] Failed to add chunk.", fd->fd);
			wcp = chunk_write_ptr(c);
			inherit = 0;
		}

		ret = read(fd->fd, wcp.data, wcp.len);

		if (ret == 0) {
			check(!fcgi_fd_set_state(fd, FCGI_FD_CLOSING),
                  "Failed to set fd state.");
			done = 1;
		} else if (ret == -1) {
			if (errno == EAGAIN) {
				errno = 0;
				done = 1;
			} else {
				sentinel("Socket read error.");
			}
		} else {
			wcp.data += ret;
			wcp.len  -= ret;
			check(!chunk_set_write_ptr(c, wcp),
                  "Failed to set new write ptr.");
			rcp = chunk_read_ptr(c);
		}

		while (rcp.len > 0) {
			if (rcp.len < sizeof(h)) {
				pkg_size = sizeof(h);
			} else {
				fcgi_read_header(rcp.data, &h);
				pkg_size = sizeof(h) + h.body_len + h.body_pad;
			}

			if (rcp.len < pkg_size) {
				inherit = rcp.len;
				ret     = inherit;
			} else {
				req = request_list_get(rl, h.req_id);
				check_debug(!handle_pkg(fd, req, h, rcp),
                            "[REQ_ID %d] Failed to handle pkg.",
                            h.req_id);
				ret = pkg_size;
			}

			rcp.data += ret;
			rcp.len  -= ret;
		}

		if (rcp.parent == c) {
			check(!chunk_set_read_ptr(c, rcp),
                  "Failed to set new read ptr.");
		}
	} while (!done);

	PLUGIN_TRACE("[FCGI_FD %d] Response received successfully.", fd->fd);

	return 0;

 error:
	fcgi_fd_set_state(fd, FCGI_FD_CLOSING);
	return -1;
}

static int regex_match_location(const struct fcgi_config *config,
                                const char *uri)
{
	unsigned int i;
	regex_t *regp;

	for (i = 0; i < config->location_count; i++) {
		regp = &config->locations[i].match_regex;
		if (!regexec(regp, uri, 0, NULL, 0)) {
			return i;
		}
	}
	return -1;
}

int mk_fastcgi_stage30(struct mk_plugin *plugin, struct mk_http_session *cs,
                       struct mk_http_request *sr)
{
	char *uri = NULL;
	struct fcgi_context *cntx;
	struct request_list *rl;
	struct request *req = NULL;
	uint16_t req_id;
	int location_id;

	UNUSED_VARIABLE(plugin);

	cntx = pthread_getspecific(fcgi_local_context);
	check(cntx, "No fcgi context on thread.");
	rl = &cntx->rl;

	uri = mk_api->mem_alloc_z(sr->real_path.len + 1);
	memcpy(uri, sr->real_path.data, sr->real_path.len);

	location_id = regex_match_location(&fcgi_global_config, uri);
	mk_api->mem_free(uri);
	if (location_id == -1) {
		PLUGIN_TRACE("[FD %d] Did not match any location.", cs->socket);
		return MK_PLUGIN_RET_NOT_ME;
	}

	req = request_list_next_available(rl, location_id);
	check(req, "[FD %d] No available request structs.", cs->socket);
	req_id = request_list_index_of(rl, req);

	check(!request_assign(req, cs->socket, location_id, cs, sr),
          "[REQ_ID %d] Failed to assign request for fd %d.",
          req_id, cs->socket);
	check(!fcgi_prepare_request(req),
          "[REQ_ID %d] Failed to prepare request.", req_id);

	PLUGIN_TRACE("[FD %d] Assigned to req_id %d.", cs->socket, req_id);

	if (fcgi_wake_connection(location_id)) {
		PLUGIN_TRACE("[REQ_ID %d] Create new fcgi connection.", req_id);
		check_debug(!fcgi_new_connection(location_id),
                    "New connection failed seriously.");
	}

	request_set_flag(req, REQ_SLEEPING);
	mk_api->event_socket_change_mode(req->fd,
                                     MK_EVENT_SLEEP, 0);

	return MK_PLUGIN_RET_CONTINUE;

 error:
	if (req) {
		PLUGIN_TRACE("[REQ_ID %d] Request failed in stage_30.", req_id);
		request_set_state(req, REQ_FAILED);
		if (request_get_flag(req, REQ_SLEEPING)) {
			mk_api->event_socket_change_mode(req->fd,
                                             MK_EVENT_WRITE, -1);
			request_unset_flag(req, REQ_SLEEPING);
		}
	}
	return MK_PLUGIN_RET_CONTINUE;
}

int mk_fastcgi_plugin_init(struct plugin_api **api, char *confdir)
{
	mk_api = *api;

	pthread_key_create(&fcgi_local_context, NULL);

	check(!fcgi_validate_struct_sizes(),
          "Validating struct sizes failed.");
	check(!fcgi_config_read(&fcgi_global_config, confdir),
          "Failed to read config.");

	return 0;

 error:
	return -1;
}

int mk_fastcgi_plugin_exit()
{
	fcgi_context_list_free(&fcgi_global_context_list);
	fcgi_config_free(&fcgi_global_config);

    return 0;
}

int mk_fastcgi_master_init(struct mk_server_config *config)
{
	check(!fcgi_context_list_init(&fcgi_global_context_list,
                                  &fcgi_global_config,
                                  config->workers,
                                  config->server_capacity),
          "Failed to init thread data list.");
	return 0;

 error:
	return -1;
}

void mk_fastcgi_worker_init()
{
	int tid;
	struct fcgi_context *cntx;

	tid = fcgi_context_list_assign_thread_id(&fcgi_global_context_list);
	check(tid != -1, "Failed to assign thread id.");

	cntx = fcgi_context_list_get(&fcgi_global_context_list, tid);
	pthread_setspecific(fcgi_local_context, cntx);

	return;
 error:
	log_err("Failed to initiate thread context.");
	abort();
}

static int hangup(int socket)
{
	struct fcgi_context *cntx;
	struct fcgi_fd_list *fdl;
	struct fcgi_fd *fd;
	struct request_list *rl;
	struct request *req;
#ifdef TRACE
	uint16_t req_id;
#endif
	enum fcgi_fd_state state;

	cntx = pthread_getspecific(fcgi_local_context);
	if (!cntx) {
		mk_err("No fcgi context on thread.");
		return MK_PLUGIN_RET_EVENT_NEXT;
	}
	fdl = &cntx->fdl;
	rl = &cntx->rl;

	fd  = fcgi_fd_list_get_by_fd(fdl, socket);
	req = fd ? NULL : request_list_get_by_fd(rl, socket);

	if (!fd && !req) {
		return MK_PLUGIN_RET_EVENT_NEXT;
	}
	else if (fd) {
		PLUGIN_TRACE("[FCGI_FD %d] Hangup event.", fd->fd);

		close(fd->fd);

		state = fd->state;

		fd->fd     = -1;
		fd->state  = FCGI_FD_AVAILABLE;

		if (state & FCGI_FD_CLOSING) {
			fcgi_new_connection(fd->location_id);
		}

		return MK_PLUGIN_RET_EVENT_OWNED;
	}
	else if (req) {
#ifdef TRACE
		req_id = request_list_index_of(rl, req);
		PLUGIN_TRACE("[REQ_ID %d] Hangup event.", req_id);
#endif

		if (req->state != REQ_FAILED) {
			request_set_state(req, REQ_FAILED);
		}

		if (req->fcgi_fd == -1) {
			request_recycle(req);
		} else {
			req->fd = -1;
			req->cs = NULL;
			req->sr = NULL;
		}

		return MK_PLUGIN_RET_EVENT_CONTINUE;
	}
	else {
		return MK_PLUGIN_RET_EVENT_CONTINUE;
	}
}

int _mkp_event_write(int socket)
{
	uint16_t req_id = 0;
	struct fcgi_context *cntx;
	struct request_list *rl;
	struct request *req = NULL;
	struct fcgi_fd_list *fdl;
	struct fcgi_fd *fd;
	ssize_t ret;

	cntx = pthread_getspecific(fcgi_local_context);
	check(cntx, "No fcgi context on thread.");
	rl = &cntx->rl;
	fdl = &cntx->fdl;

	fd  = fcgi_fd_list_get_by_fd(fdl, socket);
	req = fd ? NULL : request_list_get_by_fd(rl, socket);

	if (!fd && !req) {
		return MK_PLUGIN_RET_EVENT_NEXT;
	}
	else if (req && req->state == REQ_ENDED) {
		req_id = request_list_index_of(rl, req);

		PLUGIN_TRACE("[REQ_ID %d] Request ended.", req_id);

		check(!fcgi_send_response_headers(req),
              "[REQ_ID %d] Failed to send response headers.", req_id);
		check(!fcgi_send_response(req),
              "[REQ_ID %d] Failed to send response.", req_id);

		return MK_PLUGIN_RET_EVENT_OWNED;
	}
	else if (req && req->state == REQ_FAILED) {
#ifdef TRACE
		req_id = request_list_index_of(rl, req);
#endif

		mk_api->http_request_error(MK_SERVER_INTERNAL_ERROR,
                                   req->cs, req->sr);

		if (req->fcgi_fd == -1) {
			request_recycle(req);
		}
		mk_api->http_request_end(req->cs, MK_FALSE);

		return MK_PLUGIN_RET_EVENT_OWNED;
	}
	else if (fd && fd->state == FCGI_FD_READY) {
		req = request_list_next_assigned(rl, fd->location_id);

		if (req) {
			req_id = request_list_index_of(rl, req);
			request_set_fcgi_fd(req, fd->fd);

			check(!request_set_state(req, REQ_SENT),
                  "[REQ_ID %d] Failed to set sent state.",
                  req_id);
			check(!fcgi_fd_set_begin_req_iov(fd, &req->iov),
                  "[FCGI_FD %d] Failed to set begin_req_iov.",
                  fd->fd);
			check(!fcgi_fd_set_state(fd, FCGI_FD_SENDING),
                  "[FCGI_FD %d] Failed to set sending state.",
                  fd->fd);

			if (fd->type == FCGI_FD_INET) {
				mk_api->socket_cork_flag(fd->fd, TCP_CORK_ON);
			}

			return _mkp_event_write(fd->fd);
		}
		else {
			PLUGIN_TRACE("[FCGI_FD %d] Sleep.", fd->fd);

			mk_api->event_socket_change_mode(fd->fd,
                                             MK_EVENT_SLEEP,
                                             -1);
			check(!fcgi_fd_set_state(fd, FCGI_FD_SLEEPING),
                  "Failed to set fd state.");

			return MK_PLUGIN_RET_EVENT_OWNED;
		}
	}
	else if (fd && fd->state == FCGI_FD_SENDING) {

		PLUGIN_TRACE("[FCGI_FD %d] Sending request.", fd->fd);

		check(fd->begin_req,
              "[FCGI_FD %d] No begin_req attached.", fd->fd);

		ret = chunk_iov_sendv(fd->fd, fd->begin_req);
		if (ret == -1) {
			check(errno == EAGAIN, "Socket write error.");

			PLUGIN_TRACE("[FCGI_FD %d] EAGAIN on write.", fd->fd);

			return MK_PLUGIN_RET_EVENT_OWNED;
		}

		fd->begin_req_remain -= ret;

		if (fd->begin_req_remain == 0) {
			if (fd->type == FCGI_FD_INET) {
				mk_api->socket_cork_flag(fd->fd, TCP_CORK_OFF);
			}
			fcgi_fd_set_state(fd, FCGI_FD_RECEIVING);
			chunk_iov_reset(fd->begin_req);
			fd->begin_req = NULL;

			mk_api->event_socket_change_mode(fd->fd,
                                             MK_EVENT_READ, -1);
		} else {
			chunk_iov_drop(fd->begin_req, ret);
		}

		return MK_PLUGIN_RET_EVENT_OWNED;
	}
	else {
		return MK_PLUGIN_RET_EVENT_CONTINUE;
	}
 error:
	if (req) {
		PLUGIN_TRACE("[REQ_ID %d] Request failed in event_write.", req_id);
		request_set_state(req, REQ_FAILED);
		if (request_get_flag(req, REQ_SLEEPING)) {
			mk_api->event_socket_change_mode(req->fd,
                                             MK_EVENT_WRITE, -1);
			request_unset_flag(req, REQ_SLEEPING);
		}
	}
	return MK_PLUGIN_RET_EVENT_CLOSE;
}

int _mkp_event_read(int socket)
{
	struct fcgi_context *cntx;
	struct chunk_list *cl;
	struct request_list *rl;
	struct fcgi_fd_list *fdl;
	struct fcgi_fd *fd;
	struct fcgi_location *loc;

	cntx = pthread_getspecific(fcgi_local_context);
	check(cntx, "No fcgi context on thread.");
	cl = &cntx->cl;
	rl = &cntx->rl;
	fdl = &cntx->fdl;

	fd = fcgi_fd_list_get_by_fd(fdl, socket);
	if (!fd) {
		return MK_PLUGIN_RET_EVENT_NEXT;
	}
	else {
		loc = fcgi_config_get_location(&fcgi_global_config, fd->location_id);
		check(loc, "No location for fcgi_fd.");
		PLUGIN_TRACE("[FCGI_FD %d] Receiving data.", fd->fd);

		check_debug(!fcgi_recv_response(fd, cl, rl, fcgi_handle_pkg),
                    "[FCGI_FD %d] Failed to receive response.", fd->fd);

		PLUGIN_TRACE("[FCGI_FD %d] Data received.", fd->fd);

		if (fd->state == FCGI_FD_READY) {
			if (loc->keep_alive) {
				mk_api->event_socket_change_mode(fd->fd,
                                                 MK_EVENT_WRITE, -1);
			}
			else {
				check(!fcgi_fd_set_state(fd, FCGI_FD_CLOSING),
                      "[FCGI_FD %d] State change failed.", fd->fd);
				return MK_PLUGIN_RET_EVENT_CLOSE;
			}
		}
		else if (fd->state == FCGI_FD_CLOSING) {
			return MK_PLUGIN_RET_EVENT_CLOSE;
		}

		return MK_PLUGIN_RET_EVENT_OWNED;
	}

error:
	return MK_PLUGIN_RET_EVENT_CLOSE;
}

int _mkp_event_close(int socket)
{
	return hangup(socket);
}

int _mkp_event_error(int socket)
{
	return hangup(socket);
}


struct mk_plugin_stage mk_plugin_stage_fastcgi = {
    .stage30      = &mk_fastcgi_stage30
};

struct mk_plugin mk_plugin_fastcgi = {
    /* Identification */
    .shortname     = "fastcgi",
    .name          = "FastCGI Client",
    .version       = "0.4",
    .hooks         = MK_PLUGIN_STAGE,

    /* Init / Exit */
    .init_plugin   = mk_fastcgi_plugin_init,
    .exit_plugin   = mk_fastcgi_plugin_exit,

    /* Init Levels */
    .master_init   = mk_fastcgi_master_init,
    .worker_init   = NULL,

    /* Type */
    .stage         = &mk_plugin_stage_fastcgi
};
