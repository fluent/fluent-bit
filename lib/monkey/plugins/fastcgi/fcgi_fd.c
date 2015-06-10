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

#ifdef DEBUG
#include <stdio.h> /* printf */
#endif

#include "dbg.h"
#include "fcgi_fd.h"

void fcgi_fd_init(struct fcgi_fd *fd,
		enum fcgi_fd_type type,
		int server_id,
		int location_id)
{
	fd->type = type;
	fd->state = FCGI_FD_AVAILABLE;
	fd->fd = -1;
	fd->server_id = server_id;
	fd->location_id = location_id;

	fd->begin_req_remain = 0;
	fd->begin_req = NULL;

	fd->chunk = NULL;
}

int fcgi_fd_set_state(struct fcgi_fd *fd, enum fcgi_fd_state state)
{
	switch (state) {
	case FCGI_FD_AVAILABLE:
		check(fd->state & (FCGI_FD_CLOSING | FCGI_FD_SLEEPING),
			"Bad state transition. (C|S) -> A");
		fd->state = FCGI_FD_AVAILABLE;
		break;
	case FCGI_FD_READY:
		check(fd->state & (FCGI_FD_AVAILABLE
				| FCGI_FD_RECEIVING
				| FCGI_FD_SLEEPING),
			"Bad state transition. (A|Re|S) -> R");
		fd->state = FCGI_FD_READY;
		break;
	case FCGI_FD_SENDING:
		check(fd->state & (FCGI_FD_READY),
			"Bad state transition. Re -> Se");
		fd->state = FCGI_FD_SENDING;
		break;
	case FCGI_FD_RECEIVING:
		check(fd->state & (FCGI_FD_SENDING),
			"Bad state transition. Se -> R, %d", fd->state);
		fd->state = FCGI_FD_RECEIVING;
		break;
	case FCGI_FD_CLOSING:
		check(fd->state & (FCGI_FD_READY | FCGI_FD_RECEIVING),
			"Bad state transition. R -> C");
		fd->state = FCGI_FD_CLOSING;
		break;
	case FCGI_FD_SLEEPING:
		check(fd->state & (FCGI_FD_READY),
			"Bad state transition. R -> Sl");
		fd->state = FCGI_FD_SLEEPING;
		break;
	}
	return 0;
error:
	return -1;
}

int fcgi_fd_set_begin_req_iov(struct fcgi_fd *fd, struct chunk_iov *iov)
{
	check(fd->state == FCGI_FD_READY,
		"[FCGI_FD %d] Please set begin_req_iov when ready.", fd->fd);

	fd->begin_req_remain = chunk_iov_length(iov);
	fd->begin_req = iov;

	return 0;
error:
	return -1;
}

/*
 * Copy inherit bytes from old chunk to new chunk and set as current
 * chunk.
 */
int fcgi_fd_set_chunk(struct fcgi_fd *fd, struct chunk *a, size_t inherit)
{
	struct chunk *b = fd->chunk;
	size_t b_pos, a_pos;
	struct chunk_ptr tmp;

	chunk_retain(a);

	if (b && inherit > 0) {
		check(b->write >= inherit,
			"Not enough used on old chunk to inherit.");
		check(a->size - a->write > inherit,
			"Not enough free space on new chunk to inherit.");

		a_pos = a->write;
		b_pos = b->write - inherit;

		memcpy(a->data + a_pos, b->data + b_pos, inherit);

		a_pos     += inherit;
		tmp.parent = a;
		tmp.len    = a->size - a_pos;
		tmp.data   = a->data + a_pos;

		check(!chunk_set_write_ptr(a, tmp),
			"Failed to set new write pointer.");
		chunk_release(b);
	} else if (b) {
		chunk_release(b);
	} else {
		check(inherit == 0, "There are no chunks to inherit from.");
	}

	fd->chunk = a;
	return 0;
error:
	if (mk_list_is_empty(&a->_head)) {
		mk_list_del(&a->_head);
	}
	return -1;
}

struct chunk *fcgi_fd_get_chunk(struct fcgi_fd *fd)
{
	return fd->chunk;
}

int fcgi_fd_list_init(struct fcgi_fd_list *fdl,
		const struct fcgi_fd_matrix fdm,
		unsigned int thread_id,
		const struct fcgi_config *config)
{
	const struct fcgi_location *loc;
	const struct fcgi_server *srv;
	int server_location_id[config->server_count];

	unsigned int fd_count = fcgi_fd_matrix_thread_sum(fdm, thread_id);
	unsigned int server_fd_count;
	enum fcgi_fd_type type;
	unsigned int fd_id = 0;
	unsigned int i, j;

	for (i = 0; i < fdm.server_count; i++) {
		server_location_id[i] = -1;
	}
	for (i = 0; i < config->location_count; i++) {
		loc = config->locations + i;

		for (j = 0; j < loc->server_count; j++) {
			server_location_id[loc->server_ids[j]] = i;
		}
	}

	fdl->n = fd_count;
	fdl->fds = NULL;

	fdl->fds = mk_api->mem_alloc(fd_count * sizeof(*fdl->fds));
	check_mem(fdl->fds);

	for (i = 0; i < fdm.server_count; i++) {
		server_fd_count = fcgi_fd_matrix_get(fdm, thread_id, i);

		srv = fcgi_config_get_server(config, i);
		check(srv, "No server with id %d.", i);
		type = srv->path ? FCGI_FD_UNIX : FCGI_FD_INET;

		for (j = 0; j < server_fd_count; j++, fd_id++) {
			check(server_location_id[i] != -1,
					"No location for server %s", srv->name);
			fcgi_fd_init(fdl->fds + fd_id, type, i, server_location_id[i]);
		}
	}
	check(fd_id == fd_count, "Init too many fcgi_fd.");

	return 0;
error:
	fdl->n = 0;
	if (fdl->fds) {
		mk_api->mem_free(fdl->fds);
		fdl->fds = NULL;
	}
	return -1;
}

void fcgi_fd_list_free(struct fcgi_fd_list *fdl)
{
	mk_api->mem_free(fdl->fds);
}

struct fcgi_fd *fcgi_fd_list_get(struct fcgi_fd_list *fdl,
		enum fcgi_fd_state state,
		int location_id)
{
	struct fcgi_fd *fd;
	int i;

	for (i = 0; i < fdl->n; i++) {
		fd = fdl->fds + i;

		if (fd->state & state && fd->location_id == location_id) {
			return fd;
		}
	}
	return NULL;
}

struct fcgi_fd *fcgi_fd_list_get_by_fd(struct fcgi_fd_list *fdl, int fd)
{
	int i;

	for (i = 0; i < fdl->n; i++) {
		if (fdl->fds[i].fd == fd) {
			return fdl->fds + i;
		}
	}
	return NULL;
}

static void distribute_conns_normal(struct fcgi_fd_matrix fdm,
		const struct fcgi_location *loc,
		const struct fcgi_config *config)
{
	unsigned int fd_count;
	const struct fcgi_server *srv;
	unsigned int i, j, srv_id, t_clock = 0;

	check(fdm.thread_count > 0, "Struct fcgi_fd_matrix not initialized.");

	for (i = 0; i < loc->server_count; i++) {
		srv_id = loc->server_ids[i];
		srv = fcgi_config_get_server(config, srv_id);
		fd_count = srv->max_connections;

		for (j = t_clock; fd_count > 0; j = (j + 1) % fdm.thread_count) {
			fdm.thread_server_fd[j * fdm.server_count + srv_id] += 1;
			fd_count -= 1;
		}
		t_clock = j;
	}
error:
	return;
}

static void distribute_conns_fallback(struct fcgi_fd_matrix fdm,
		const struct fcgi_location *loc)
{
	unsigned int i, t_id = 0, s_id = 0;

	check(loc->server_count > 0, "No servers for this location.");

	for (i = 0; t_id < fdm.thread_count; i = (i + 1) % loc->server_count) {
		s_id = loc->server_ids[i];

		fdm.thread_server_fd[t_id * fdm.server_count + s_id] = 1;
		t_id++;
	}
error:
	return;
}

struct fcgi_fd_matrix fcgi_fd_matrix_create(const struct fcgi_config *config,
		unsigned int worker_count)
{
	unsigned int loc_fd_count;
	const struct fcgi_location *loc;
	const struct fcgi_server *srv;
	unsigned int i, j;

	struct fcgi_fd_matrix fdm = {
		.server_count = config->server_count,
		.thread_count = worker_count,
	};

	fdm.thread_server_fd = mk_api->mem_alloc_z(fdm.server_count *
			fdm.thread_count *
			sizeof(*fdm.thread_server_fd));
	check_mem(fdm.thread_server_fd);

	for (i = 0; i < config->location_count; i++) {
		loc = config->locations + i;
		loc_fd_count = 0;

		for (j = 0; j < loc->server_count; j++) {
			srv = fcgi_config_get_server(config, loc->server_ids[j]);
			loc_fd_count += srv->max_connections > 0 ?
				srv->max_connections : 1;
		}

		if (loc_fd_count < worker_count) {
			log_info("[LOC %s] Sum of server fds less than workers, "
					"using fallback distribution.",
					loc->name);
			if (loc->keep_alive) {
				log_warn("[LOC %s] Unless keep_alive is disabled "
					"some threads will be starved.",
					loc->name);
			}
			distribute_conns_fallback(fdm, loc);
		} else {
			distribute_conns_normal(fdm, loc, config);
		}
	}

#ifdef DEBUG
	printf("fcgi_fd_matrix:\n");
	for (i = 0; i < fdm.thread_count; i++) {
		for (j = 0; j < fdm.server_count; j++) {
			printf("%5d",
				fdm.thread_server_fd[i * fdm.server_count + j]);
		}
		printf("\n");
	}
#endif
	return fdm;
error:
	if (fdm.thread_server_fd) {
		mk_api->mem_free(fdm.thread_server_fd);
	}
	return (struct fcgi_fd_matrix){
		.server_count = 0,
		.thread_count = 0,
		.thread_server_fd = NULL,
	};
}

void fcgi_fd_matrix_free(struct fcgi_fd_matrix *fdm)
{
	fdm->thread_count = 0;
	fdm->server_count = 0;
	if (fdm->thread_server_fd) {
		mk_api->mem_free(fdm->thread_server_fd);
		fdm->thread_server_fd = NULL;
	}
}

unsigned int fcgi_fd_matrix_thread_sum(const struct fcgi_fd_matrix fdm,
		unsigned int thread_id)
{
	unsigned int fd_count = 0;
	unsigned int *row_ptr = fdm.thread_server_fd +
		thread_id * fdm.server_count;
	unsigned int i;

	check(fdm.thread_server_fd, "fcgi_fd_matrix is uninitialized.");

	for (i = 0; i < fdm.server_count; i++) {
		fd_count += row_ptr[i];
	}

	return fd_count;
error:
	return 0;
}

unsigned int fcgi_fd_matrix_get(const struct fcgi_fd_matrix fdm,
		unsigned int thread_id,
		unsigned int server_id)
{
	check(fdm.thread_server_fd, "fcgi_fd_matrix is uninitialized.");

	return fdm.thread_server_fd[thread_id * fdm.server_count + server_id];
error:
	return 0;
}
