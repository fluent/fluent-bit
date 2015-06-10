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
#include "dbg.h"
#include "protocol.h"

#include "request.h"

/* Calculate next power of two for 16 bit integers, modified version of
 * http://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
 */
uint16_t next_power_of_2(uint16_t v)
{
	v--;
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v++;

	return v;
}

/* Check if 16 bit integer is power of 2,
 * http://graphics.stanford.edu/~seander/bithacks.html#DetermineIfPowerOf2
 */
uint16_t is_power_of_2(uint16_t v)
{
	return ((v != 0) && !(v & (v - 1)));
}

int request_init(struct request *req, int iov_n)
{
	*req = (struct request){
		.state = REQ_AVAILABLE,
		.flags = 0,

		.fd = -1,
		.fcgi_fd = -1,

		.clock_id = 0,
		.cs = NULL,
		.sr = NULL,

		.iov = {
			.index = 0,
			.size = 0,
			.held_refs = NULL,
			.io = NULL,
		},
	};

	check(!chunk_iov_init(&req->iov, iov_n), "Failed to init chunk_iov.");

	return 0;
error:
	return -1;
}

static void request_reset(struct request *req)
{
	req->state         = REQ_AVAILABLE;
	req->flags         = 0;
	req->fd            = -1;
	req->fcgi_fd       = -1;
	req->clock_id      = 0;

	chunk_iov_reset(&req->iov);
}

int request_set_state(struct request *req, enum request_state state)
{
	switch (state) {
	case REQ_AVAILABLE:
		check(req->state == REQ_FINISHED,
			"Bad state transition to REQ_AVAILABLE.");
		request_reset(req);
		break;
	case REQ_ASSIGNED:
		check(req->state == REQ_AVAILABLE ||
			req->state == REQ_FINISHED,
			"Bad state transition to REQ_ASSIGNED.");
		req->state = REQ_ASSIGNED;
		break;
	case REQ_SENT:
		check(req->state == REQ_ASSIGNED,
			"Bad state transition to REQ_SENT.");
		req->state = REQ_SENT;
		break;
	case REQ_STREAM_CLOSED:
		check(req->state == REQ_SENT,
			"Bad state transition to REQ_STREAM_CLOSED.");
		req->state = REQ_STREAM_CLOSED;
		break;
	case REQ_ENDED:
		check(req->state == REQ_STREAM_CLOSED ||
			req->state == REQ_FAILED ||
			req->state == REQ_SENT,
			"Bad state transition REQ_ENDED.");
		req->state = REQ_ENDED;
		break;
	case REQ_FINISHED:
		check(req->state == REQ_ENDED,
			"Bad state transition REQ_FINISHED.");
		req->state = REQ_FINISHED;
		break;
	case REQ_FAILED:
		req->state = REQ_FAILED;
		break;
	default:
		sentinel("Tried to set unknown request state.");
	};
	return 0;
error:
	return -1;
}

int request_set_flag(struct request *req, enum request_flags flag)
{
	check(!(req->flags & flag), "Flag already set.");

	req->flags |= flag;

	return 0;
error:
	return -1;
}

int request_unset_flag(struct request *req, enum request_flags flag)
{
	check(req->flags & flag, "Flag not set.");

	req->flags &= ~flag;

	return 0;
error:
	return -1;
}

int request_get_flag(const struct request *req, enum request_flags flag)
{
	return !!(req->flags & flag);
}

int request_assign(struct request *req,
                   int fd,
                   uint16_t clock_id,
                   struct mk_http_session *cs,
                   struct mk_http_request *sr)
{
	check_debug(!request_set_state(req, REQ_ASSIGNED),
		"Failed to set request state.");

	req->fd = fd;
	req->clock_id = clock_id;
	req->cs = cs;
	req->sr = sr;
	return 0;
error:
	return -1;
}

void request_set_fcgi_fd(struct request *req, int fcgi_fd)
{
	req->fcgi_fd = fcgi_fd;
}

int request_recycle(struct request *req)
{
	if (!(req->state & (REQ_FINISHED | REQ_FAILED))) {
		log_warn("Recycling still running request.");
	}

	request_reset(req);
	return 0;
}

ssize_t request_add_pkg(struct request *req,
		struct fcgi_header h,
		struct chunk_ptr cp)
{
	size_t pkg_length = sizeof(h) + h.body_len + h.body_pad;

	check(cp.len >= pkg_length, "Missing package data.");
	check(req->state == REQ_SENT, "Request not yet sent.");

	cp.data += sizeof(h);
	cp.len = h.body_len;

	if (chunk_iov_add(&req->iov, cp)) {
		check(!chunk_iov_resize(&req->iov, req->iov.size + 2),
				"Failed to resize chunk.");
		check(!chunk_iov_add(&req->iov, cp),
				"Adding content to iov failed.");
	}

	return pkg_length;
error:
	return -1;

}

void request_free(struct request *req)
{
	request_reset(req);
	chunk_iov_free(&req->iov);
}

void request_cache_init(struct request_cache *cache)
{
	uint16_t i;

	for (i = 0; i < REQ_CACHE_SIZE; i++) {
		cache->entries[i].req = NULL;
		cache->entries[i].fd = -1;
		cache->entries[i].counter = 0;
	}

	cache->clock_hand = 0;
	cache->mask = REQ_CACHE_SIZE - 1;
}

void request_cache_add(struct request_cache *cache, struct request *req)
{
	uint16_t i, mask = cache->mask, clock = cache->clock_hand;
	struct req_cache_entry *e;

	i = clock;
	do {
		i = (i + 1) & mask;
		e = cache->entries + 1;

		if (e->counter > 0) {
			e->counter--;
		} else {
			e->req = req;
			e->fd = req->fd;
			e->fcgi_fd = req->fcgi_fd;
			e->counter = 1;
			cache->clock_hand = i;
			return;
		}
	} while (i != clock);
}

void request_cache_hit(struct request_cache *cache, struct request *req)
{
	uint16_t i, mask = cache->mask, clock = cache->clock_hand;
	struct req_cache_entry *e;

	i = clock;
	do {
		i = (i + 1) & mask;
		e = cache->entries + i;

		if (e->req == req) {
			e->fd = req->fd;
			e->fcgi_fd = req->fcgi_fd;
			e->counter += 1;
			return;
		}
	} while (i != clock);

	request_cache_add(cache, req);
}

struct request *request_cache_search_fcgi_fd(struct request_cache *cache, int fd)
{
	uint16_t i, mask = cache->mask, clock = cache->clock_hand;
	struct req_cache_entry *e;

	i = clock;
	do {
		i = (i + 1) & mask;
		e = cache->entries + i;

		if (e->fcgi_fd == fd) {
			if (e->req->fcgi_fd == fd) {
				e->counter += 1;
				return e->req;
			} else {
				e->counter = 0;
				e->fcgi_fd = -1;
				return NULL;
			}
		}
	} while (i != clock);

	return NULL;
}

struct request *request_cache_search(struct request_cache *cache, int fd)
{
	uint16_t i, mask = cache->mask, clock = cache->clock_hand;
	struct req_cache_entry *e;

	i = clock;
	do {
		i = (i + 1) & mask;
		e = cache->entries + i;

		if (e->fd == fd) {
			if (e->req->fd == fd) {
				e->counter += 1;
				return e->req;
			} else {
				e->counter = 0;
				e->fd = -1;
				return NULL;
			}
		}
	} while (i != clock);

	return NULL;
}

int request_list_init(struct request_list *rl,
		uint16_t clock_count,
		uint16_t id_offset,
		uint16_t size)
{
	uint16_t *clock_hands = NULL;
	struct request *tmp = NULL;
	uint16_t i;

	check(is_power_of_2(size), "Size must be power of 2, it is %d", size);

	request_cache_init(&rl->cache);

	clock_hands = mk_api->mem_alloc(clock_count * sizeof(*clock_hands));
	check_mem(clock_hands);

	for (i = 0; i < clock_count; i++) {
		clock_hands[i] = 0;
	}

	tmp = mk_api->mem_alloc(size * sizeof(*tmp));
	check_mem(tmp);

	for (i = 0; i < size; i++) {
		check(!request_init(tmp + i, 4),
			"Failed to init request %d", i);
	}

	rl->size = size;
	rl->id_offset = id_offset;
	rl->clock_count = clock_count;
	rl->clock_hands = clock_hands;
	rl->rs = tmp;

	return 0;
error:
	if (tmp && i > 0) {
		size = i;
		for (i = 0; i < size; i++) {
			request_free(tmp + i);
		}
	}
	if (tmp) mk_api->mem_free(tmp);
	return -1;
}

static int get_clock_hand(struct request_list *rl, uint16_t clock_id)
{
	check(clock_id < rl->clock_count, "Clock index out of range.");

	return rl->clock_hands[clock_id];
error:
	return 0;
}

static void set_clock_hand(struct request_list *rl,
		uint16_t clock_id,
		uint16_t clock_hand)
{
	check(clock_id < rl->clock_count,
		"location index out of range.");

	rl->clock_hands[clock_id] = clock_hand;
error:
	return;
}

struct request *request_list_next_available(struct request_list *rl,
		uint16_t clock_id)
{
	uint16_t i, mask = rl->size - 1, clock = get_clock_hand(rl, clock_id);
	struct request *r;

	i = clock;
	do {
		i = (i + 1) & mask;
		r = rl->rs + i;
		if (r->state == REQ_AVAILABLE) {
			return r;
		}
	} while (i != clock);

	return NULL;
}

struct request *request_list_next_assigned(struct request_list *rl,
		uint16_t clock_id)
{
	uint16_t i, mask = rl->size - 1, clock = get_clock_hand(rl, clock_id);
	struct request *r;

	i = clock;
	do {
		i = (i + 1) & mask;
		r = rl->rs + i;
		if (r->state == REQ_ASSIGNED && r->clock_id == clock_id) {
			request_cache_hit(&rl->cache, r);
			set_clock_hand(rl, clock_id, i);
			return r;
		}
	} while (i != clock);

	return NULL;
}

struct request *request_list_get_by_fd(struct request_list *rl, int fd)
{
	uint16_t i, mask = rl->size -1, clock = get_clock_hand(rl, 0);
	struct request *r;

	r = request_cache_search(&rl->cache, fd);
	if (r != NULL) {
		return r;
	}

	i = clock;
	do {
		i = (i + 1) & mask;
		r = rl->rs + i;
		if (r->fd == fd) {
			request_cache_add(&rl->cache, r);
			return r;
		}
	} while (i != clock);

	return NULL;
}

struct request *request_list_get_by_fcgi_fd(struct request_list *rl, int fd)
{
	uint16_t i, mask = rl->size -1, clock = get_clock_hand(rl, 0);
	struct request *r;

	r = request_cache_search_fcgi_fd(&rl->cache, fd);
	if (r != NULL) {
		return r;
	}

	i = clock;
	do {
		r = rl->rs + i;
		if (r->fcgi_fd == fd) {
			request_cache_add(&rl->cache, r);
			return r;
		}
		i = (i + 1) & mask;
	} while (i != clock);

	return NULL;
}

struct request *request_list_get(struct request_list *rl, uint16_t req_id)
{
	uint16_t real_req_index = req_id - rl->id_offset;
	check(req_id >= rl->id_offset,
		"Request id out of range.");
	check(real_req_index < rl->size,
		"Request id out of range.");

	request_cache_hit(&rl->cache, rl->rs + real_req_index);

	return rl->rs + real_req_index;
error:
	return NULL;
}

uint16_t request_list_index_of(struct request_list *rl, struct request *r)
{
	ptrdiff_t offset = r - rl->rs;

	check(r >= rl->rs && r <= rl->rs + rl->size, "Request not part of list.");

	return rl->id_offset + offset;
error:
	return 0;

}

void request_list_free(struct request_list *rl)
{
	uint16_t i;

	if (!rl)
		return;

	for (i = 0; i < rl->size; i++) {
		request_free(rl->rs + i);
	}
	mk_api->mem_free(rl->rs);
	rl->size = 0;
	rl->rs = NULL;
}
