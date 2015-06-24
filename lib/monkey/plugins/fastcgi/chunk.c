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

#define _GNU_SOURCE

#include <sys/uio.h> /* struct iovec, writev */
#include <limits.h>

#include "dbg.h"
#include "chunk.h"

struct chunk *chunk_new(size_t size)
{
	struct chunk *tmp = NULL;

	tmp = mk_api->mem_alloc(size);
	check_mem(tmp);

	mk_list_init(&tmp->_head);
	tmp->read  = 0;
	tmp->write = 0;
	tmp->refs  = 0;
	tmp->size  = CHUNK_SIZE(size);

	return tmp;
 error:
	if (tmp) {
        mk_api->mem_free(tmp);
	}
	return NULL;
}

struct chunk_ptr chunk_read_ptr(struct chunk *c)
{
	return (struct chunk_ptr){
		.parent = c,
		.len    = c->write - c->read,
		.data   = c->data + c->read,
	};
}

struct chunk_ptr chunk_write_ptr(struct chunk *c)
{
	return (struct chunk_ptr){
		.parent = c,
		.len    = c->size - c->write,
		.data   = c->data + c->write,
	};
}

int chunk_set_read_ptr(struct chunk *c, struct chunk_ptr read)
{
	check(read.parent == c,
		"Pointer not from this chunk.");
	check(read.data >= c->data && read.data <= c->data + c->size,
		"Pointer out of range for this chunk.");

	c->read = read.data - c->data;
	return 0;
error:
	return -1;
}

int chunk_set_write_ptr(struct chunk *c, struct chunk_ptr write)
{
	check(write.parent == c,
		"Pointer not from this chunk.");
	check(write.data >= c->data && write.data <= c->data + c->size,
		"Pointer out of range for this chunk.");

	c->write = write.data - c->data;
	return 0;
error:
	return -1;
}

void chunk_free(struct chunk *c)
{
	mk_list_del(&c->_head);
	mk_api->mem_free(c);
}

void chunk_retain(struct chunk *c)
{
	c->refs += 1;
}

int chunk_release(struct chunk *c)
{
	c->refs -= 1;

	if (c->refs == 0) {
            chunk_free(c);
            return 1;
        }
        return 0;
}

void chunk_list_init(struct chunk_list *cm)
{
	mk_list_init(&cm->chunks._head);
}

struct chunk *chunk_list_current(struct chunk_list *cm)
{
	check_debug(mk_list_is_empty(&cm->chunks._head), "No managed chunks.");

	return mk_list_entry_last((&cm->chunks._head), struct chunk, _head);
error:
	return NULL;
}

void chunk_list_add(struct chunk_list *cm, struct chunk *a)
{
	mk_list_add(&a->_head, &cm->chunks._head);
}

void chunk_list_stats(struct chunk_list *cm)
{
	struct mk_list *head;
	struct chunk *c;
	size_t used;
	size_t free;
	size_t total_used = 0;
	size_t total_free = 0;
	int chunks        = 0;

	log_info("# Chunk stats.");

	mk_list_foreach(head, &cm->chunks._head) {
		c = mk_list_entry(head, struct chunk, _head);
		used = c->write;
		free = c->size - used;

		log_info("Chunk: %d, S: %zu B, U: %zu B, F: %zu B, R: %d",
			chunks,
			c->size,
			used,
			free,
			c->refs);

		total_used += used;
		total_free += free;
		chunks++;
	}

	log_info("Total");
	log_info("Count: %d, Size: %zu B, Used: %zu B, Free: %zu B",
		chunks,
		total_used + total_free,
		total_used,
		total_free);

	log_info("# Chunk stats.");
}

void chunk_list_free_chunks(struct chunk_list *cm)
{
	struct mk_list *head, *tmp;
	struct chunk *c;

	if (!mk_list_is_empty(&cm->chunks._head)) {
		PLUGIN_TRACE("No chunks to free in manager.");
		return;
	}

	mk_list_foreach_safe(head, tmp, &cm->chunks._head) {
		c = mk_list_entry(head, struct chunk, _head);
		chunk_free(c);
	}
}


int chunk_iov_init(struct chunk_iov *iov, int size)
{
	check(size <= IOV_MAX, "New iov size is larger then IOV_MAX.");

	iov->held_refs = mk_api->mem_alloc(size * sizeof(*iov->held_refs));
	check_mem(iov->held_refs);

	iov->io = mk_api->mem_alloc(size * sizeof(*iov->io));
	check_mem(iov->io);

	iov->size = size;
	iov->index = 0;

	return 0;
error:
	return -1;
}

int chunk_iov_resize(struct chunk_iov *iov, int size)
{
	struct iovec *tio = NULL;
	struct chunk_ref *trefs = NULL;

	check(iov->io, "iovec in iov not allocated.");
	check(iov->held_refs, "held refs in iov is not allocated.");
	check(size <= IOV_MAX, "New iov size is larger then IOV_MAX.");

	tio = mk_api->mem_realloc(iov->io, size * sizeof(*iov->io));
	check(tio, "Failed to realloc iovec in iov.");

	trefs = mk_api->mem_realloc(iov->held_refs, size * sizeof(*iov->held_refs));
	check(trefs, "Failed to realloc held refs in iov.");

	iov->io = tio;
	iov->held_refs = trefs;
	iov->size = size;

	return 0;
error:
	if (tio) {
		iov->io = tio;
	}
	if (trefs) {
		iov->held_refs = trefs;
	}
	return -1;
}

size_t chunk_iov_length(struct chunk_iov *iov)
{
	size_t s = 0;
	int i;

	for (i = 0; i < iov->index; i++) {
		s += iov->io[i].iov_len;
	}

	return s;
}

ssize_t chunk_iov_sendv(int fd, struct chunk_iov *iov)
{
	check_debug(iov->index > 0, "Tried sending empty chunk_iov.");

	return writev(fd, iov->io, iov->index);
error:
	return 0;
}

/*
 * Use char* p for pointer arithmetic as it's undefined for void*.
 */
int chunk_iov_drop(struct chunk_iov *iov, size_t bytes)
{
	struct iovec *io;
	size_t length = chunk_iov_length(iov);
	size_t drop;
	int i;
	char *p;

	check(bytes > 0, "Tried dropping 0 bytes.");
	check(length >= bytes, "Tried dropping more bytes then available.");

	for (i = 0; bytes > 0 && i < iov->size; i++) {
		io = iov->io + i;

		if (io->iov_len < bytes) {
			drop = io->iov_len;
			io->iov_len = 0;
			io->iov_base = NULL;
		} else {
			drop = bytes;
			io->iov_len -= bytes;
			p = io->iov_base;
			p += bytes;
			io->iov_base = p;
		}
		bytes -= drop;
	}
	return 0;
error:
	return -1;
}

int chunk_iov_add(struct chunk_iov *iov, struct chunk_ptr cp)
{
	struct chunk_ref *cr;
	struct iovec *io;

	if (iov->index >= iov->size) {
            return -1;
        }
	check(cp.len > 0, "tried to add empty chunk_ptr");

	cr = iov->held_refs + iov->index;
	io = iov->io + iov->index;

	iov->index += 1;

	chunk_retain(cp.parent);

	cr->t = CHUNK_REF_CHUNK;
	cr->u.chunk = cp.parent;

	io->iov_len = cp.len;
	io->iov_base = cp.data;

	return 0;
error:
	return -1;
}

int chunk_iov_add_ptr(struct chunk_iov *iov,
		void *vptr,
		size_t len,
		int do_free)
{
	struct chunk_ref *cr;
	struct iovec *io;
	uint8_t *ptr = vptr;

	check(iov->index < iov->size, "chunk_iov is full.");
	check(len > 0, "tried to add ptr with len = 0.");

	cr = iov->held_refs + iov->index;
	io = iov->io + iov->index;

	iov->index += 1;

	if (do_free) {
		cr->t = CHUNK_REF_UINT8;
		cr->u.ptr = ptr;
	} else {
		cr->t = CHUNK_REF_NULL;
		cr->u.ptr = NULL;
	}

	io->iov_len = len;
	io->iov_base = ptr;

	return 0;
error:
	return -1;
}

static void chunk_iov_free_refs(struct chunk_iov *iov)
{
	int i;
	struct chunk_ref *cr;

	for (i = 0; i < iov->index; i++) {
		cr = iov->held_refs + i;

		if (cr->t == CHUNK_REF_CHUNK) {
			chunk_release(cr->u.chunk);
			cr->u.chunk = NULL;
		}
		else if (cr->t == CHUNK_REF_UINT8) {
			mk_api->mem_free(cr->u.ptr);
			cr->u.ptr = NULL;
		}

		cr->t = CHUNK_REF_NULL;
	}
}

void chunk_iov_reset(struct chunk_iov *iov)
{
	chunk_iov_free_refs(iov);
	iov->index = 0;
}

void chunk_iov_free(struct chunk_iov *iov)
{
	chunk_iov_free_refs(iov);

	if (iov->io) {
		mk_api->mem_free(iov->io);
		iov->io = NULL;
	}
	if (iov->held_refs) {
		mk_api->mem_free(iov->held_refs);
		iov->held_refs = NULL;
	}

	iov->index = 0;
	iov->size = 0;
}
