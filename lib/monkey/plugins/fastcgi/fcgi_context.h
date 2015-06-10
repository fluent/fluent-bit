/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef _FCGI_CONTEXT_H_
#define _FCGI_CONTEXT_H_

#include <pthread.h>

#include "fcgi_config.h"
#include "request.h"
#include "chunk.h"
#include "fcgi_fd.h"

struct fcgi_context {
	int thread_id;

	struct chunk_list cl;
	struct request_list rl;
	struct fcgi_fd_list fdl;
};

struct fcgi_context_list {
	pthread_mutex_t thread_id_counter_mutex;
	int thread_id_counter;

	int n;
	struct fcgi_context **tds;
};

void fcgi_context_module_init(void *(*mem_alloc_p)(const size_t),
		void (*mem_free_p)(void *));

void fcgi_context_list_free(struct fcgi_context_list *tdlist);

int fcgi_context_list_init(struct fcgi_context_list *tdlist,
		struct fcgi_config *config,
		int workers,
		int worker_capacity);

int fcgi_context_list_assign_thread_id(
		struct fcgi_context_list *tdlist);

struct fcgi_context *fcgi_context_list_get(
		struct fcgi_context_list *tdlist,
		int thread_id);

#endif // _FCGI_CONTEXT_H_
