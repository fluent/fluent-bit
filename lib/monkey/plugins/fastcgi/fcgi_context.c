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
#include "fcgi_context.h"

#include "dbg.h"

void fcgi_context_free(struct fcgi_context *tdata)
{
	request_list_free(&tdata->rl);
	fcgi_fd_list_free(&tdata->fdl);
	chunk_list_free_chunks(&tdata->cl);
}

int fcgi_context_init(struct fcgi_context *tdata,
		const struct fcgi_fd_matrix fdm,
		unsigned int thread_id,
		unsigned int request_capacity,
		struct fcgi_config *config)
{
	unsigned int request_offset = 1 + request_capacity * thread_id;

	check(!request_list_init(&tdata->rl,
				config->location_count,
				request_offset,
				request_capacity),
			"Failed to init request list.");
	check(!fcgi_fd_list_init(&tdata->fdl,
				fdm,
				thread_id,
				config),
			"Failed to init fd list.");
	chunk_list_init(&tdata->cl);

	return 0;
error:
	fcgi_context_free(tdata);
	return -1;
}

void fcgi_context_list_free(struct fcgi_context_list *tdlist)
{
	int i;

	pthread_mutex_destroy(&tdlist->thread_id_counter_mutex);

	for (i = 0; i < tdlist->n; i++) {
		if (!tdlist->tds[i]) {
			continue;
		}
		fcgi_context_free(tdlist->tds[i]);
		mk_api->mem_free(tdlist->tds[i]);
	}

	mk_api->mem_free(tdlist->tds);
	tdlist->n = 0;
	tdlist->tds = NULL;
}

int fcgi_context_list_init(struct fcgi_context_list *tdlist,
		struct fcgi_config *config,
		int workers,
		int worker_capacity)
{
	struct fcgi_context *tdata;
	struct fcgi_fd_matrix fdm = fcgi_fd_matrix_create(config, workers);
	const uint16_t capacity = next_power_of_2(worker_capacity);
	int i;

	check(capacity > 0, "No request capacity.");
	check(capacity < UINT16_MAX, "Request capacity too large.");

	tdlist->thread_id_counter = 0;
	pthread_mutex_init(&tdlist->thread_id_counter_mutex, NULL);

	tdlist->tds = mk_api->mem_alloc(workers * sizeof(*tdlist->tds));
	check_mem(tdlist->tds);
	tdlist->n = workers;

	for (i = 0; i < workers; i++) {
        tdata = mk_api->mem_alloc(sizeof(*tdata));
		check_mem(tdata);
		tdlist->tds[i] = tdata;

		check(!fcgi_context_init(tdata, fdm, i, capacity, config),
			"[THREAD_ID %d] Failed to init thread data.", i);
	}

	fcgi_fd_matrix_free(&fdm);
	return 0;
error:
	fcgi_fd_matrix_free(&fdm);
	fcgi_context_list_free(tdlist);
	return -1;
}

int fcgi_context_list_assign_thread_id(struct fcgi_context_list *tdlist)
{
	int my_thread_id;

	check(tdlist->thread_id_counter < tdlist->n,
		"All thread id's have already assigned.");

	pthread_mutex_lock(&tdlist->thread_id_counter_mutex);

	my_thread_id = tdlist->thread_id_counter;
	tdlist->thread_id_counter += 1;

	pthread_mutex_unlock(&tdlist->thread_id_counter_mutex);

	return my_thread_id;
error:
	return -1;
}

struct fcgi_context *fcgi_context_list_get(
		struct fcgi_context_list *tdlist,
		int thread_id)
{
	struct fcgi_context *tdata;

	check(thread_id >= 0  && thread_id < tdlist->n,
		"Thread id %d is out of range.", thread_id);

	tdata = tdlist->tds[thread_id];
	check(tdata, "Thread data is NULL for thread id %d.", thread_id);

	return tdata;
error:
	return NULL;
}
