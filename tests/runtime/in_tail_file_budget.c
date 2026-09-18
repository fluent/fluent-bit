/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#include <fluent-bit.h>
#include <fluent-bit/flb_pthread.h>
#include "flb_tests_runtime.h"
#include "../../plugins/in_tail/tail_config.h"
#include "../../plugins/in_tail/tail_file_budget.h"

#define BUDGET_THREADS 4

struct budget_test {
    pthread_mutex_t lock;
    pthread_cond_t condition;
    int waiting;
    int generation;
    int admitted;
    int failures;
};

struct budget_worker {
    struct flb_tail_config ctx;
    struct budget_test *test;
};

static void budget_barrier(struct budget_test *test, int check)
{
    int generation;

    pthread_mutex_lock(&test->lock);
    generation = test->generation;
    test->waiting++;
    if (test->waiting == BUDGET_THREADS) {
        if (check && test->admitted != 2) {
            test->failures++;
        }
        test->admitted = 0;
        test->waiting = 0;
        test->generation++;
        pthread_cond_broadcast(&test->condition);
    }
    else {
        while (generation == test->generation) {
            pthread_cond_wait(&test->condition, &test->lock);
        }
    }
    pthread_mutex_unlock(&test->lock);
}

static void *budget_worker_run(void *data)
{
    int i;
    int admitted;
    struct budget_worker *worker = data;

    for (i = 0; i < 100; i++) {
        admitted = flb_tail_file_budget_reserve(&worker->ctx);
        pthread_mutex_lock(&worker->test->lock);
        worker->test->admitted += admitted;
        pthread_mutex_unlock(&worker->test->lock);

        /* All four attempts must finish before any reservation is released. */
        budget_barrier(worker->test, FLB_TRUE);
        if (admitted) {
            flb_tail_file_budget_release(&worker->ctx);
        }
        budget_barrier(worker->test, FLB_FALSE);
    }
    return NULL;
}

static void test_shared_file_budget(void)
{
    int i;
    int input;
    int ret;
    flb_ctx_t *flb;
    flb_ctx_t *other;
    struct flb_input_instance *ins;
    struct flb_tail_config first = {0};
    struct flb_tail_config second = {0};
    struct budget_test test = {0};
    struct budget_worker workers[BUDGET_THREADS];
    pthread_t threads[BUDGET_THREADS];

    flb = flb_create();
    TEST_CHECK(flb != NULL);
    input = flb_input(flb, "tail", NULL);
    TEST_CHECK(input >= 0);
    TEST_CHECK(flb_input_set(flb, input, "max_open_files", "2", NULL) == 0);
    ins = mk_list_entry(flb->config->inputs.next, struct flb_input_instance, _head);
    ins->log_level = FLB_LOG_OFF;
    first.config = flb->config;
    first.ins = ins;
    first.file_budget = flb_tail_file_budget_create(&first);
    TEST_CHECK(first.file_budget != NULL);
    /* A conflicting engine must fail without changing the active pool. */
    other = flb_create();
    TEST_CHECK(other != NULL);
    input = flb_input(other, "tail", NULL);
    TEST_CHECK(input >= 0);
    TEST_CHECK(flb_input_set(other, input, "max_open_files", "3", NULL) == 0);
    second.config = other->config;
    second.ins = mk_list_entry(other->config->inputs.next, struct flb_input_instance, _head);
    second.ins->log_level = FLB_LOG_OFF;
    TEST_CHECK(flb_tail_file_budget_create(&second) == NULL);
    flb_destroy(other);

    /* A second embedded engine with no limit inherits the active process pool. */
    other = flb_create();
    TEST_CHECK(other != NULL);
    TEST_CHECK(flb_input(other, "tail", NULL) >= 0);
    second.config = other->config;
    second.ins = mk_list_entry(other->config->inputs.next, struct flb_input_instance, _head);
    second.ins->log_level = FLB_LOG_OFF;
    second.file_budget = flb_tail_file_budget_create(&second);
    TEST_CHECK(second.file_budget == first.file_budget);

    pthread_mutex_init(&test.lock, NULL);
    pthread_cond_init(&test.condition, NULL);
    for (i = 0; i < BUDGET_THREADS; i++) {
        workers[i].ctx = i % 2 == 0 ? first : second;
        workers[i].test = &test;
        ret = pthread_create(&threads[i], NULL, budget_worker_run, &workers[i]);
        if (!TEST_CHECK(ret == 0)) {
            exit(EXIT_FAILURE);
        }
    }
    for (i = 0; i < BUDGET_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    TEST_CHECK(test.failures == 0);
    pthread_cond_destroy(&test.condition);
    pthread_mutex_destroy(&test.lock);

    /* Detaching one user must neither reset the pool nor free it early. */
    TEST_CHECK(flb_tail_file_budget_reserve(&first) == FLB_TRUE);
    flb_tail_file_budget_destroy(second.file_budget);
    flb_destroy(other);
    TEST_CHECK(flb_tail_file_budget_reserve(&first) == FLB_TRUE);
    TEST_CHECK(flb_tail_file_budget_reserve(&first) == FLB_FALSE);
    flb_tail_file_budget_release(&first);
    flb_tail_file_budget_release(&first);
    flb_tail_file_budget_destroy(first.file_budget);

    /* The final detach permits a fresh engine with a different limit. */
    flb_destroy(flb);
    flb = flb_create();
    TEST_CHECK(flb != NULL);
    input = flb_input(flb, "tail", NULL);
    TEST_CHECK(input >= 0);
    ins = mk_list_entry(flb->config->inputs.next, struct flb_input_instance, _head);
    ins->log_level = FLB_LOG_OFF;
    first.config = flb->config;
    first.ins = ins;
    TEST_CHECK(flb_input_set(flb, input, "max_open_files", "1", NULL) == 0);
    first.file_budget = flb_tail_file_budget_create(&first);
    TEST_CHECK(first.file_budget != NULL);
    TEST_CHECK(flb_tail_file_budget_reserve(&first) == FLB_TRUE);
    TEST_CHECK(flb_tail_file_budget_reserve(&first) == FLB_FALSE);
    flb_tail_file_budget_release(&first);
    flb_tail_file_budget_destroy(first.file_budget);
    flb_destroy(flb);
}

TEST_LIST = {
    {"shared_file_budget", test_shared_file_budget},
    {NULL, NULL}
};
