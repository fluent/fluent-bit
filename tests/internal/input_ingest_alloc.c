/* Deterministic allocation failure tests for the engine release queue. */
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_sds.h>
#include <cmetrics/cmetrics.h>
#include "flb_tests_internal.h"

static int fail_envelope;
static int fail_tag;

void *__real_calloc(size_t count, size_t size);
flb_sds_t __real_flb_sds_create_len(const char *str, int len);

void *__wrap_calloc(size_t count, size_t size)
{
    if (fail_envelope) {
        fail_envelope = 0;
        return NULL;
    }
    return __real_calloc(count, size);
}

flb_sds_t __wrap_flb_sds_create_len(const char *str, int len)
{
    if (fail_tag) {
        fail_tag = 0;
        return NULL;
    }
    return __real_flb_sds_create_len(str, len);
}

static void test_allocation_failure(void)
{
    struct flb_input_instance ins;
    void *buffer;
    void *original;
    int ret;
    int failure;

    memset(&ins, 0, sizeof(ins));
    pthread_mutex_init(&ins.ingress_queue_lock, NULL);
    pthread_cond_init(&ins.ingress_queue_space_available, NULL);
    mk_list_init(&ins.ingress_queue);
    ins.ingress_queue_enabled = FLB_TRUE;
    ins.ingress_queue_signal_pending = FLB_TRUE;
    buffer = flb_malloc(4);
    TEST_ASSERT(buffer != NULL);
    memcpy(buffer, "test", 4);
    original = buffer;
    for (failure = 0; failure < 2; failure++) {
        fail_envelope = failure == 0;
        fail_tag = failure == 1;
        ret = flb_input_ingress_try_resume_log(&ins, 1, "tag", 3, &buffer, 4, 1);
        TEST_CHECK(ret == -1);
        TEST_CHECK(fail_envelope == 0 && fail_tag == 0);
        TEST_CHECK(buffer == original);
        TEST_CHECK(memcmp(buffer, "test", 4) == 0);
        TEST_CHECK(ins.ingress_queue_pending_events == 0);
        TEST_CHECK(ins.ingress_queue_pending_bytes == 0);
    }
    ret = flb_input_ingress_try_resume_log(&ins, 1, "tag", 3, &buffer, 4, 1);
    TEST_CHECK(ret == 0);
    TEST_CHECK(buffer == NULL);
    flb_input_ingress_destroy(&ins);
    pthread_mutex_destroy(&ins.ingress_queue_lock);
    pthread_cond_destroy(&ins.ingress_queue_space_available);
}

static void test_metrics_ownership(void)
{
    struct flb_input_instance ins;
    struct cmt *context;
    struct cmt *original;
    struct cfl_list contexts;
    int ret;
    int failure;

    memset(&ins, 0, sizeof(ins));
    pthread_mutex_init(&ins.ingress_queue_lock, NULL);
    pthread_cond_init(&ins.ingress_queue_space_available, NULL);
    mk_list_init(&ins.ingress_queue);
    cfl_list_init(&contexts);
    ins.ingress_queue_enabled = FLB_TRUE;
    ins.ingress_queue_signal_pending = FLB_TRUE;
    context = cmt_create();
    TEST_ASSERT(context != NULL);
    original = context;
    cfl_list_add(&context->_head, &contexts);
    for (failure = 0; failure < 2; failure++) {
        fail_envelope = failure == 0;
        fail_tag = failure == 1;
        ret = flb_input_ingress_try_resume_metrics(&ins, 9, "tag", 3, &context, 8);
        TEST_CHECK(ret == -1);
        TEST_CHECK(context == original);
        TEST_CHECK(contexts.next == &context->_head && contexts.prev == &context->_head);
        TEST_CHECK(ins.ingress_queue_pending_events == 0);
    }
    ins.ingress_queue_byte_limit = 4;
    ret = flb_input_ingress_try_resume_metrics(&ins, 9, "tag", 3, &context, 8);
    TEST_CHECK(ret == FLB_INPUT_INGRESS_BUSY);
    TEST_CHECK(context == original);
    TEST_CHECK(contexts.next == &context->_head && contexts.prev == &context->_head);
    ins.ingress_queue_byte_limit = 0;
    ins.ingress_queue_enabled = FLB_FALSE;
    ret = flb_input_ingress_try_resume_metrics(&ins, 9, NULL, 0, &context, 8);
    TEST_CHECK(ret == -1);
    TEST_CHECK(context == original);
    ins.ingress_queue_enabled = FLB_TRUE;
    ret = flb_input_ingress_try_resume_metrics(&ins, 9, "tag", 3, &context, 8);
    TEST_CHECK(ret == 0);
    TEST_CHECK(context == NULL);
    TEST_CHECK(cfl_list_is_empty(&contexts));
    TEST_CHECK(ins.ingress_queue_pending_events == 1);
    TEST_CHECK(ins.ingress_queue_pending_bytes == 8);
    flb_input_ingress_destroy(&ins);
    pthread_mutex_destroy(&ins.ingress_queue_lock);
    pthread_cond_destroy(&ins.ingress_queue_space_available);
}

TEST_LIST = {
    {"allocation_failure_preserves_payload", test_allocation_failure},
    {"metrics_ownership_and_allocation_failure", test_metrics_ownership},
    {NULL, NULL}
};
