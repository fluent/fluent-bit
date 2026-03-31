/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "test_helper.h"
#include "gtest/gtest.h"

#include "bh_platform.h"

class bh_queue_test_suite : public testing::Test
{
  protected:
    // You should make the members protected s.t. they can be
    // accessed from sub-classes.

    // virtual void SetUp() will be called before each test is run.  You
    // should define it if you need to initialize the variables.
    // Otherwise, this can be skipped.
    virtual void SetUp() {}

    // virtual void TearDown() will be called after each test is run.
    // You should define it if there is cleanup work to do.  Otherwise,
    // you don't have to provide it.
    //
    virtual void TearDown() {}

  public:
    WAMRRuntimeRAII<512 * 1024> runtime;
};

typedef struct bh_queue_node {
    struct bh_queue_node *next;
    struct bh_queue_node *prev;
    unsigned short tag;
    unsigned int len;
    void *body;
    bh_msg_cleaner msg_cleaner;
} bh_queue_node;

struct bh_queue {
    bh_queue_mutex queue_lock;
    bh_queue_cond queue_wait_cond;
    unsigned int cnt;
    unsigned int max;
    unsigned int drops;
    bh_queue_node *head;
    bh_queue_node *tail;

    bool exit_loop_run;
};

typedef enum LINK_MSG_TYPE {
    COAP_TCP_RAW = 0,
    COAP_UDP_RAW = 1,
    REQUEST_PACKET,
    RESPONSE_PACKET,
    INSTALL_WASM_APP,
    CBOR_GENERIC = 30,

    LINK_MSG_TYPE_MAX = 50
} LINK_MSG_TYPE;

typedef enum QUEUE_MSG_TYPE {
    COAP_PARSED = LINK_MSG_TYPE_MAX + 1,
    RESTFUL_REQUEST,
    RESTFUL_RESPONSE,
    TIMER_EVENT = 5,
    SENSOR_EVENT = 6,
    GPIO_INTERRUPT_EVENT = 7,
    BLE_EVENT = 8,
    JDWP_REQUEST = 9,
    WD_TIMEOUT = 10,
    BASE_EVENT_MAX = 100

} QUEUE_MSG_TYPE;

enum {
    WASM_Msg_Start = BASE_EVENT_MAX,
    TIMER_EVENT_WASM,
    SENSOR_EVENT_WASM,
    CONNECTION_EVENT_WASM,
    WIDGET_EVENT_WASM,
    WASM_Msg_End = WASM_Msg_Start + 100
};

// If RES_CMP == 1, the function bh_queue_enter_loop_run run error.
int RES_CMP = 0;

TEST_F(bh_queue_test_suite, bh_queue_create)
{
    EXPECT_NE(nullptr, bh_queue_create());
}

TEST_F(bh_queue_test_suite, bh_queue_destroy)
{
    bh_message_t msg_ptr;
    bh_queue *queue_ptr = bh_queue_create();

    // Normally.
    msg_ptr = bh_new_msg(RESTFUL_REQUEST, nullptr, 0, nullptr);
    bh_post_msg2(queue_ptr, msg_ptr);
    bh_queue_destroy(queue_ptr);
    EXPECT_EQ(nullptr, queue_ptr->head);

    // Illegal parameters.
    bh_queue_destroy(nullptr);
}

TEST_F(bh_queue_test_suite, bh_message_payload)
{
    bh_message_t msg_ptr;

    msg_ptr = bh_new_msg(RESTFUL_REQUEST, (void *)"test_msg_body",
                         sizeof("test_msg_body"), nullptr);
    EXPECT_EQ("test_msg_body", bh_message_payload(msg_ptr));
}

TEST_F(bh_queue_test_suite, bh_message_payload_len)
{
    bh_message_t msg_ptr;

    msg_ptr = bh_new_msg(RESTFUL_REQUEST, (void *)"test_msg_body",
                         sizeof("test_msg_body"), nullptr);
    EXPECT_EQ(sizeof("test_msg_body"), bh_message_payload_len(msg_ptr));
}

TEST_F(bh_queue_test_suite, bh_message_type)
{
    bh_message_t msg_ptr;

    msg_ptr = bh_new_msg(RESTFUL_REQUEST, (void *)"test_msg_body",
                         sizeof("test_msg_body"), nullptr);
    EXPECT_EQ(RESTFUL_REQUEST, bh_message_type(msg_ptr));
}

TEST_F(bh_queue_test_suite, bh_new_msg)
{
    EXPECT_NE(nullptr, bh_new_msg(RESTFUL_REQUEST, (void *)"test_msg_body",
                                  sizeof("test_msg_body"), nullptr));
}

void
msg_cleaner_test(void *)
{
    return;
}

TEST_F(bh_queue_test_suite, bh_free_msg)
{
    bh_message_t msg_ptr;

    msg_ptr = bh_new_msg(RESTFUL_REQUEST, (void *)"test_msg_body",
                         sizeof("test_msg_body"), (void *)msg_cleaner_test);
    bh_free_msg(msg_ptr);

    msg_ptr = bh_new_msg(RESTFUL_REQUEST, (void *)"test_msg_body",
                         sizeof("test_msg_body"), nullptr);
    bh_free_msg(msg_ptr);

    msg_ptr = bh_new_msg(RESTFUL_REQUEST, (void *)(uintptr_t)100, 0, nullptr);
    bh_free_msg(msg_ptr);
}

TEST_F(bh_queue_test_suite, bh_post_msg)
{
    int i = 0;
    bh_queue *queue_ptr = bh_queue_create();
    bh_message_t msg_ptr;

    EXPECT_EQ(true, bh_post_msg(queue_ptr, TIMER_EVENT_WASM, nullptr, 0));
    EXPECT_EQ(1, queue_ptr->cnt);

    // queue_ptr->cnt >= queue_ptr->max.
    msg_ptr = bh_new_msg(RESTFUL_REQUEST, (void *)"test_msg_body",
                         sizeof("test_msg_body"), nullptr);
    for (i = 1; i <= 50; i++) {
        bh_post_msg2(queue_ptr, msg_ptr);
    }
    EXPECT_EQ(false, bh_post_msg(queue_ptr, TIMER_EVENT_WASM, nullptr, 0));
}

TEST_F(bh_queue_test_suite, bh_post_msg2)
{
    bh_message_t msg_ptr;
    bh_queue *queue_ptr = bh_queue_create();

    msg_ptr = bh_new_msg(RESTFUL_REQUEST, nullptr, 0, nullptr);
    EXPECT_EQ(true, bh_post_msg2(queue_ptr, msg_ptr));
    EXPECT_EQ(1, queue_ptr->cnt);
}

TEST_F(bh_queue_test_suite, bh_get_msg)
{
    bh_message_t msg_ptr;
    bh_queue *queue_ptr = bh_queue_create();

    msg_ptr = bh_new_msg(RESTFUL_REQUEST, (void *)"test_msg_body",
                         sizeof("test_msg_body"), nullptr);

    // queue->cnt == 0, timeout_us == 0.
    EXPECT_EQ(nullptr, bh_get_msg(queue_ptr, 0));
    // queue->cnt == 0, timeout_us != 0.
    bh_get_msg(queue_ptr, 1);

    bh_post_msg2(queue_ptr, msg_ptr);
    EXPECT_EQ(1, queue_ptr->cnt);
    bh_get_msg(queue_ptr, -1);
    EXPECT_EQ(0, queue_ptr->cnt);
}

TEST_F(bh_queue_test_suite, bh_queue_get_message_count)
{
    int i = 0, j = 0;
    bh_message_t msg_ptr;
    bh_queue *queue_ptr = bh_queue_create();

    // Normally.
    msg_ptr = bh_new_msg(RESTFUL_REQUEST, (void *)"test_msg_body",
                         sizeof("test_msg_body"), nullptr);
    for (i = 1; i <= 20; i++) {
        bh_post_msg2(queue_ptr, msg_ptr);
    }
    i = i - 1;
    // The count of msg is less than queue_ptr->max.
    EXPECT_EQ(i, bh_queue_get_message_count(queue_ptr));

    // The count of msg is more than queue_ptr->max.
    for (j = 1; j <= 60; j++) {
        bh_post_msg2(queue_ptr, msg_ptr);
    }
    j = j - 1;
    EXPECT_EQ(queue_ptr->max, bh_queue_get_message_count(queue_ptr));
    EXPECT_EQ(j + i - queue_ptr->max, queue_ptr->drops);

    // Illegal parameters.
    EXPECT_EQ(0, bh_queue_get_message_count(nullptr));
}

void
bh_queue_enter_loop_run_test_fun(void *message, void *arg)
{
    static int count = 0;
    RES_CMP =
        strncmp("test_queue_loop", (char *)((bh_message_t)message)->body, 15);

    count++;
    if (2 == count) {
        bh_queue_exit_loop_run((bh_queue *)arg);
    }
}

TEST_F(bh_queue_test_suite, bh_queue_enter_loop_run)
{
    bh_queue *queue_ptr = bh_queue_create();
    bh_message_t msg_ptr1 =
        bh_new_msg(RESTFUL_REQUEST, (void *)"test_queue_loop",
                   sizeof("test_queue_loop"), nullptr);
    bh_message_t msg_ptr2 =
        bh_new_msg(RESTFUL_REQUEST, (void *)"test_queue_loop",
                   sizeof("test_queue_loop"), nullptr);

    bh_post_msg2(queue_ptr, msg_ptr1);
    bh_post_msg2(queue_ptr, msg_ptr2);
    bh_queue_enter_loop_run(queue_ptr, bh_queue_enter_loop_run_test_fun,
                            queue_ptr);
    EXPECT_EQ(0, RES_CMP);

    // Illegal parameters.
    bh_queue_enter_loop_run(nullptr, bh_queue_enter_loop_run_test_fun,
                            queue_ptr);
}

TEST_F(bh_queue_test_suite, bh_queue_exit_loop_run)
{
    // Illegal parameters.
    bh_queue_exit_loop_run(nullptr);
}