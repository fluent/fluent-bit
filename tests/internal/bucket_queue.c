/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_mp.h>
#include <msgpack.h>

#include "flb_tests_internal.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <fluent-bit/flb_bucket_queue.h>
#include <monkey/mk_core/mk_list.h>

#define TST_PRIORITY_OP_ADD    1
#define TST_PRIORITY_OP_DELETE 2
#define TST_PRIORITY_OP_EXPECT 3
#define TST_PRIORITY_OP_POP    3


struct bucket_queue_entry {
    char *tag;
    size_t priority;
    struct mk_list item;
    size_t add_idx;
};

struct bucket_queue_op_add {
    struct bucket_queue_entry *entries;
};

struct bucket_queue_op_expect {
    char *tag;
};

struct bucket_queue_op_pop {
    char *tag;
};

union bucket_queue_op_union {
    struct bucket_queue_op_pop pop;
    struct bucket_queue_op_add add;
    struct bucket_queue_op_expect expect;
};

struct bucket_queue_op {
    char op;
    void *op_description;
};

void test_create_destroy()
{
    struct flb_bucket_queue *bucket_queue;
    bucket_queue = flb_bucket_queue_create(100);
    flb_bucket_queue_destroy(bucket_queue);
}

void test_add_priorities()
{
    struct flb_bucket_queue *bucket_queue;

    struct bucket_queue_op operations[] = {
        {
            TST_PRIORITY_OP_ADD,
            &(struct bucket_queue_op_add) {
                (struct bucket_queue_entry[]) {
                    {
                        "a",
                        2 /* priority */
                    },
                    {
                        "b",
                        2 /* priority */
                    },
                    {
                        "c",
                        0 /* priority */
                    },
                    {
                        "d",
                        2 /* priority */
                    },
                    {
                        "e",
                        3 /* priority */
                    },
                    { 0 }
                }
            }
        },
        {
            TST_PRIORITY_OP_POP,
            &(struct bucket_queue_op_pop) {
                "c"
            }
        },
        {
            TST_PRIORITY_OP_POP,
            &(struct bucket_queue_op_pop) {
                "a"
            }
        },
        {
            TST_PRIORITY_OP_POP,
            &(struct bucket_queue_op_pop) {
                "b"
            }
        },
        {
            TST_PRIORITY_OP_POP,
            &(struct bucket_queue_op_pop) {
                "d"
            }
        },
        {
            TST_PRIORITY_OP_POP,
            &(struct bucket_queue_op_pop) {
                "e"
            }
        },
        {
            TST_PRIORITY_OP_POP,
            &(struct bucket_queue_op_pop) {
                "<EXPECT_NULL>"
            }
        },
        {
            TST_PRIORITY_OP_ADD,
            &(struct bucket_queue_op_add) {
                (struct bucket_queue_entry[]) {
                    {
                        "f",
                        1 /* priority */
                    },
                    {
                        "g",
                        1 /* priority */
                    },
                    {
                        "h",
                        0
                    },
                    { 0 }
                }
            }
        },
        {
            TST_PRIORITY_OP_POP,
            &(struct bucket_queue_op_pop) {
                "h"
            }
        },
        {
            TST_PRIORITY_OP_POP,
            &(struct bucket_queue_op_pop) {
                "f"
            }
        },
        {
            TST_PRIORITY_OP_POP,
            &(struct bucket_queue_op_pop) {
                "g"
            }
        },
        {
            TST_PRIORITY_OP_POP,
            &(struct bucket_queue_op_pop) {
                "<EXPECT_NULL>"
            }
        },
        {
            TST_PRIORITY_OP_POP,
            &(struct bucket_queue_op_pop) {
                "<EXPECT_NULL>"
            }
        },
        { 0 }
    };
    
    bucket_queue = flb_bucket_queue_create(4);
    struct bucket_queue_op *op;
    struct bucket_queue_op_add *op_desc_add;
    struct bucket_queue_op_pop *op_desc_pop;
    struct bucket_queue_entry *bucket_queue_entry;
    struct mk_list *list_entry;
    size_t add_idx = 0;
    int ret;
    int retB;

    for (op = operations; op->op != 0; ++op) {
        if (op->op == TST_PRIORITY_OP_ADD) {
            op_desc_add = (struct bucket_queue_op_add *) op->op_description;
            for (bucket_queue_entry = op_desc_add->entries; bucket_queue_entry->tag != 0;
                                                            ++bucket_queue_entry) {
                bucket_queue_entry->add_idx = add_idx++;
                ret = flb_bucket_queue_add(bucket_queue, &bucket_queue_entry->item,
                                   bucket_queue_entry->priority);
                TEST_CHECK(ret == 0);
                TEST_MSG("[op %zu][entry %zu] Add failed. Returned %d", op - operations,
                        bucket_queue_entry - op_desc_add->entries, ret);
            }
        }

        else if (op->op == TST_PRIORITY_OP_POP) {
            op_desc_pop = (struct bucket_queue_op_pop *) op->op_description;
            list_entry = flb_bucket_queue_pop_min(bucket_queue);
            ret = strcmp("<EXPECT_NULL>", op_desc_pop->tag);
            
            if (ret == 0) {
                TEST_CHECK(list_entry == NULL);
                TEST_MSG("[op %zu] Pop failed.", op - operations);
                TEST_MSG("Expect: null");
                TEST_MSG("Produced: list_entry %p", list_entry);
            }
            else {
                TEST_CHECK(list_entry != NULL);
                TEST_MSG("[op %zu] Pop failed.", op - operations);
                TEST_MSG("Expect: non-null");
                TEST_MSG("Produced: null");

                bucket_queue_entry = mk_list_entry(list_entry, struct bucket_queue_entry, item);
                ret = strcmp(bucket_queue_entry->tag, op_desc_pop->tag);
                TEST_CHECK(ret == 0);
                TEST_MSG("[op %zu] Pop failed.", op - operations);
                TEST_MSG("Expect tag: %s", op_desc_pop->tag);
                TEST_MSG("Produced tag: %s", bucket_queue_entry->tag);

                ret = strlen(bucket_queue_entry->tag);
                retB = strlen(op_desc_pop->tag);
                TEST_CHECK(ret == retB);
                TEST_MSG("[op %zu] Pop failed.", op - operations);
                TEST_MSG("Expect tag len: %d", retB);
                TEST_MSG("Produced tag len: %d", ret);
            }
        }
    }

    flb_bucket_queue_destroy(bucket_queue);
}

TEST_LIST = {
    {"create_destroy"                , test_create_destroy},
    {"add_priorities"                , test_add_priorities},
    { 0 }
};
