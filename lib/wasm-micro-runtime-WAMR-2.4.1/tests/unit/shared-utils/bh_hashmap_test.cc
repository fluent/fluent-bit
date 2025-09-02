/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "bh_platform.h"
#include "test_helper.h"
#include "gtest/gtest.h"
#include "bh_hashmap.h"
#include "wasm.h"
#include "wasm_export.h"

#include <future>

typedef struct HashMapElem {
    void *key;
    void *value;
    struct HashMapElem *next;
} HashMapElem;

struct HashMap {
    /* size of element array */
    uint32 size;
    /* lock for elements */
    korp_mutex *lock;
    /* hash function of key */
    HashFunc hash_func;
    /* key equal function */
    KeyEqualFunc key_equal_func;
    KeyDestroyFunc key_destroy_func;
    ValueDestroyFunc value_destroy_func;
    HashMapElem *elements[1];
};

int DESTROY_NUM = 0;
char TRAVERSE_KEY[] = "key_1";
char TRAVERSE_VAL[] = "val_1";
int TRAVERSE_COMP_RES = 0;

class bh_hashmap_test_suite : public testing::Test
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

TEST_F(bh_hashmap_test_suite, bh_hash_map_create)
{
    // Normally.
    EXPECT_NE((HashMap *)nullptr,
              bh_hash_map_create(32, true, (HashFunc)wasm_string_hash,
                                 (KeyEqualFunc)wasm_string_equal, nullptr,
                                 wasm_runtime_free));

    // Illegal parameters.
    EXPECT_EQ((HashMap *)nullptr,
              bh_hash_map_create(65537, true, (HashFunc)wasm_string_hash,
                                 (KeyEqualFunc)wasm_string_equal, nullptr,
                                 wasm_runtime_free));
    EXPECT_EQ((HashMap *)nullptr,
              bh_hash_map_create(65536, true, nullptr, nullptr, nullptr,
                                 wasm_runtime_free));
    EXPECT_EQ((HashMap *)nullptr,
              bh_hash_map_create(65536, true, (HashFunc)wasm_string_hash,
                                 nullptr, nullptr, wasm_runtime_free));
}

TEST_F(bh_hashmap_test_suite, bh_hash_map_insert)
{
    HashMap *test_hash_map = bh_hash_map_create(
        32, false, (HashFunc)wasm_string_hash, (KeyEqualFunc)wasm_string_equal,
        nullptr, wasm_runtime_free);
    int num = 0;
    void **p_old_key = nullptr;
    void **p_old_value = nullptr;

    // Normally.
    EXPECT_EQ(true, bh_hash_map_insert(test_hash_map, (void *)"key_1",
                                       (void *)"val_1"));
    num++;
    // Illegal parameters.
    EXPECT_EQ(false, bh_hash_map_insert(nullptr, nullptr, (void *)"val_2"));

    // Execute fail: more than 32.
    for (; num <= 32; num++) {
        bh_hash_map_insert(test_hash_map, (void *)&num, (void *)"val");
    }
    EXPECT_EQ(false,
              bh_hash_map_insert(test_hash_map, (void *)&num, (void *)"val"));

    // Remove one, insert one.
    bh_hash_map_remove(test_hash_map, (void *)"key_1", p_old_key, p_old_value);
    EXPECT_EQ(true, bh_hash_map_insert(test_hash_map, (void *)"key_1",
                                       (void *)"val_1"));
}

TEST_F(bh_hashmap_test_suite, bh_hash_map_find)
{
    HashMap *test_hash_map = bh_hash_map_create(
        32, false, (HashFunc)wasm_string_hash, (KeyEqualFunc)wasm_string_equal,
        nullptr, wasm_runtime_free);
    bh_hash_map_insert(test_hash_map, (void *)"key_1", (void *)"val_1");

    // Normally. use_lock is false.
    EXPECT_NE((void *)nullptr,
              bh_hash_map_find(test_hash_map, (void *)"key_1"));

    // Execute fail.
    EXPECT_EQ((void *)nullptr,
              bh_hash_map_find(test_hash_map, (void *)"KEY_1"));

    // Illegal parameters.
    EXPECT_EQ((void *)nullptr, bh_hash_map_find(nullptr, nullptr));
    EXPECT_EQ((void *)nullptr, bh_hash_map_find(test_hash_map, nullptr));

    // Normally. use_lock is true.
    test_hash_map = bh_hash_map_create(32, true, (HashFunc)wasm_string_hash,
                                       (KeyEqualFunc)wasm_string_equal, nullptr,
                                       wasm_runtime_free);
    bh_hash_map_insert(test_hash_map, (void *)"key_1", (void *)"val_1");
    EXPECT_EQ((void *)nullptr,
              bh_hash_map_find(test_hash_map, (void *)"KEY_1"));
}

TEST_F(bh_hashmap_test_suite, bh_hash_map_update)
{
    char old_value[10] = { 0 };
    void **p_old_value = (void **)(&old_value);
    HashMap *test_hash_map = bh_hash_map_create(
        32, false, (HashFunc)wasm_string_hash, (KeyEqualFunc)wasm_string_equal,
        nullptr, wasm_runtime_free);
    bh_hash_map_insert(test_hash_map, (void *)"key_1", (void *)"val_1");

    // test_hash_map->lock == nullptr. Normally.
    EXPECT_EQ(true, bh_hash_map_update(test_hash_map, (void *)"key_1",
                                       (void *)"val_2", p_old_value));
    // test_hash_map->lock == nullptr. Illegal parameters.
    EXPECT_EQ(false, bh_hash_map_update(nullptr, nullptr, (void *)"val_2",
                                        p_old_value));
    EXPECT_EQ(false, bh_hash_map_update(test_hash_map, nullptr, (void *)"val_2",
                                        p_old_value));
    EXPECT_EQ(false,
              bh_hash_map_update(nullptr, nullptr, (void *)"val_2", nullptr));

    // test_hash_map->lock == nullptr. Update non-existent elements.
    EXPECT_EQ(false, bh_hash_map_update(test_hash_map, (void *)"key",
                                        (void *)"val", p_old_value));

    test_hash_map = bh_hash_map_create(32, true, (HashFunc)wasm_string_hash,
                                       (KeyEqualFunc)wasm_string_equal, nullptr,
                                       wasm_runtime_free);
    bh_hash_map_insert(test_hash_map, (void *)"key_1", (void *)"val_1");

    // test_hash_map->lock == no nullptr. Normally.
    EXPECT_EQ(true, bh_hash_map_update(test_hash_map, (void *)"key_1",
                                       (void *)"val_2", p_old_value));
    // test_hash_map->lock == no nullptr. Illegal parameters.
    EXPECT_EQ(false, bh_hash_map_update(nullptr, nullptr, (void *)"val_2",
                                        p_old_value));
    EXPECT_EQ(false, bh_hash_map_update(test_hash_map, nullptr, (void *)"val_2",
                                        p_old_value));
}

void
trav_callback_fun(void *key, void *value, void *user_data)
{
    if (!strncmp(TRAVERSE_VAL, (const char *)value, 5)) {
        TRAVERSE_COMP_RES = 1;
    }
    else {
        TRAVERSE_COMP_RES = 0;
    }
}

TEST_F(bh_hashmap_test_suite, bh_hash_map_traverse)
{
    void **p_old_value = nullptr;
    HashMap *test_hash_map = bh_hash_map_create(
        32, false, (HashFunc)wasm_string_hash, (KeyEqualFunc)wasm_string_equal,
        nullptr, wasm_runtime_free);

    // Normally: TRAVERSE_COMP_RES = 1.
    bh_hash_map_insert(test_hash_map, (void *)TRAVERSE_KEY,
                       (void *)TRAVERSE_VAL);
    EXPECT_EQ(true,
              bh_hash_map_traverse(test_hash_map, trav_callback_fun, nullptr));
    EXPECT_EQ(1, TRAVERSE_COMP_RES);

    // Normally: TRAVERSE_COMP_RES = 0.
    bh_hash_map_update(test_hash_map, (void *)TRAVERSE_KEY, (void *)"val",
                       p_old_value);
    EXPECT_EQ(true,
              bh_hash_map_traverse(test_hash_map, trav_callback_fun, nullptr));
    EXPECT_EQ(0, TRAVERSE_COMP_RES);
    // Illegal parameters.
    EXPECT_EQ(false, bh_hash_map_traverse(nullptr, trav_callback_fun, nullptr));
    EXPECT_EQ(false, bh_hash_map_traverse(test_hash_map, nullptr, nullptr));
}

TEST_F(bh_hashmap_test_suite, bh_hash_map_remove)
{
    void **p_old_key = nullptr;
    void **p_old_value = nullptr;

    HashMap *test_hash_map = bh_hash_map_create(
        32, false, (HashFunc)wasm_string_hash, (KeyEqualFunc)wasm_string_equal,
        nullptr, wasm_runtime_free);
    bh_hash_map_insert(test_hash_map, (void *)"key_1", (void *)"val_1");
    bh_hash_map_insert(test_hash_map, (void *)"key_2", (void *)"val_2");

    // test_hash_map->lock == nullptr. Normally.
    EXPECT_EQ(true, bh_hash_map_remove(test_hash_map, (void *)"key_1",
                                       p_old_key, p_old_value));
    // test_hash_map->lock == nullptr. Remove non-existent elements.
    EXPECT_EQ(false, bh_hash_map_remove(test_hash_map, (void *)"key_1",
                                        p_old_key, p_old_value));
    // test_hash_map->lock == nullptr. Illegal parameters.
    EXPECT_EQ(false, bh_hash_map_remove(nullptr, (void *)"key_2", p_old_key,
                                        p_old_value));
    EXPECT_EQ(false, bh_hash_map_remove(test_hash_map, nullptr, p_old_key,
                                        p_old_value));

    test_hash_map = bh_hash_map_create(32, true, (HashFunc)wasm_string_hash,
                                       (KeyEqualFunc)wasm_string_equal, nullptr,
                                       wasm_runtime_free);
    bh_hash_map_insert(test_hash_map, (void *)"key_1", (void *)"val_1");
    bh_hash_map_insert(test_hash_map, (void *)"key_2", (void *)"val_2");

    // test_hash_map->lock == no nullptr. Normally.
    EXPECT_EQ(true, bh_hash_map_remove(test_hash_map, (void *)"key_1",
                                       p_old_key, p_old_value));
    // test_hash_map->lock == no nullptr. Illegal parameters.
    EXPECT_EQ(false, bh_hash_map_remove(nullptr, (void *)"key_2", p_old_key,
                                        p_old_value));
}

TEST_F(bh_hashmap_test_suite, bh_hash_map_get_struct_size)
{
    HashMap *test_hash_map = nullptr;
    uint32 size = 0;

    // No lock.
    test_hash_map = bh_hash_map_create(32, false, (HashFunc)wasm_string_hash,
                                       (KeyEqualFunc)wasm_string_equal, nullptr,
                                       wasm_runtime_free);
    bh_hash_map_insert(test_hash_map, (void *)"key_1", (void *)"val_1");
    size = (size_t)(&((HashMap *)0)->elements)
           + (uint32)sizeof(HashMapElem *) * test_hash_map->size;
    EXPECT_EQ(size, bh_hash_map_get_struct_size(test_hash_map));

    // Has lock.
    test_hash_map = bh_hash_map_create(32, true, (HashFunc)wasm_string_hash,
                                       (KeyEqualFunc)wasm_string_equal, nullptr,
                                       wasm_runtime_free);
    bh_hash_map_insert(test_hash_map, (void *)"key_1", (void *)"val_1");
    size = (size_t)(&((HashMap *)0)->elements)
           + (uint32)sizeof(HashMapElem *) * test_hash_map->size;
    size += (uint32)sizeof(korp_mutex);
    EXPECT_EQ(size, bh_hash_map_get_struct_size(test_hash_map));
}

TEST_F(bh_hashmap_test_suite, bh_hash_map_get_elem_struct_size)
{
    EXPECT_EQ((uint32)sizeof(HashMapElem), bh_hash_map_get_elem_struct_size());
}

void
destroy_func_test(void *key)
{
    DESTROY_NUM++;
}

TEST_F(bh_hashmap_test_suite, bh_hash_map_destroy)
{
    HashMap *test_hash_map = bh_hash_map_create(
        32, true, (HashFunc)wasm_string_hash, (KeyEqualFunc)wasm_string_equal,
        destroy_func_test, wasm_runtime_free);
    bh_hash_map_insert(test_hash_map, (void *)"key_1", (void *)"val_1");
    bh_hash_map_insert(test_hash_map, (void *)"key_2", (void *)"val_2");

    // test_hash_map->lock == no nullptr. Normally.
    EXPECT_EQ(true, bh_hash_map_destroy(test_hash_map));
    // key_destroy_func must be called 2 times.
    EXPECT_EQ(2, DESTROY_NUM);

    test_hash_map = bh_hash_map_create(32, false, (HashFunc)wasm_string_hash,
                                       (KeyEqualFunc)wasm_string_equal,
                                       destroy_func_test, wasm_runtime_free);

    // test_hash_map->lock == no nullptr. Illegal parameters.
    EXPECT_EQ(false, bh_hash_map_destroy(nullptr));
    // test_hash_map->lock == nullptr.
    EXPECT_EQ(true, bh_hash_map_destroy(test_hash_map));

    // key_destroy_func and value_destroy_func is nullptr.
    test_hash_map =
        bh_hash_map_create(32, false, (HashFunc)wasm_string_hash,
                           (KeyEqualFunc)wasm_string_equal, nullptr, nullptr);
    bh_hash_map_insert(test_hash_map, (void *)"key_1", (void *)"val_1");
    bh_hash_map_insert(test_hash_map, (void *)"key_2", (void *)"val_2");
    EXPECT_EQ(true, bh_hash_map_destroy(test_hash_map));
}

// This fun allows inserting the same keys.
bool
string_equal_test(const char *s1, const char *s2)
{
    return false;
}

int COUNT_ELEM = 0;

void
fun_count_elem(void *key, void *value, void *user_data)
{
    COUNT_ELEM++;
}

TEST_F(bh_hashmap_test_suite, bh_hashmap_thread_safety)
{
    HashMap *test_hash_map = bh_hash_map_create(
        32, true, (HashFunc)wasm_string_hash, (KeyEqualFunc)string_equal_test,
        destroy_func_test, wasm_runtime_free);
    int32_t i = 0;
    std::vector<std::future<void>> threads;

    // Creat 8 threads. In every thread, run the codes in brackets of
    // std::async.
    for (i = 0; i < 8; i++) {
        threads.push_back(std::async([&] {
            for (int j = 0; j < 25; j++) {
                bh_hash_map_insert(test_hash_map, (void *)"key_1",
                                   (void *)"val_1");
            }
        }));
    }

    // Wait all 8 threads finished.
    for (auto &t : threads) {
        t.wait();
    }

    // Count hash map elements.
    bh_hash_map_traverse(test_hash_map, fun_count_elem, nullptr);

    EXPECT_EQ(200, COUNT_ELEM);
    EXPECT_EQ(true, bh_hash_map_destroy(test_hash_map));
}